//! Cold ring negotiation and owner-thread affinity validation.

use io_uring::{IoUring, Parameters};

use crate::{
    Result, UringError,
    backend::*,
    config::{KernelFeatures, ProactorConfig, ProactorMode, SqPollConfig},
};

pub(super) fn create(config: ProactorConfig) -> Result<(IoUring, KernelFeatures)> {
    let sqpoll = match config.mode {
        ProactorMode::SqPoll(sq) | ProactorMode::SqPollIoPoll(sq) => Some(sq),
        ProactorMode::EventDriven(_) | ProactorMode::IoPoll => None,
    };
    if let Some(sq) = sqpoll {
        reject_shared_owner_cpu(sq)?;
    }
    let single = IORING_SETUP_SINGLE_ISSUER;
    let coop = IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
    let defer = IORING_SETUP_DEFER_TASKRUN;
    let sq = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF | single;
    let candidates: &[u32] = match config.mode {
        ProactorMode::EventDriven(_) if !config.enable_optimizations => &[0],
        ProactorMode::EventDriven(_) => &[single | coop | defer, single | coop, coop, 0],
        ProactorMode::SqPoll(_) => &[sq],
        ProactorMode::IoPoll => &[
            IORING_SETUP_IOPOLL | single | defer | IORING_SETUP_TASKRUN_FLAG,
            IORING_SETUP_IOPOLL | single,
            IORING_SETUP_IOPOLL,
        ],
        ProactorMode::SqPollIoPoll(_) => &[sq | IORING_SETUP_IOPOLL],
    };
    let preferred = if config.enable_optimizations {
        [
            IORING_SETUP_SUBMIT_ALL | IORING_SETUP_NO_SQARRAY,
            IORING_SETUP_SUBMIT_ALL,
            0,
        ]
    } else {
        [0; 3]
    };
    for &mode_flags in candidates {
        let mut previous = None;
        for optional in preferred {
            let flags = mode_flags | config.setup_flags | optional;
            if previous == Some(flags) {
                continue;
            }
            previous = Some(flags);
            match build(config, flags, sqpoll) {
                Ok(ring) => {
                    let features = features(ring.params(), flags);
                    validate_features(&ring, config.mode)?;
                    return Ok((ring, features));
                }
                Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {}
                Err(error) => return Err(UringError::RingInit(super::errno(&error))),
            }
        }
    }
    Err(UringError::RingInit(libc::EINVAL))
}

fn build(
    config: ProactorConfig,
    flags: u32,
    sqpoll: Option<SqPollConfig>,
) -> std::io::Result<IoUring> {
    let mut builder = IoUring::builder();
    if let Some(entries) = config.cq_entries {
        builder.setup_cqsize(entries);
    }
    if let Some(sq) = sqpoll {
        builder
            .setup_sqpoll(sq.idle_ms.get())
            .setup_sqpoll_cpu(sq.thread_cpu);
    }
    if flags & IORING_SETUP_IOPOLL != 0 {
        builder.setup_iopoll();
    }
    if flags & IORING_SETUP_SINGLE_ISSUER != 0 {
        builder.setup_single_issuer();
    }
    if flags & IORING_SETUP_COOP_TASKRUN != 0 {
        builder.setup_coop_taskrun();
    }
    if flags & IORING_SETUP_TASKRUN_FLAG != 0 {
        builder.setup_taskrun_flag();
    }
    if flags & IORING_SETUP_DEFER_TASKRUN != 0 {
        builder.setup_defer_taskrun();
    }
    if flags & IORING_SETUP_SUBMIT_ALL != 0 {
        builder.setup_submit_all();
    }
    if flags & IORING_SETUP_NO_SQARRAY != 0 {
        builder.setup_no_sqarray();
    }
    if flags & IORING_SETUP_CLAMP != 0 {
        builder.setup_clamp();
    }
    builder.build(config.entries)
}

fn validate_features(ring: &IoUring, mode: ProactorMode) -> Result<()> {
    let params = ring.params();
    if !params.is_feature_nodrop() {
        return Err(UringError::InvalidConfig(
            "kernel requires NODROP completion ownership",
        ));
    }
    if !params.is_feature_ext_arg() {
        return Err(UringError::InvalidConfig("kernel requires EXT_ARG waits"));
    }
    if matches!(mode, ProactorMode::SqPoll(_)) && !params.is_feature_sqpoll_nonfixed() {
        return Err(UringError::InvalidConfig(
            "SQPOLL requires nonfixed descriptors",
        ));
    }
    Ok(())
}

fn features(params: &Parameters, flags: u32) -> KernelFeatures {
    KernelFeatures {
        setup_flags: flags,
        features: u32::from(params.is_feature_single_mmap())
            | (u32::from(params.is_feature_nodrop()) << 1)
            | (u32::from(params.is_feature_submit_stable()) << 2)
            | (u32::from(params.is_feature_sqpoll_nonfixed()) << 7)
            | (u32::from(params.is_feature_ext_arg()) << 8)
            | (u32::from(params.is_feature_min_timeout()) << 15)
            | (u32::from(params.is_feature_no_iowait()) << 17),
    }
}

fn reject_shared_owner_cpu(config: SqPollConfig) -> Result<()> {
    // A growable word-aligned mask also handles kernels built for more than CPU_SETSIZE CPUs.
    let mut mask = vec![0usize; 16];
    loop {
        let bytes = std::mem::size_of_val(mask.as_slice());
        // SAFETY: The aligned, initialized buffer spans bytes writable bytes. pid zero
        // selects this thread, and the kernel only writes within the supplied extent.
        if unsafe { libc::sched_getaffinity(0, bytes, mask.as_mut_ptr().cast()) } == 0 {
            let bits = usize::BITS as usize;
            let cpu = config.thread_cpu as usize;
            let contains = mask
                .get(cpu / bits)
                .is_some_and(|word| word & (1 << (cpu % bits)) != 0);
            let count: u32 = mask.iter().map(|word| word.count_ones()).sum();
            if count == 1 && contains {
                return Err(UringError::InvalidConfig(
                    "sq thread cpu cannot share the owner's sole cpu",
                ));
            }
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINVAL) {
            return Err(UringError::syscalls(
                "sched_getaffinity",
                super::errno(&error),
            ));
        }
        if mask.len() >= 1 << 14 {
            return Err(UringError::InvalidConfig(
                "owner CPU mask exceeds supported extent",
            ));
        }
        mask.resize(mask.len() * 2, 0);
    }
}
