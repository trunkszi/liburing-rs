//! Cold setup transactions: geometry validation, handle adoption and checked mapped addresses.
use core::{marker::PhantomData, sync::atomic::Ordering};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};

use uarch::prelude::*;

use crate::{
    Result, UringError,
    backend::{
        mapping::{MmapRegion, RingHandle, RingMemory, RingStorage, UserRingMemory},
        ring::{
            NativeRing,
            cq::CqState,
            geometry::{CqeGeometry, SqeGeometry},
            load32,
            sq::{SqMeta, SqState},
        },
        sys::{self, params::*},
    },
};

fn extent(offset: u32, count: u32, stride: usize) -> Result<usize> {
    (count as usize)
        .checked_mul(stride)
        .and_then(|size| (offset as usize).checked_add(size))
        .ok_or(UringError::InvalidTopology("ring extent overflow"))
}
fn validate<S: SqeGeometry, C: CqeGeometry>(
    entries: u32,
    params: &mut IoUringParams,
) -> Result<()> {
    if entries == 0
        || params.resv != [0; 3]
        || params.sq_off.user_addr != 0
        || params.cq_off.user_addr != 0
    {
        return Err(UringError::InvalidTopology(
            "invalid entries, reserved fields or externally owned addresses",
        ));
    }
    let geometry =
        IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED | IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED;
    if params.flags & geometry != 0 && params.flags & geometry != S::FLAGS | C::FLAGS {
        return Err(UringError::InvalidTopology(
            "setup flags disagree with queue geometry",
        ));
    }
    params.flags |= S::FLAGS | C::FLAGS;
    if params.flags & IORING_SETUP_REGISTERED_FD_ONLY != 0
        && params.flags & IORING_SETUP_NO_MMAP == 0
    {
        return Err(UringError::InvalidTopology(
            "REGISTERED_FD_ONLY requires NO_MMAP",
        ));
    }
    if params.flags & IORING_SETUP_SQ_REWIND != 0
        && (params.flags & IORING_SETUP_NO_SQARRAY == 0 || params.flags & IORING_SETUP_SQPOLL != 0)
    {
        return Err(UringError::InvalidTopology(
            "SQ_REWIND requires NO_SQARRAY and forbids SQPOLL",
        ));
    }
    if S::MIXED && params.flags & IORING_SETUP_SQ_REWIND == 0 && entries <= 2 {
        return Err(UringError::InvalidTopology(
            "mixed SQ requires capacity for atomic pad plus wide reservation",
        ));
    }
    Ok(())
}
fn user_memory<S: SqeGeometry, C: CqeGeometry>(
    entries: u32,
    params: &mut IoUringParams,
) -> Result<Option<UserRingMemory>> {
    if params.flags & IORING_SETUP_NO_MMAP == 0 {
        return Ok(None);
    }
    // These are the audited Linux 6.16/7.0 queue limits, not unchecked pointer-size assumptions.
    let clamp = params.flags & IORING_SETUP_CLAMP != 0;
    let bounded = if clamp { entries.min(32768) } else { entries };
    let sq = bounded
        .checked_next_power_of_two()
        .filter(|&n| n <= 32768)
        .ok_or(UringError::InvalidTopology(
            "NO_MMAP SQ capacity exceeds audited limit",
        ))?;
    let requested_cq = if params.flags & IORING_SETUP_CQSIZE != 0 {
        params.cq_entries
    } else {
        sq * 2
    };
    let requested_cq = if clamp {
        requested_cq.min(65536)
    } else {
        requested_cq
    };
    let cq = requested_cq
        .checked_next_power_of_two()
        .filter(|&n| n != 0 && n <= 65536)
        .ok_or(UringError::InvalidTopology(
            "NO_MMAP CQ capacity exceeds audited limit",
        ))?;
    let memory = UserRingMemory::new(sq, cq, S::STRIDE, C::STRIDE)?;
    params.sq_off.user_addr = memory.sqes.as_ptr() as u64;
    params.cq_off.user_addr = memory.rings.as_ptr() as u64;
    Ok(Some(memory))
}
/// Creates an exact raw ring without silently dropping caller flags or changing geometry.
/// setup returns a complete owner, or rolls back every adopted mapping/handle on failure.
/// # Errors
/// Returns baseline/topology/capability errors, mmap failures or the setup errno.
/// # Panics
/// Does not panic.
#[cold_sink]
pub fn setup<S: SqeGeometry, C: CqeGeometry>(
    entries: u32,
    mut params: IoUringParams,
) -> Result<NativeRing<S, C>> {
    sys::ensure_kernel_baseline_6_16()?;
    validate::<S, C>(entries, &mut params)?;
    let memory = user_memory::<S, C>(entries, &mut params)?;
    // SAFETY: params is initialized and exclusive. Any NO_MMAP addresses name retained guarded
    // allocations; failed setup rolls back kernel pins before returning the negative errno.
    let result = unsafe { sys::sys_io_uring_setup(entries, &raw mut params) };
    if result < 0 {
        return Err(UringError::cold_ring_init(result));
    }
    let handle = if params.flags & IORING_SETUP_REGISTERED_FD_ONLY != 0 {
        RingHandle::RegisteredOnly {
            registered_index: result as u32,
        }
    } else {
        // SAFETY: Setup without REGISTERED_FD_ONLY returns a new VFS descriptor adopted exactly
        // once.
        let fd = unsafe { OwnedFd::from_raw_fd(result) };
        RingHandle::Vfs {
            fd,
            registered_index: None,
        }
    };
    let mut storage = RingStorage {
        handle: Some(handle),
        memory: memory.map(RingMemory::UserProvided),
        retain_memory: false,
    };
    if params.sq_entries == 0
        || !params.sq_entries.is_power_of_two()
        || params.sq_entries > 32768
        || params.cq_entries == 0
        || !params.cq_entries.is_power_of_two()
        || params.cq_entries > 65536
        || (S::MIXED && params.flags & IORING_SETUP_SQ_REWIND == 0 && params.sq_entries < 4)
        || (C::MIXED && params.cq_entries < 2)
    {
        return Err(UringError::InvalidTopology(
            "kernel returned invalid ring counts",
        ));
    }
    if params.features & IORING_FEAT_NODROP == 0 {
        return Err(UringError::UnsupportedCapability("NODROP"));
    }
    if params.features & IORING_FEAT_EXT_ARG == 0 {
        return Err(UringError::UnsupportedCapability("EXT_ARG"));
    }
    if S::MIXED && params.features & IORING_FEAT_CQE_SKIP == 0 {
        return Err(UringError::UnsupportedCapability(
            "CQE_SKIP for mixed SQ padding",
        ));
    }
    if params.flags & IORING_SETUP_SQ_REWIND != 0
        && params.features & IORING_FEAT_SUBMIT_STABLE == 0
    {
        return Err(UringError::UnsupportedCapability(
            "SUBMIT_STABLE for rewind compaction",
        ));
    }
    let sq_size = if params.flags & IORING_SETUP_NO_SQARRAY == 0 {
        extent(params.sq_off.array, params.sq_entries, 4)?
    } else {
        [
            params.sq_off.head,
            params.sq_off.tail,
            params.sq_off.flags,
            params.sq_off.ring_mask,
            params.sq_off.ring_entries,
        ]
        .into_iter()
        .map(|n| extent(n, 1, 4))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .ok_or(UringError::InvalidTopology("missing SQ header"))?
    };
    let cq_size = extent(params.cq_off.cqes, params.cq_entries, C::STRIDE)?;
    if storage.memory.is_none() {
        let Some(RingHandle::Vfs { fd, .. }) = storage.handle.as_ref() else {
            return Err(UringError::InvalidTopology(
                "mmap requires a VFS ring handle",
            ));
        };
        let single = params.features & IORING_FEAT_SINGLE_MMAP != 0;
        let sq = MmapRegion::map(
            fd.as_fd(),
            IORING_OFF_SQ_RING,
            if single {
                sq_size.max(cq_size)
            } else {
                sq_size
            },
        )?;
        let cq = if single {
            None
        } else {
            Some(MmapRegion::map(fd.as_fd(), IORING_OFF_CQ_RING, cq_size)?)
        };
        let sqes = MmapRegion::map(
            fd.as_fd(),
            IORING_OFF_SQES,
            extent(0, params.sq_entries, S::STRIDE)?,
        )?;
        storage.memory = Some(RingMemory::KernelMapped { sq, cq, sqes });
    }
    let memory = storage
        .memory
        .as_ref()
        .ok_or(UringError::InvalidTopology("missing mapped ring memory"))?;
    let (sq_region, cq_region, sqes_region) = memory.regions();
    let sq_word = |offset| sq_region.pointer::<u32>(offset as usize, 1);
    let cq_word = |offset| cq_region.pointer::<u32>(offset as usize, 1);
    if load32(sq_word(params.sq_off.ring_entries)?, Ordering::Acquire) != params.sq_entries
        || load32(sq_word(params.sq_off.ring_mask)?, Ordering::Acquire) != params.sq_entries - 1
        || load32(cq_word(params.cq_off.ring_entries)?, Ordering::Acquire) != params.cq_entries
        || load32(cq_word(params.cq_off.ring_mask)?, Ordering::Acquire) != params.cq_entries - 1
    {
        return Err(UringError::InvalidTopology(
            "shared ring masks disagree with setup parameters",
        ));
    }
    let head = sq_word(params.sq_off.head)?;
    let tail = sq_word(params.sq_off.tail)?;
    let sq_head = load32(head, Ordering::Acquire);
    let sq_tail = load32(tail, Ordering::Acquire);
    if sq_head != 0 || sq_tail != 0 {
        return Err(UringError::InvalidTopology("new SQ cursors are not zero"));
    }
    if params.flags & IORING_SETUP_NO_SQARRAY == 0 {
        let array =
            sq_region.pointer::<u32>(params.sq_off.array as usize, params.sq_entries as usize)?;
        for index in 0..params.sq_entries {
            // SAFETY: The checked array contains every index; initial unpublished entries are
            // owner-written once before the first release tail store makes them visible.
            unsafe {
                array.add(index as usize).write(index);
            }
        }
    }
    let sqes = sqes_region.pointer::<u8>(0, extent(0, params.sq_entries, S::STRIDE)?)?;
    let cqes = cq_region
        .pointer::<u64>(
            params.cq_off.cqes as usize,
            extent(0, params.cq_entries, C::STRIDE)? / 8,
        )?
        .cast();
    let cq_head_pointer = cq_word(params.cq_off.head)?;
    let cq_head = load32(cq_head_pointer, Ordering::Acquire);
    let cq = CqState {
        head: cq_head_pointer,
        tail: cq_word(params.cq_off.tail)?,
        overflow: cq_word(params.cq_off.overflow)?,
        cqes,
        entries: params.cq_entries,
        mask: params.cq_entries - 1,
        local_head: cq_head,
        published_head: cq_head,
        cached_tail: cq_head,
    };
    let mut meta = SqMeta::new(0).patch(patch!(SqMeta { DRAINED: true }));
    if params.flags & IORING_SETUP_SQPOLL != 0 {
        meta |= SqMeta::SQPOLL;
    }
    let sq = SqState {
        head,
        tail,
        flags: sq_word(params.sq_off.flags)?,
        entries: params.sq_entries,
        mask: params.sq_entries - 1,
        sqes,
        cached_head: sq_head,
        local_tail: sq_tail,
        published_tail: sq_tail,
        meta,
    };
    Ok(NativeRing {
        storage,
        params,
        sq,
        cq,
        marker: PhantomData,
    })
}

/// Negotiates the existing four Proactor modes without changing their fallback order.
/// Caller-managed modifiers are mandatory; only known optional flags fall back on EINVAL.
/// # Errors
/// Returns configuration/affinity errors, required-feature failures or the setup errno.
/// # Panics
/// Does not panic.
#[cold_sink]
pub fn negotiate(config: crate::config::ProactorConfig) -> Result<NativeRing> {
    use crate::config::ProactorMode;
    config.validate()?;
    let sqpoll = match config.mode {
        ProactorMode::SqPoll(sq) | ProactorMode::SqPollIoPoll(sq) => Some(sq),
        _ => None,
    };
    if let Some(sq) = sqpoll {
        reject_shared_owner_cpu(sq.thread_cpu)?;
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
            let mut params = IoUringParams {
                flags,
                ..Default::default()
            };
            if let Some(entries) = config.cq_entries {
                params.cq_entries = entries;
                params.flags |= IORING_SETUP_CQSIZE;
            }
            if let Some(sq) = sqpoll {
                params.sq_thread_cpu = sq.thread_cpu;
                params.sq_thread_idle = sq.idle_ms.get();
            }
            match setup(config.entries, params) {
                Ok(ring) => {
                    if matches!(config.mode, ProactorMode::SqPoll(_))
                        && ring.params().features & IORING_FEAT_SQPOLL_NONFIXED == 0
                    {
                        return Err(UringError::UnsupportedCapability("SQPOLL_NONFIXED"));
                    }
                    return Ok(ring);
                }
                Err(UringError::RingInit(errno)) if errno == libc::EINVAL => {}
                Err(error) => return Err(error),
            }
        }
    }
    Err(UringError::RingInit(libc::EINVAL))
}
fn reject_shared_owner_cpu(thread_cpu: u32) -> Result<()> {
    let mut mask = vec![0usize; 16];
    loop {
        let bytes = core::mem::size_of_val(mask.as_slice());
        // SAFETY: The exclusive aligned buffer is writable for bytes bytes; pid zero selects
        // the caller thread. The library never changes the caller's affinity.
        if unsafe { libc::sched_getaffinity(0, bytes, mask.as_mut_ptr().cast()) } == 0 {
            let bits = usize::BITS as usize;
            let cpu = thread_cpu as usize;
            let contains = mask
                .get(cpu / bits)
                .is_some_and(|word| word & (1 << (cpu % bits)) != 0);
            if contains && mask.iter().map(|word| word.count_ones()).sum::<u32>() == 1 {
                return Err(UringError::InvalidConfig(
                    "sq thread cpu cannot share the owner's sole cpu",
                ));
            }
            return Ok(());
        }
        let errno = sys::last_os_errno();
        if errno != libc::EINVAL {
            return Err(UringError::cold_syscall("sched_getaffinity", errno));
        }
        if mask.len() >= 1 << 14 {
            return Err(UringError::InvalidConfig(
                "owner CPU mask exceeds supported extent",
            ));
        }
        mask.resize(mask.len() * 2, 0);
    }
}
