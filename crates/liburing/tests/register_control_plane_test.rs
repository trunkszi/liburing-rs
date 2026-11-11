//! Kernel registration contracts, including task-local handle routing.
use std::os::fd::AsRawFd;

use liburing::{Result, backend::register::*};

#[test]
fn probe_and_query_match_kernel() -> Result<()> {
    let (ring, params) = ring(0)?;
    let target = RegisterTarget::VfsFd(ring.as_raw_fd());
    let caps = Capabilities::discover(target, params.features)?;
    assert!(caps.opcodes().supports(0));
    assert!(caps.opcodes().supports(62));
    assert!(!caps.opcodes().supports(255));
    if let Ok(inventory) = query_opcode_inventory(target) {
        assert!(caps.opcodes().supports(64));
        assert!(inventory.nr_register_opcodes >= 38);
        assert!(inventory.nr_request_opcodes >= 65);
        assert_eq!(caps.register_opcode_known(37), Some(true));
        assert_eq!(caps.register_opcode_known(u32::MAX), Some(false));
    } else {
        assert_eq!(caps.register_opcode_known(37), None);
    }
    Ok(())
}

fn ring(
    flags: u32,
) -> Result<(
    std::os::fd::OwnedFd,
    liburing::backend::sys::params::IoUringParams,
)> {
    use std::os::fd::FromRawFd;

    use liburing::backend::sys::{self, params::IoUringParams};
    sys::ensure_kernel_baseline_6_16()?;
    let mut params = IoUringParams {
        flags,
        ..Default::default()
    };
    // SAFETY: The default setup uses no external memory and writes an exclusive initialized record.
    let fd = unsafe { sys::sys_io_uring_setup(8, &raw mut params) };
    if fd < 0 {
        return Err(liburing::UringError::syscalls("io_uring_setup", fd));
    }
    // SAFETY: Successful setup returned a new ordinary VFS descriptor, adopted exactly once.
    Ok((unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }, params))
}

#[test]
fn registered_index_routes_and_releases() -> Result<()> {
    use liburing::backend::sys::register::*;
    let (fd, _) = ring(0)?;
    let target = RegisterTarget::VfsFd(fd.as_raw_fd());
    let mut updates = [IoUringRsrcUpdate {
        offset: u32::MAX,
        data: fd.as_raw_fd() as u64,
        ..Default::default()
    }];
    // SAFETY: The ring is owned here and update storage is initialized and writable.
    assert_eq!(unsafe { register_ring_fds(target, &mut updates) }?, 1);
    struct Guard {
        fd: i32,
        slot: Option<u32>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(offset) = self.slot {
                let update = IoUringRsrcUpdate {
                    offset,
                    ..Default::default()
                };
                // SAFETY: Guard drops before its ring owner, on the registering thread.
                let cleanup =
                    unsafe { unregister_ring_fds(RegisterTarget::VfsFd(self.fd), &[update]) };
                if let Err(error) = cleanup {
                    eprintln!("registered ring cleanup failed: {error}");
                }
            }
        }
    }
    let mut guard = Guard {
        fd: fd.as_raw_fd(),
        slot: Some(updates[0].offset),
    };
    let registered = RegisterTarget::RegisteredIndex(updates[0].offset);
    assert_eq!(
        registered.syscall_args(RegisterOpcode::RegisterProbe)?.1,
        IORING_REGISTER_USE_REGISTERED_RING | IORING_REGISTER_PROBE
    );
    assert!(register_probe(registered)?.supports(0));
    // SAFETY: No operations reference the personality; unregister uses its exact returned ID.
    unsafe {
        let id = register_personality(registered)?;
        assert_eq!(unregister_personality(registered, id)?, 0);
        assert_eq!(
            unregister_ring_fds(
                registered,
                &[IoUringRsrcUpdate {
                    offset: updates[0].offset,
                    ..Default::default()
                }]
            )?,
            1
        );
    }
    guard.slot = None;
    assert!(register_probe(registered).is_err());
    assert!(register_probe(target)?.supports(0));
    Ok(())
}

#[test]
fn files_update_sparse_and_allocation_range() -> Result<()> {
    use liburing::backend::sys::register::*;
    let file = std::fs::File::open("/dev/null")?;
    let (fd, _) = ring(0)?;
    let target = RegisterTarget::VfsFd(fd.as_raw_fd());
    let files = [file.as_raw_fd(), -1];
    // SAFETY: Descriptors are live; no SQEs access the tables during mutation.
    unsafe {
        assert_eq!(register_files(target, &files)?, 0);
        assert_eq!(register_files_update(target, 1, &files[..1])?, 1);
        assert_eq!(
            register_file_alloc_range(
                target,
                &IoUringFileIndexRange {
                    off: 1,
                    len: 1,
                    ..Default::default()
                }
            )?,
            0
        );
        assert_eq!(unregister_files(target)?, 0);
        assert_eq!(
            register_files2(
                target,
                &IoUringRsrcRegister {
                    nr: 2,
                    flags: IORING_RSRC_REGISTER_SPARSE,
                    ..Default::default()
                }
            )?,
            0
        );
        assert_eq!(
            register_files_update2(
                target,
                &IoUringRsrcUpdate2 {
                    offset: 0,
                    data: files.as_ptr() as u64,
                    nr: 1,
                    ..Default::default()
                }
            )?,
            1
        );
        assert_eq!(unregister_files(target)?, 0);
    }
    Ok(())
}

#[test]
fn buffers_update_clone_and_pbuf_status() -> Result<()> {
    use liburing::backend::sys::register::*;
    let mut bytes = vec![0u8; 4096];
    let iovecs = [libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    }];
    let (source, _) = ring(0)?;
    let (dest, _) = ring(0)?;
    let target = RegisterTarget::VfsFd(source.as_raw_fd());
    let cloned = RegisterTarget::VfsFd(dest.as_raw_fd());
    // SAFETY: Rings drop before bytes on all paths. No I/O or buffer leases exist.
    unsafe {
        assert_eq!(register_buffers(target, &iovecs)?, 0);
        assert_eq!(unregister_buffers(target)?, 0);
        assert_eq!(
            register_buffers2(
                target,
                &IoUringRsrcRegister {
                    nr: 1,
                    flags: IORING_RSRC_REGISTER_SPARSE,
                    ..Default::default()
                }
            )?,
            0
        );
        assert_eq!(
            register_buffers_update(
                target,
                &IoUringRsrcUpdate2 {
                    data: iovecs.as_ptr() as u64,
                    nr: 1,
                    ..Default::default()
                }
            )?,
            1
        );
        assert_eq!(
            register_clone_buffers(
                cloned,
                &IoUringCloneBuffers {
                    src_fd: source.as_raw_fd() as u32,
                    nr: 1,
                    ..Default::default()
                }
            )?,
            0
        );
        assert_eq!(unregister_buffers(target)?, 0);
        assert_eq!(unregister_buffers(cloned)?, 0);
        for flags in [IOU_PBUF_RING_MMAP, IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC] {
            let mut record = IoUringBufReg {
                ring_entries: 8,
                bgid: 7,
                flags,
                ..Default::default()
            };
            assert_eq!(register_pbuf_ring(target, &mut record)?, 0);
            let mut status = IoUringBufStatus {
                buf_group: 7,
                ..Default::default()
            };
            assert_eq!(register_pbuf_status(target, &mut status)?, 0);
            assert_eq!(status.head, 0);
            assert_eq!(unregister_pbuf_ring(target, 7)?, 0);
        }
    }
    Ok(())
}

#[test]
fn workers_clock_napi_and_eventfd() -> Result<()> {
    use std::os::fd::FromRawFd;

    use liburing::backend::sys::register::*;
    let (fd, _) = ring(0)?;
    let target = RegisterTarget::VfsFd(fd.as_raw_fd());
    let mut workers = [1, 1];
    let mut current = [0, 0];
    let mut napi = IoUringNapi {
        busy_poll_to: 10,
        ..Default::default()
    };
    // SAFETY: All control records are initialized and exclusive; no active operations exist.
    unsafe {
        assert_eq!(register_iowq_max_workers(target, &mut workers)?, 0);
        assert_eq!(register_iowq_max_workers(target, &mut current)?, 0);
        assert_eq!(current, [1, 1]);
        assert_eq!(
            register_clock(
                target,
                &IoUringClockRegister {
                    clockid: libc::CLOCK_MONOTONIC as u32,
                    ..Default::default()
                }
            )?,
            0
        );
        assert_eq!(register_napi(target, &mut napi)?, 0);
        assert_eq!(unregister_napi(target, &mut napi)?, 0);
    }
    let mut affinity = [0u8; 1024];
    // SAFETY: The array is writable and supplies its exact byte extent.
    let rc = unsafe { libc::sched_getaffinity(0, affinity.len(), affinity.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);
    // SAFETY: The native bitmap is initialized; only this ring's worker settings change.
    unsafe {
        assert_eq!(register_iowq_aff(target, &affinity)?, 0);
        assert_eq!(unregister_iowq_aff(target)?, 0);
    }
    // SAFETY: eventfd has no borrowed operands and returns a new descriptor on success.
    let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: This owner adopts the newly created descriptor exactly once.
    let event = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    // SAFETY: The descriptor is an owned live eventfd; no eventfd registration is in flight.
    unsafe {
        assert_eq!(register_eventfd(target, event.as_raw_fd())?, 0);
        assert_eq!(unregister_eventfd(target)?, 0);
        assert_eq!(register_eventfd_async(target, event.as_raw_fd())?, 0);
        assert_eq!(unregister_eventfd(target)?, 0);
    }
    Ok(())
}

#[test]
fn restrictions_keep_padding_cancel_and_teardown() -> Result<()> {
    use liburing::backend::sys::sqe::IOSQE_ASYNC;
    for allowed in [None, Some(0), Some(IOSQE_ASYNC)] {
        restricted_policy_case(allowed)?;
    }
    Ok(())
}

fn restricted_policy_case(allowed: Option<u8>) -> Result<()> {
    use liburing::backend::{
        IoUring, opcode, squeue,
        sys::{register::*, sqe::IOSQE_ASYNC},
        types,
    };
    let mut ring: IoUring = IoUring::builder()
        .setup_r_disabled()
        .setup_submit_all()
        .build(8)?;
    let target = RegisterTarget::VfsFd(ring.as_raw_fd());
    let mut rules = vec![
        IoUringRestriction {
            opcode: IORING_RESTRICTION_SQE_OP,
            register_op: liburing::backend::sys::sqe::IORING_OP_READ,
            ..Default::default()
        },
        IoUringRestriction {
            opcode: IORING_RESTRICTION_REGISTER_OP,
            register_op: IORING_REGISTER_PERSONALITY as u8,
            ..Default::default()
        },
    ];
    if let Some(flags) = allowed {
        rules.push(IoUringRestriction {
            opcode: IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
            register_op: flags,
            ..Default::default()
        });
    }
    // SAFETY: Disabled ring is exclusively owned; there are no operations or resource users.
    unsafe {
        assert_eq!(register_restrictions(target, &rules)?, 0);
        assert_eq!(register_enable_rings(target)?, 0);
        let id = register_personality(target)?;
        assert_eq!(unregister_personality(target, id)?, 0);
        let cancel = IoUringSyncCancelReg {
            flags: 4,
            timeout: liburing::backend::sys::params::KernelTimespec {
                tv_sec: -1,
                tv_nsec: 0,
            },
            ..Default::default()
        };
        assert_eq!(register_sync_cancel(target, &cancel)?, 0);
    }
    assert_eq!(
        register_probe(target).map(|_| ()),
        Err(liburing::UringError::syscalls(
            "io_uring_register",
            libc::EACCES
        ))
    );
    let entries = [
        opcode::Nop::new()
            .build()
            .flags(squeue::Flags::SKIP_SUCCESS),
        opcode::Nop::new().build(),
        opcode::AsyncCancel::new(0xdead).build(),
        opcode::Fsync::new(types::Fd(-1)).build(),
        opcode::Nop::new().build().flags(squeue::Flags::ASYNC),
    ];
    {
        let mut sq = ring.submission();
        for (id, entry) in entries.into_iter().enumerate() {
            // SAFETY: NOP has no operands, cancel references no live target and fsync is rejected.
            unsafe { sq.push(&entry.user_data(id as u64)) }
                .map_err(|_| liburing::UringError::SqRingFull)?;
        }
    }
    assert_eq!(ring.submit_and_wait(4)?, 5);
    let mut results = [i32::MAX; 5];
    for cqe in ring.completion() {
        results[cqe.user_data() as usize] = cqe.result();
    }
    let async_result = if allowed.is_some_and(|flags| flags & IOSQE_ASYNC != 0) {
        0
    } else {
        -libc::EACCES
    };
    assert_eq!(
        results,
        [i32::MAX, 0, -libc::ENOENT, -libc::EACCES, async_result]
    );
    Ok(())
}

#[test]
fn flag_only_rules_keep_nop_and_cancel() -> Result<()> {
    use liburing::backend::{
        IoUring, opcode, squeue,
        sys::{register::*, sqe::IOSQE_CQE_SKIP_SUCCESS},
    };
    for kind in [
        IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
        IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
    ] {
        let mut ring: IoUring = IoUring::builder()
            .setup_r_disabled()
            .setup_submit_all()
            .build(8)?;
        let target = RegisterTarget::VfsFd(ring.as_raw_fd());
        let rules = [IoUringRestriction {
            opcode: kind,
            register_op: 0,
            ..Default::default()
        }];
        // SAFETY: The disabled ring is exclusive and has no outstanding operations.
        unsafe {
            assert_eq!(register_restrictions(target, &rules)?, 0);
            assert_eq!(register_enable_rings(target)?, 0);
        }
        let entries = [
            opcode::Nop::new()
                .build()
                .flags(squeue::Flags::SKIP_SUCCESS)
                .user_data(0),
            opcode::Nop::new().build().user_data(1),
            opcode::AsyncCancel::new(0xdead).build().user_data(2),
        ];
        {
            let mut sq = ring.submission();
            for entry in entries {
                // SAFETY: NOP has no operands. Cancel names no live operation.
                unsafe { sq.push(&entry) }.map_err(|_| liburing::UringError::SqRingFull)?;
            }
        }
        assert_eq!(ring.submit_and_wait(2)?, 3);
        let mut results = [i32::MAX; 3];
        for cqe in ring.completion() {
            results[cqe.user_data() as usize] = cqe.result();
        }
        assert_eq!(squeue::Flags::SKIP_SUCCESS.bits(), IOSQE_CQE_SKIP_SUCCESS);
        assert_eq!(results, [i32::MAX, 0, -libc::ENOENT]);
    }
    Ok(())
}

#[test]
fn required_flags_rejected_before_registration() -> Result<()> {
    use liburing::{
        UringError,
        backend::{IoUring, sys::register::*},
    };
    let ring: IoUring = IoUring::builder().setup_r_disabled().build(8)?;
    let target = RegisterTarget::VfsFd(ring.as_raw_fd());
    for flags in 1..=u8::MAX {
        let rules = [IoUringRestriction {
            opcode: IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
            register_op: flags,
            ..Default::default()
        }];
        // SAFETY: The disabled ring is exclusive and has no outstanding operations.
        let result = unsafe { register_restrictions(target, &rules) };
        assert!(
            matches!(result, Err(UringError::InvalidConfig(_))),
            "mask {flags}: {result:?}"
        );
    }
    let rules = [IoUringRestriction {
        opcode: IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
        ..Default::default()
    }];
    // SAFETY: Rejected policies must leave the exclusively owned ring disabled and unrestricted.
    unsafe {
        assert_eq!(register_restrictions(target, &rules)?, 0);
        assert_eq!(register_enable_rings(target)?, 0);
    }
    Ok(())
}

#[test]
fn sync_cancel_and_send_msg_ring() -> Result<()> {
    use liburing::{
        UringError,
        backend::{
            IoUring, RawSqe,
            sys::{params::KernelTimespec, register::*, sqe::IORING_OP_MSG_RING},
        },
    };
    let mut ring = IoUring::new(8)?;
    let target = RegisterTarget::VfsFd(ring.as_raw_fd());
    let cancel = IoUringSyncCancelReg {
        flags: 4,
        timeout: KernelTimespec {
            tv_sec: -1,
            tv_nsec: 0,
        },
        ..Default::default()
    };
    // SAFETY: Ring is empty and the record has no pointer operands; cancellation cannot release
    // DMA.
    assert_eq!(unsafe { register_sync_cancel(target, &cancel) }, Ok(0));
    let sqe = RawSqe {
        opcode: IORING_OP_MSG_RING,
        fd: ring.as_raw_fd(),
        off: 0x1234,
        len: 17,
        ..Default::default()
    };
    // SAFETY: The destination ring is live; this data message transfers no descriptor or pointers.
    assert_eq!(unsafe { register_send_msg_ring(&sqe) }?, 0);
    let cqe = ring
        .completion()
        .next()
        .ok_or(UringError::InvalidConfig("missing message CQE"))?;
    assert_eq!((cqe.user_data(), cqe.result()), (0x1234, 17));
    Ok(())
}

#[test]
fn resize_and_registered_wait_region() -> Result<()> {
    use liburing::backend::sys::{params::*, register::*};
    #[repr(align(4096))]
    struct Page([u8; 4096]);
    let mut page = Box::new(Page([0; 4096]));
    let (fd, _) = ring(IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN)?;
    let target = RegisterTarget::VfsFd(fd.as_raw_fd());
    let mut params = IoUringParams {
        sq_entries: 16,
        cq_entries: 32,
        ..Default::default()
    };
    // SAFETY: The ring has no mappings or operations, so resizing invalidates no live view.
    assert_eq!(unsafe { register_resize_rings(target, &mut params) }?, 0);
    assert_eq!((params.sq_entries, params.cq_entries), (16, 32));
    let (disabled, _) = ring(IORING_SETUP_R_DISABLED)?;
    let mut region = IoUringRegionDesc {
        user_addr: page.0.as_mut_ptr() as u64,
        size: 4096,
        flags: IORING_MEM_REGION_TYPE_USER,
        ..Default::default()
    };
    let mut record = IoUringMemRegionReg {
        region_uptr: (&raw mut region) as u64,
        flags: IORING_MEM_REGION_REG_WAIT_ARG,
        ..Default::default()
    };
    // SAFETY: Aligned initialized page and writable descriptor outlive the disabled ring.
    let registered_region =
        unsafe { register_mem_region(RegisterTarget::VfsFd(disabled.as_raw_fd()), &mut record) }?;
    assert_eq!(registered_region, 0);
    assert_eq!(region.size, 4096);
    drop(disabled);
    drop(page);
    Ok(())
}

#[test]
fn optional_controls_preserve_bad_fd_errors() -> Result<()> {
    use liburing::{
        UringError,
        backend::sys::{query_bpf::IoUringBpf, zcrx::*},
    };
    let target = RegisterTarget::VfsFd(-2);
    let error = UringError::syscalls("io_uring_register", libc::EBADF);
    let mut ifq = IoUringZcrxIfqReg::default();
    let mut ctrl = ZcrxCtrl::default();
    let bpf = IoUringBpf::default();
    // SAFETY: Invalid non-blind fd makes the kernel reject before it can retain any operand.
    unsafe {
        assert_eq!(register_zcrx_ifq(target, &mut ifq), Err(error));
        assert_eq!(register_zcrx_ctrl(target, &mut ctrl), Err(error));
        assert_eq!(register_bpf_filter(target, &bpf), Err(error));
        assert_eq!(unregister_files(target), Err(error));
    }
    Ok(())
}

#[test]
fn invalid_index_cannot_become_blind_query() {
    assert!(matches!(
        query_opcode_inventory(RegisterTarget::VfsFd(-1)),
        Ok(_)
            | Err(liburing::UringError::Syscall {
                errno: libc::EINVAL | libc::ENOSYS,
                ..
            })
    ));
    assert!(matches!(
        query_opcode_inventory(RegisterTarget::RegisteredIndex(u32::MAX)),
        Err(liburing::UringError::InvalidConfig(_))
    ));
}
