//! Kernel scenarios for native mapped-ring cursor ownership.
use liburing::backend::{
    ring::{
        NativeRing,
        geometry::{Cqe16, Sqe64},
    },
    sys::{params::*, sqe::RawSqe},
};

#[test]
fn standard_batch_and_peek() {
    for flags in [0, IORING_SETUP_NO_SQARRAY] {
        let mut ring = NativeRing::<Sqe64, Cqe16>::with_params(
            4,
            liburing::backend::sys::params::IoUringParams {
                flags,
                ..Default::default()
            },
        )
        .unwrap();
        for id in 1..=3 {
            // SAFETY: NOP has no external operands; its initialized SQE is copied before return.
            unsafe {
                ring.submission()
                    .unwrap()
                    .push(&RawSqe {
                        user_data: id,
                        ..Default::default()
                    })
                    .unwrap();
            }
        }
        assert_eq!(
            ring.submission().unwrap().publish_and_need_wakeup(),
            (3, false)
        );
        assert_eq!(ring.enter(3, 3, IORING_ENTER_GETEVENTS).unwrap(), 3);
        let mut cq = ring.completion();
        cq.refresh_tail();
        assert_eq!(cq.peek_ahead(1).unwrap().user_data, 2);
        for id in 1..=3 {
            assert_eq!(cq.pop().unwrap().user_data, id);
        }
        assert_eq!(cq.commit_head(), 3);
        assert_eq!(cq.commit_head(), 0);
    }
}

#[test]
fn fixed_wide_queue_geometry() {
    use liburing::backend::{
        ring::geometry::{Cqe32, Sqe128},
        sys::sqe::{IORING_OP_NOP128, RawSqe128},
    };
    let mut ring = NativeRing::<Sqe128, Cqe32>::with_params(4, Default::default()).unwrap();
    let entry = RawSqe128 {
        base: RawSqe {
            opcode: IORING_OP_NOP128,
            user_data: 17,
            operation_flags: 1 << 5,
            off: 0x1122,
            addr: 0x3344,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: NOP128 with NOP_CQE32 consumes these fields as immediate data, never as pointers.
    unsafe {
        ring.submission().unwrap().reserve_wide(&entry).unwrap();
    }
    assert_eq!(
        ring.submission().unwrap().publish_and_need_wakeup(),
        (1, false)
    );
    assert_eq!(ring.enter(1, 1, IORING_ENTER_GETEVENTS).unwrap(), 1);
    let mut cq = ring.completion();
    cq.refresh_tail();
    let result = cq.pop().unwrap();
    if result.base.res == -libc::EINVAL {
        assert_eq!(result.base.user_data, 17);
        assert_eq!(cq.commit_head(), 1);
        return;
    }
    assert_eq!((result.base.user_data, result.base.res), (17, 0));
    assert_eq!(result.big_cqe, [0x1122, 0x3344]);
    assert_eq!(cq.commit_head(), 1);
}

#[test]
fn mixed_sq_padding_is_transactional() {
    for flags in [0, IORING_SETUP_NO_SQARRAY] {
        mixed_sq_padding(flags);
    }
}
fn mixed_sq_padding(flags: u32) {
    use liburing::backend::{
        ring::geometry::SqeMixed,
        sys::sqe::{IORING_OP_NOP128, RawSqe128},
    };
    let Ok(mut ring) = NativeRing::<SqeMixed, Cqe16>::with_params(
        4,
        liburing::backend::sys::params::IoUringParams {
            flags,
            ..Default::default()
        },
    ) else {
        return;
    };
    let wide = RawSqe128 {
        base: RawSqe {
            opcode: IORING_OP_NOP128,
            user_data: 44,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: All entries are operand-free NOPs. Failed wide reservation must not publish a pad.
    unsafe {
        let mut sq = ring.submission().unwrap();
        for id in 1..=3 {
            sq.push(&RawSqe {
                user_data: id,
                ..Default::default()
            })
            .unwrap();
        }
        assert_eq!(
            sq.reserve_wide(&wide),
            Err(liburing::UringError::SqRingFull)
        );
        assert_eq!(sq.publish_and_need_wakeup(), (3, false));
    }
    assert_eq!(ring.enter(3, 3, IORING_ENTER_GETEVENTS).unwrap(), 3);
    {
        let mut cq = ring.completion();
        cq.refresh_tail();
        for id in 1..=3 {
            assert_eq!(cq.pop().unwrap().user_data, id);
        }
        cq.commit_head();
    }
    // SAFETY: The pad, wide NOP and following narrow NOP have no retained operands.
    unsafe {
        let mut sq = ring.submission().unwrap();
        sq.reserve_wide(&wide).unwrap();
        sq.push(&RawSqe {
            user_data: 55,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(sq.publish_and_need_wakeup(), (4, false));
    }
    assert_eq!(ring.enter(4, 2, IORING_ENTER_GETEVENTS).unwrap(), 4);
    let mut cq = ring.completion();
    cq.refresh_tail();
    assert_eq!(cq.pop().unwrap().user_data, 44);
    assert_eq!(cq.pop().unwrap().user_data, 55);
    assert!(cq.pop().is_none());
    assert_eq!(cq.commit_head(), 2);
}

#[test]
fn mixed_cq_gap_and_extensions() {
    use liburing::backend::{ring::geometry::CqeMixed, sys::cqe::IORING_CQE_F_32};
    let Ok(mut ring) = NativeRing::<Sqe64, CqeMixed>::with_params(4, Default::default()) else {
        return;
    };
    let entries = ring.params().cq_entries;
    for id in 1..entries {
        // SAFETY: The staged NOP has no external operands.
        unsafe {
            ring.submission()
                .unwrap()
                .push(&RawSqe {
                    user_data: id as u64,
                    ..Default::default()
                })
                .unwrap();
        }
        ring.submission().unwrap().publish_and_need_wakeup();
        ring.enter(1, 1, IORING_ENTER_GETEVENTS).unwrap();
        let mut cq = ring.completion();
        cq.refresh_tail();
        assert_eq!(cq.pop().unwrap().base.user_data, id as u64);
        cq.commit_head();
    }
    // SAFETY: NOP_CQE32 treats off/addr as immediate extension words, not dereferenced operands.
    unsafe {
        ring.submission()
            .unwrap()
            .push(&RawSqe {
                user_data: 77,
                operation_flags: 1 << 5,
                off: 0xaabb,
                addr: 0xccdd,
                ..Default::default()
            })
            .unwrap();
    }
    ring.submission().unwrap().publish_and_need_wakeup();
    ring.enter(1, 1, IORING_ENTER_GETEVENTS).unwrap();
    let mut cq = ring.completion();
    cq.refresh_tail();
    assert_eq!(cq.peek_ahead(0).unwrap().user_data, 77);
    assert!(cq.peek_ahead(1).is_none());
    let entry = cq.pop().unwrap();
    assert_eq!(entry.base.user_data, 77);
    assert_ne!(entry.base.flags & IORING_CQE_F_32, 0);
    assert_eq!(entry.big_cqe, [0xaabb, 0xccdd]);
    assert!(cq.pop().is_none());
    assert_eq!(cq.commit_head(), 3);
    assert_eq!(cq.commit_head(), 0);
    // SAFETY: The following NOP has no operands and must use one CQ unit after the extended record.
    unsafe {
        ring.submission()
            .unwrap()
            .push(&RawSqe {
                user_data: 88,
                ..Default::default()
            })
            .unwrap();
    }
    ring.submission().unwrap().publish_and_need_wakeup();
    ring.enter(1, 1, IORING_ENTER_GETEVENTS).unwrap();
    let mut cq = ring.completion();
    cq.refresh_tail();
    let next = cq.pop().unwrap();
    assert_eq!(next.base.user_data, 88);
    assert_eq!(next.big_cqe, [0, 0]);
    assert_eq!(cq.commit_head(), 1);
}

#[test]
fn rewind_compacts_kernel_short_submit() {
    let Ok(mut ring) = NativeRing::<Sqe64, Cqe16>::with_params(
        4,
        liburing::backend::sys::params::IoUringParams {
            flags: IORING_SETUP_SQ_REWIND | IORING_SETUP_NO_SQARRAY,
            ..Default::default()
        },
    ) else {
        return;
    };
    assert!(ring.submission().is_err());
    // SAFETY: An invalid opcode and two NOPs have no DMA operands. Invalid opcode forces a
    // short submission with SUBMIT_ALL absent, exercising real-kernel suffix compaction.
    unsafe {
        let mut sq = ring.rewind().unwrap();
        sq.push(&RawSqe {
            opcode: 255,
            user_data: 1,
            ..Default::default()
        })
        .unwrap();
        for id in 2..=3 {
            sq.push(&RawSqe {
                user_data: id,
                ..Default::default()
            })
            .unwrap();
        }
        assert_eq!(sq.submit().unwrap(), 1);
        assert_eq!(sq.pending(), 2);
        assert_eq!(sq.submit().unwrap(), 2);
        assert_eq!(sq.pending(), 0);
        assert_eq!(sq.submit().unwrap(), 0);
    }
    assert_eq!(ring.shared_sq_cursors(), (0, 0));
    let mut cq = ring.completion();
    cq.refresh_tail();
    let first = cq.pop().unwrap();
    assert_eq!((first.user_data, first.res), (1, -libc::EINVAL));
    for id in 2..=3 {
        assert_eq!(cq.pop().unwrap().user_data, id);
    }
    assert!(cq.pop().is_none());
    assert_eq!(cq.commit_head(), 3);
}

#[test]
fn user_memory_registered_only_teardown() {
    use liburing::backend::mapping::RingHandle;
    for registered in [0, IORING_SETUP_REGISTERED_FD_ONLY] {
        for _ in 0..24 {
            let mut ring = NativeRing::<Sqe64, Cqe16>::with_params(
                4,
                liburing::backend::sys::params::IoUringParams {
                    flags: IORING_SETUP_NO_MMAP | IORING_SETUP_NO_SQARRAY | registered,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(
                matches!(ring.handle(), Some(RingHandle::RegisteredOnly { .. })),
                registered != 0
            );
            // SAFETY: Operand-free NOP is copied into private queue storage.
            unsafe {
                ring.submission()
                    .unwrap()
                    .push(&RawSqe {
                        user_data: 9,
                        ..Default::default()
                    })
                    .unwrap();
            }
            ring.submission().unwrap().publish_and_need_wakeup();
            ring.enter(1, 1, IORING_ENTER_GETEVENTS).unwrap();
            {
                let mut cq = ring.completion();
                cq.refresh_tail();
                assert_eq!(cq.pop().unwrap().user_data, 9);
                cq.commit_head();
            }
            // SAFETY: The sole NOP's final CQE was consumed; no other targets or notifications
            // exist.
            unsafe {
                ring.confirm_drained();
            }
        }
    }
}

#[test]
fn mode_negotiation_preserves_flags() {
    use liburing::{ProactorConfig, ProactorMode};
    for mode in [
        ProactorMode::EventDriven(Default::default()),
        ProactorMode::IoPoll,
    ] {
        let mut ring = liburing::backend::setup::negotiate(ProactorConfig {
            entries: 4,
            mode,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            ring.params().flags & IORING_SETUP_IOPOLL != 0,
            mode == ProactorMode::IoPoll
        );
        // SAFETY: A NOP has no buffer/descriptor operands.
        unsafe {
            ring.submission()
                .unwrap()
                .push(&RawSqe {
                    user_data: 21,
                    ..Default::default()
                })
                .unwrap();
        }
        ring.submission().unwrap().publish_and_need_wakeup();
        ring.enter(1, 1, IORING_ENTER_GETEVENTS).unwrap();
        let mut cq = ring.completion();
        cq.refresh_tail();
        assert_eq!(cq.pop().unwrap().user_data, 21);
        cq.commit_head();
    }
}

struct Affinity(Vec<usize>);
impl Drop for Affinity {
    fn drop(&mut self) {
        // SAFETY: Restore the initialized affinity mask captured from this test thread.
        let result = unsafe {
            libc::sched_setaffinity(
                0,
                std::mem::size_of_val(self.0.as_slice()),
                self.0.as_ptr().cast(),
            )
        };
        assert_eq!(result, 0);
    }
}
fn pin_owner() -> (Affinity, u32) {
    let mut mask = vec![0usize; 16];
    loop {
        // SAFETY: The aligned, exclusive buffer has the byte capacity passed to sched_getaffinity.
        if unsafe {
            libc::sched_getaffinity(
                0,
                std::mem::size_of_val(mask.as_slice()),
                mask.as_mut_ptr().cast(),
            )
        } == 0
        {
            break;
        }
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert!(mask.len() < 1 << 14);
        mask.resize(mask.len() * 2, 0);
    }
    let cpus: Vec<_> = mask
        .iter()
        .enumerate()
        .flat_map(|(word, &bits)| {
            (0..usize::BITS as usize).filter_map(move |bit| {
                (bits & (1 << bit) != 0).then_some(word * usize::BITS as usize + bit)
            })
        })
        .take(2)
        .collect();
    assert_eq!(cpus.len(), 2, "two distinct allowed CPUs are required");
    let guard = Affinity(mask);
    let mut owner = vec![0usize; guard.0.len()];
    owner[cpus[0] / usize::BITS as usize] |= 1 << (cpus[0] % usize::BITS as usize);
    // SAFETY: The temporary initialized mask pins only this test thread to one allowed CPU.
    let result = unsafe {
        libc::sched_setaffinity(
            0,
            std::mem::size_of_val(owner.as_slice()),
            owner.as_ptr().cast(),
        )
    };
    assert_eq!(result, 0);
    (guard, cpus[1] as u32)
}

#[test]
fn sqpoll_sleep_handshake_and_idle() {
    use liburing::{ProactorConfig, ProactorMode, SqPollConfig};
    let (_guard, thread_cpu) = pin_owner();
    for mode in [
        ProactorMode::SqPoll(SqPollConfig {
            thread_cpu,
            idle_ms: std::num::NonZeroU32::new(1).unwrap(),
        }),
        ProactorMode::SqPollIoPoll(SqPollConfig {
            thread_cpu,
            idle_ms: std::num::NonZeroU32::new(1).unwrap(),
        }),
    ] {
        let mut ring = liburing::backend::setup::negotiate(ProactorConfig {
            entries: 4,
            mode,
            ..Default::default()
        })
        .unwrap();
        let start = std::time::Instant::now();
        while ring.submission().unwrap().flags() & IORING_SQ_NEED_WAKEUP == 0 {
            assert!(start.elapsed() < std::time::Duration::from_secs(2));
            std::thread::yield_now();
        }
        let before = ring.shared_sq_cursors();
        assert_eq!(
            ring.submission().unwrap().publish_and_need_wakeup(),
            (0, false)
        );
        assert_eq!(ring.shared_sq_cursors(), before);
        // SAFETY: NOP has no DMA operands and completes once.
        unsafe {
            ring.submission()
                .unwrap()
                .push(&RawSqe {
                    user_data: 97,
                    ..Default::default()
                })
                .unwrap();
        }
        let (published, wake) = ring.submission().unwrap().publish_and_need_wakeup();
        assert_eq!(published, 1);
        let (published, recheck) = ring.submission().unwrap().publish_and_need_wakeup();
        assert_eq!(published, 0);
        // The SQ thread may observe the tail and clear NEED_WAKEUP before either flag reread.
        if wake || recheck {
            ring.enter(0, 0, IORING_ENTER_SQ_WAKEUP).unwrap();
        }
        loop {
            let mut cq = ring.completion();
            cq.refresh_tail();
            if let Some(entry) = cq.pop() {
                assert_eq!(entry.user_data, 97);
                cq.commit_head();
                break;
            }
            assert!(start.elapsed() < std::time::Duration::from_secs(3));
            std::thread::yield_now();
        }
    }
}

#[test]
fn adopted_registration_survives_views() {
    use std::os::fd::AsRawFd;

    use liburing::backend::{
        mapping::RingHandle,
        sys::{self, register::*},
    };
    for _ in 0..24 {
        let mut ring = NativeRing::<Sqe64, Cqe16>::with_params(4, Default::default()).unwrap();
        let fd = match ring.handle().unwrap() {
            RingHandle::Vfs { fd, .. } => fd.as_raw_fd(),
            _ => unreachable!(),
        };
        let mut update = IoUringRsrcUpdate {
            offset: u32::MAX,
            data: fd as u64,
            ..Default::default()
        };
        // SAFETY: The initialized registration record names the live VFS ring. A successful
        // index is immediately transferred to that same owner's cleanup obligation.
        unsafe {
            assert_eq!(
                sys::sys_io_uring_register(
                    fd,
                    IORING_REGISTER_RING_FDS,
                    (&raw mut update).cast(),
                    1
                ),
                1
            );
            ring.adopt_registered_index(update.offset).unwrap();
            ring.submission()
                .unwrap()
                .push(&RawSqe {
                    user_data: 123,
                    ..Default::default()
                })
                .unwrap();
        }
        ring.submission().unwrap().publish_and_need_wakeup();
        ring.enter(1, 1, IORING_ENTER_GETEVENTS).unwrap();
        let mut cq = ring.completion();
        cq.refresh_tail();
        assert_eq!(cq.pop().unwrap().user_data, 123);
        cq.commit_head();
    }
}

#[test]
fn topology_and_setup_rollback() {
    use liburing::backend::sys::params::IoUringParams;
    for flags in [
        IORING_SETUP_REGISTERED_FD_ONLY,
        IORING_SETUP_SQ_REWIND,
        IORING_SETUP_SQ_REWIND | IORING_SETUP_NO_SQARRAY | IORING_SETUP_SQPOLL,
        IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED,
    ] {
        assert!(
            NativeRing::<Sqe64, Cqe16>::with_params(
                4,
                IoUringParams {
                    flags,
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
    let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before = count();
    for _ in 0..24 {
        assert!(
            NativeRing::<Sqe64, Cqe16>::with_params(
                4,
                IoUringParams {
                    flags: IORING_SETUP_NO_MMAP | IORING_SETUP_REGISTERED_FD_ONLY | (1 << 31),
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
    assert_eq!(count(), before);
}

#[test]
fn mixed_rewind_keeps_wide_suffix() {
    use liburing::backend::{
        ring::geometry::SqeMixed,
        sys::sqe::{IORING_OP_NOP128, RawSqe128},
    };
    let Ok(mut ring) = NativeRing::<SqeMixed, Cqe16>::with_params(
        4,
        liburing::backend::sys::params::IoUringParams {
            flags: IORING_SETUP_NO_SQARRAY | IORING_SETUP_SQ_REWIND,
            ..Default::default()
        },
    ) else {
        return;
    };
    // SAFETY: Invalid opcode plus narrow/wide NOPs contain no pointer operands.
    unsafe {
        let mut sq = ring.rewind().unwrap();
        sq.push(&RawSqe {
            opcode: 255,
            user_data: 1,
            ..Default::default()
        })
        .unwrap();
        sq.reserve_wide(&RawSqe128 {
            base: RawSqe {
                opcode: IORING_OP_NOP128,
                user_data: 2,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        sq.push(&RawSqe {
            user_data: 3,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(sq.submit().unwrap(), 1);
        assert_eq!(sq.pending(), 3);
        assert_eq!(sq.submit().unwrap(), 3);
        assert_eq!(sq.pending(), 0);
    }
    assert!(ring.enter(1, 0, 0).is_err());
    ring.enter(0, 0, IORING_ENTER_GETEVENTS).unwrap();
    assert_eq!(ring.shared_sq_cursors(), (0, 0));
    let mut cq = ring.completion();
    cq.refresh_tail();
    for id in 1..=3 {
        assert_eq!(cq.pop().unwrap().user_data, id);
    }
    assert_eq!(cq.commit_head(), 3);
}

/// Static probe for explicit publication and the conditional SQPOLL fence.
/// # Errors
/// Does not return errors.
/// # Panics
/// Does not panic.
#[unsafe(no_mangle)]
pub fn native_sq_publish_probe(sq: &mut liburing::backend::ring::sq::SqRing<'_, Sqe64>) -> u64 {
    let (units, wake) = sq.publish_and_need_wakeup();
    u64::from(units) | (u64::from(wake) << 32)
}
/// Static probe for the standard decoder: no mixed-width flag tests should remain.
/// # Errors
/// Does not return errors.
/// # Panics
/// Does not panic.
#[unsafe(no_mangle)]
pub fn native_cq16_probe(
    ring: &mut NativeRing<Sqe64, Cqe16>,
    output: &mut liburing::backend::sys::cqe::RawCqe,
) -> bool {
    let mut cq = ring.completion();
    cq.refresh_tail();
    if let Some(entry) = cq.pop() {
        *output = entry;
        cq.commit_head();
        true
    } else {
        false
    }
}
#[test]
fn standard_codegen_seams_execute() {
    let mut ring = NativeRing::<Sqe64, Cqe16>::with_params(4, Default::default()).unwrap();
    let before = ring.shared_sq_cursors();
    assert_eq!(native_sq_publish_probe(&mut ring.submission().unwrap()), 0);
    assert_eq!(ring.shared_sq_cursors(), before);
    // SAFETY: NOP has no external operands and completes exactly once.
    unsafe {
        ring.submission()
            .unwrap()
            .push(&RawSqe {
                user_data: 12345,
                ..Default::default()
            })
            .unwrap();
    }
    assert_eq!(native_sq_publish_probe(&mut ring.submission().unwrap()), 1);
    ring.enter(1, 1, IORING_ENTER_GETEVENTS).unwrap();
    let mut output = Default::default();
    assert!(native_cq16_probe(&mut ring, &mut output));
    assert_eq!(output.user_data, 12345);
    assert!(!native_cq16_probe(&mut ring, &mut output));
}

#[test]
fn mixed_minimum_capacity_is_explicit() {
    use liburing::backend::{
        ring::geometry::SqeMixed,
        sys::sqe::{IORING_OP_NOP128, RawSqe128},
    };
    assert!(NativeRing::<SqeMixed, Cqe16>::with_params(2, Default::default()).is_err());
    let Ok(rounded) = NativeRing::<SqeMixed, Cqe16>::with_params(3, Default::default()) else {
        return;
    };
    assert_eq!(rounded.params().sq_entries, 4);
    let Ok(mut rewind) = NativeRing::<SqeMixed, Cqe16>::with_params(
        2,
        liburing::backend::sys::params::IoUringParams {
            flags: IORING_SETUP_NO_SQARRAY | IORING_SETUP_SQ_REWIND,
            ..Default::default()
        },
    ) else {
        return;
    };
    // SAFETY: The complete two-unit NOP128 has no pointer operands.
    unsafe {
        rewind
            .rewind()
            .unwrap()
            .reserve_wide(&RawSqe128 {
                base: RawSqe {
                    opcode: IORING_OP_NOP128,
                    user_data: 71,
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
    }
    assert_eq!(rewind.rewind().unwrap().submit().unwrap(), 2);
    let mut cq = rewind.completion();
    cq.refresh_tail();
    assert_eq!(cq.pop().unwrap().user_data, 71);
    cq.commit_head();
}
