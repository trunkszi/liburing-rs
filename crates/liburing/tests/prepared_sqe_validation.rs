//! Forbidden SQE flags are rejected before entering a real kernel ring.

use std::time::{Duration, Instant};

use liburing::{OpId, OpPayload, Proactor, ProactorConfig, SubsystemId, UringError};
use liburing_sys as sys;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn op(payload: u64) -> OpId {
    OpId::pack(
        SubsystemId::new_unchecked(1),
        OpPayload::new_unchecked(payload),
    )
}

fn prepare_nop_with_flags(sqe: *mut sys::io_uring_sqe, flags: u32) {
    // SAFETY: Called only with exclusive initialized SQE storage provided by a
    // preparation callback. NOP references no descriptors or external buffers.
    unsafe {
        sys::uring_shim_prep_nop(sqe);
        (*sqe).flags = flags as u8;
    }
}

#[test]
fn integration_scenario_drain_and_link_rejection_keeps_waker_and_callbacks_live() -> TestResult {
    let forbidden = [
        sys::IOSQE_IO_DRAIN,
        sys::IOSQE_IO_LINK,
        sys::IOSQE_IO_HARDLINK,
        sys::IOSQE_IO_DRAIN | sys::IOSQE_IO_LINK,
        sys::IOSQE_IO_DRAIN | sys::IOSQE_IO_HARDLINK,
    ];
    for enable_waker in [false, true] {
        let mut proactor = Proactor::new(ProactorConfig {
            entries: 1,
            staged_capacity: 1,
            enable_waker,
            ..ProactorConfig::default()
        })?;
        for flags in forbidden {
            let rejected = proactor.prepare_sqe_with(op(99), |sqe| {
                prepare_nop_with_flags(sqe, flags);
            });
            assert!(matches!(rejected, Err(UringError::InvalidPreparedSqe(_))));
        }
        proactor.alloc_sqe(op(1))?;
        let mut observed = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while observed.len() < 2 && Instant::now() < deadline {
            proactor.wait_completions(1, Some(Duration::from_millis(20)), |cqe, context| {
                assert_eq!(cqe.result, 0);
                observed.push(cqe.op_id);
                if cqe.op_id == op(1) {
                    let capacity = context.remaining_capacity();
                    for flags in forbidden {
                        let rejected = context.prepare_sqe_with(op(99), |sqe| {
                            prepare_nop_with_flags(sqe, flags);
                        });
                        assert!(matches!(rejected, Err(UringError::InvalidPreparedSqe(_))));
                        assert_eq!(context.remaining_capacity(), capacity);
                    }
                    context.prepare_sqe_with(op(2), |sqe| prepare_nop_with_flags(sqe, 0))?;
                }
                Ok(())
            })?;
        }
        assert_eq!(observed, [op(1), op(2)]);
        proactor.shutdown()?;
    }
    Ok(())
}
