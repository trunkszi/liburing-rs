//! Forbidden SQE flags are rejected before entering a real kernel ring.

use std::time::{Duration, Instant};

use liburing::{
    OperationId, OperationPayload, Proactor, ProactorConfig, SubsystemId, UringError,
    backend as sys,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn operation(payload: u64) -> OperationId {
    OperationId::pack(
        SubsystemId::new_unchecked(1),
        OperationPayload::new_unchecked(payload),
    )
}

fn prepare_nop_with_flags(sqe: *mut sys::RawSqe, flags: u32) {
    // SAFETY: Called only with exclusive initialized SQE storage provided by a
    // preparation callback. NOP references no descriptors or external buffers.
    unsafe {
        *sqe = sys::RawSqe::from_entry(io_uring::opcode::Nop::new().build());
        (*sqe).flags = flags as u8;
    }
}

#[test]
fn integration_scenario_drain_and_link_rejection_keeps_dispatch_and_callbacks_live() -> TestResult {
    let forbidden = [
        sys::IOSQE_IO_DRAIN,
        sys::IOSQE_IO_LINK,
        sys::IOSQE_IO_HARDLINK,
        sys::IOSQE_IO_DRAIN | sys::IOSQE_IO_LINK,
        sys::IOSQE_IO_DRAIN | sys::IOSQE_IO_HARDLINK,
        sys::IOSQE_CQE_SKIP_SUCCESS,
    ];
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 1,
        staged_capacity: 1,
        ..ProactorConfig::default()
    })?;
    for flags in forbidden {
        let rejected = proactor.prepare_sqe_with(operation(99), |sqe| {
            prepare_nop_with_flags(sqe, flags);
        });
        assert!(matches!(rejected, Err(UringError::InvalidPreparedSqe(_))));
    }
    proactor.alloc_sqe(operation(1))?;
    let mut observed = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while observed.len() < 2 && Instant::now() < deadline {
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe: liburing::Completion, context: &mut liburing::SubmissionContext<'_>| {
                assert_eq!(cqe.result, 0);
                observed.push(cqe.operation_id);
                if cqe.operation_id == operation(1) {
                    let capacity = context.remaining_capacity();
                    for flags in forbidden {
                        let rejected = context.prepare_sqe_with(operation(99), |sqe| {
                            prepare_nop_with_flags(sqe, flags);
                        });
                        assert!(matches!(rejected, Err(UringError::InvalidPreparedSqe(_))));
                        assert_eq!(context.remaining_capacity(), capacity);
                    }
                    context.prepare_sqe_with(operation(2), |sqe| prepare_nop_with_flags(sqe, 0))?;
                }
                Ok(())
            },
        )?;
    }
    assert_eq!(observed, [operation(1), operation(2)]);
    proactor.shutdown()?;
    Ok(())
}

#[test]
fn integration_scenario_message_ring_and_reserved_identifiers_are_transactional() -> TestResult {
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 2,
        staged_capacity: 2,
        operation_capacity: 1,
        ..ProactorConfig::default()
    })?;
    for identity in [OperationId::from_raw(1), OperationId::from_raw(u64::MAX)] {
        assert!(proactor.alloc_sqe(identity).is_err());
        assert_eq!(proactor.operation_count(), 0);
    }
    assert!(matches!(
        proactor.prepare_sqe_with(operation(1), |sqe| {
            // SAFETY: The callback provides exclusive initialized SQE storage. The
            // opcode is rejected before publication and contains no DMA operands.
            unsafe { (*sqe).opcode = io_uring::opcode::MsgRingData::CODE };
        }),
        Err(UringError::InvalidPreparedSqe(_))
    ));
    assert_eq!(proactor.operation_count(), 0);
    proactor.alloc_sqe(operation(2))?;
    let mut observed = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while observed.len() < 2 && Instant::now() < deadline {
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe: liburing::Completion, context: &mut liburing::SubmissionContext<'_>| {
                assert_eq!(cqe.result, 0);
                observed.push(cqe.operation_id);
                if cqe.operation_id == operation(2) {
                    let credit = context.remaining_capacity();
                    assert!(matches!(
                        context.prepare_sqe_with(operation(3), |sqe| {
                            // SAFETY: The callback owns initialized exclusive SQE
                            // storage, and validation rejects it before publication.
                            unsafe { (*sqe).opcode = io_uring::opcode::MsgRingData::CODE };
                        }),
                        Err(UringError::InvalidPreparedSqe(_))
                    ));
                    assert_eq!(context.remaining_capacity(), credit);
                    context.prepare_sqe_with(operation(4), |sqe| prepare_nop_with_flags(sqe, 0))?;
                }
                Ok(())
            },
        )?;
    }
    assert_eq!(observed, [operation(2), operation(4)]);
    assert_eq!(proactor.operation_count(), 0);
    proactor.shutdown()?;
    Ok(())
}
