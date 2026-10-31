//! Fault injection for shutdown stalls and cancellation retry ownership.

#[path = "../support/mode_affinity.rs"]
mod mode_affinity;
use mode_affinity::sq_thread_cpu;

use super::*;

#[test]
fn global_cancel_survives_dispatch_failure() -> Result<()> {
    let timeout = crate::ops::Timeout::new(Duration::from_secs(60))?;
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 64,
        operation_capacity: 64,
        staged_capacity: 64,
        max_cqe_batch: 1,
        ..ProactorConfig::default()
    })?;
    for payload in 0..48 {
        proactor.prepare_sqe_with(
            OperationId::pack(SubsystemId(1), crate::OperationPayload(payload)),
            |sqe| {
                // SAFETY: The immutable timeout owner precedes the ring and outlives all CQEs.
                unsafe { timeout.prepare(sqe) };
            },
        )?;
    }
    proactor.submit()?;
    let mut completed = 0;
    let error = proactor.shutdown_with(&mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
        assert_eq!(cqe.result, -libc::ECANCELED);
        completed += 1;
        Err(UringError::InvalidConfig("dispatcher interrupted teardown"))
    });
    assert_eq!(
        error,
        Err(UringError::InvalidConfig("dispatcher interrupted teardown"))
    );
    assert!(proactor.shutdown_cancel_issued);
    proactor.shutdown_with(&mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
        assert_eq!(cqe.result, -libc::ECANCELED);
        completed += 1;
        Ok(())
    })?;
    assert_eq!(completed, 48);
    assert!(proactor.shutdown_cancel_issued);
    assert!(!proactor.cancel_armed);
    assert!(proactor.is_idle());
    Ok(())
}

#[test]
fn shutdown_stall_retains_dma_for_retry() -> Result<()> {
    use crate::{config::ProactorMode, operation_slab::OperationKind};
    for mode in [
        ProactorMode::event_driven(),
        ProactorMode::sq_poll(sq_thread_cpu()?),
        ProactorMode::io_poll(),
        ProactorMode::sq_poll_io_poll(sq_thread_cpu()?),
    ] {
        let limit = Duration::from_millis(20);
        let mut proactor = Proactor::new(ProactorConfig {
            mode,
            shutdown_stall_timeout: Some(limit),
            ..Default::default()
        })?;
        proactor.configure_fixed_buffers(1, 4096)?;
        // SAFETY: The token is transferred immediately into ring-owned operation metadata.
        let buffer = unsafe { proactor.fixed_buffers() }?
            .checkout()?
            .into_in_flight();
        // A retained operation without a kernel CQE deterministically models a stalled device.
        let operations = proactor
            .operations
            .as_mut()
            .ok_or(UringError::InvalidConfig("closed table"))?;
        let key = operations.insert(
            TrackedOperation {
                original: OperationId::pack(SubsystemId(1), crate::OperationPayload(1)),
                keyed: true,
                buffer: Some(buffer),
                socket: None,
            },
            OperationKind::Single,
        )?;
        for _ in 0..2 {
            let start = Instant::now();
            assert_eq!(proactor.shutdown(), Err(UringError::Wait(libc::ETIMEDOUT)));
            assert!(start.elapsed() >= limit, "stall budget expired too early");
            if mode == ProactorMode::IoPoll {
                assert_eq!(proactor.stats().wait_calls, 0);
            } else {
                assert!(proactor.stats().wait_calls > 0);
            }
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "shutdown exceeded bounded stall"
            );
            assert_eq!(proactor.operation_count(), 1);
            assert_eq!(
                proactor.shutdown_cancel_issued,
                mode.supports_cancellation()
            );
            assert!(!proactor.cancel_armed);
            let resources = proactor
                .resources
                .as_ref()
                .ok_or(UringError::InvalidConfig("closed resources"))?;
            assert_eq!(
                resources
                    .buffers
                    .as_ref()
                    .ok_or(UringError::InvalidConfig("missing buffer"))?
                    .available(),
                0
            );
        }
        let operations = proactor
            .operations
            .as_mut()
            .ok_or(UringError::InvalidConfig("closed table"))?;
        assert_eq!(operations.state(key)?, OperationState::InFlight);
        assert!(operations.complete(key, -libc::ECANCELED, 0)?);
        // No SQE was published, so this injected terminal transition safely releases the token.
        operations.remove(key)?.release()?;
        proactor.shutdown()?;
        assert!(proactor.ring.is_none());
    }
    Ok(())
}

#[test]
fn iopoll_shutdown_resubmits_pending_sq() -> Result<()> {
    use crate::operation_slab::OperationKind;
    let mut proactor = Proactor::new(ProactorConfig {
        mode: ProactorMode::IoPoll,
        shutdown_stall_timeout: Some(Duration::from_millis(20)),
        ..Default::default()
    })?;
    let first = OperationId::pack(SubsystemId(1), crate::OperationPayload(1));
    proactor.alloc_sqe(first)?;
    proactor.submit()?;
    let operations = proactor
        .operations
        .as_mut()
        .ok_or(UringError::InvalidConfig("closed table"))?;
    let key = operations.insert(
        TrackedOperation {
            original: first,
            keyed: true,
            buffer: None,
            socket: None,
        },
        OperationKind::Single,
    )?;
    let deferred = OperationId::pack(SubsystemId(1), key.payload());
    operations.get_mut(key)?.original = deferred;
    let mut completed = 0;
    proactor.shutdown_with(
        &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.result, 0);
            if cqe.operation_id == first {
                // A retained target whose SQE appears after the initial enter models
                // an unconsumed SQ tail following a partial submission or backpressure.
                context.staged.push_back(StagedSqe {
                    sqe: RawSqe::from_entry(opcode::Nop::new().build().user_data(deferred.raw())),
                    key: Some(key),
                });
            } else {
                assert_eq!(cqe.operation_id, deferred);
            }
            completed += 1;
            Ok(())
        },
    )?;
    assert_eq!(completed, 2);
    assert!(proactor.is_idle());
    Ok(())
}
