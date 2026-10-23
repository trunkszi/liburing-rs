//! Real-ring submission, overflow, and shutdown progress regressions.

use std::time::{Duration, Instant};

use liburing::{
    Completion, OperationId, OperationPayload, Proactor, ProactorConfig, Result, SubmissionContext,
    SubsystemId,
};

fn identity(value: u64) -> OperationId {
    OperationId::pack(SubsystemId(1), OperationPayload(value))
}

#[test]
fn single_submit_drains_forty_operations_on_a_sixteen_entry_ring() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 16,
        staged_capacity: 64,
        operation_capacity: 64,
        ..ProactorConfig::default()
    })?;
    for value in 0..40 {
        ring.alloc_sqe(identity(value))?;
    }
    let submitted = ring.submit()?;
    assert!(
        submitted >= 40,
        "one submit must publish every accepted application SQE"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut application = 0;
    while application < 40 {
        assert!(Instant::now() < deadline, "application CQEs did not arrive");
        ring.poll_completions(64, &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.result, 0);
            application += 1;
            Ok(())
        })?;
    }
    assert_eq!(application, 40);
    ring.shutdown()
}

#[test]
fn shutdown_drains_ready_operations_beyond_thirty_two_single_cqe_batches() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 64,
        staged_capacity: 64,
        operation_capacity: 64,
        max_cqe_batch: 1,
        ..ProactorConfig::default()
    })?;
    for value in 0..48 {
        ring.alloc_sqe(identity(value))?;
    }
    ring.submit()?;
    let mut completed = 0;
    ring.shutdown_with(&mut |_: Completion, _: &mut SubmissionContext<'_>| {
        completed += 1;
        Ok(())
    })?;
    assert_eq!(completed, 48);
    assert!(ring.is_idle());
    assert!(ring.ring_mut().is_null());
    Ok(())
}

#[test]
fn poll_flushes_overflow_without_deferred_task_work() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 2,
        cq_entries: Some(2),
        staged_capacity: 4,
        operation_capacity: 4,
        enable_optimizations: false,
        ..ProactorConfig::default()
    })?;
    for batch in 0..2 {
        for value in 0..2 {
            ring.alloc_sqe(identity(batch * 2 + value))?;
        }
        ring.submit()?;
    }
    // SAFETY: This thread exclusively owns the live ring. The queue borrow ends
    // before the proactor polls or mutates it again; no entries are published.
    assert!(unsafe { &mut *ring.ring_mut() }.submission().cq_overflow());
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut completed = 0;
    while completed < 4 {
        assert!(
            Instant::now() < deadline,
            "overflow CQEs remained stranded in the kernel"
        );
        ring.poll_completions(4, &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.result, 0);
            completed += 1;
            Ok(())
        })?;
    }
    assert!(ring.is_idle());
    Ok(())
}
