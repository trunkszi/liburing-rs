//! Caller-owned completion dispatch, bounded staging, and thread-local lifecycle.

use std::{
    collections::BTreeSet,
    panic::{AssertUnwindSafe, catch_unwind},
    time::{Duration, Instant},
};

use liburing::{
    Completion, CompletionDispatcher, OperationId, OperationPayload, Proactor, ProactorConfig,
    Result, SubmissionContext, SubsystemId, UringError,
    ops::{Timeout, prep_nop, wait_timeout},
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

static_assertions::assert_not_impl_any!(Proactor: Send, Sync);

fn config() -> ProactorConfig {
    ProactorConfig {
        entries: 16,
        staged_capacity: 256,
        max_cqe_batch: 64,
        ..ProactorConfig::default()
    }
}

fn operation(subsystem: u8, payload: u64) -> OperationId {
    OperationId::pack(
        SubsystemId::new_unchecked(subsystem),
        OperationPayload::new_unchecked(payload),
    )
}

#[test]
fn integration_scenario_nop_preserves_full_operation_id() -> TestResult {
    let mut proactor = Proactor::new(config())?;
    let expected = operation(254, OperationPayload::MAX_RAW);
    proactor.prepare_sqe_with(expected, |sqe| {
        // SAFETY: The callback provides initialized, exclusive SQE storage.
        unsafe { prep_nop(sqe) };
    })?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut completion = None;
    while completion.is_none() && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, _| {
            completion = Some(cqe);
            Ok(())
        })?;
    }
    let completion = completion.ok_or("NOP deadline elapsed")?;
    assert_eq!(completion.operation_id, expected);
    assert_eq!(completion.result, 0);
    assert_eq!(completion.operation_id.unpack(), expected.unpack());
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_single_sqe_ring_cannot_strand_application_work() -> TestResult {
    let mut tiny = config();
    tiny.entries = 1;
    let mut proactor = Proactor::new(tiny)?;
    let expected = operation(1, 7);
    proactor.alloc_sqe(expected)?;
    let mut observed = None;
    let deadline = Instant::now() + Duration::from_secs(2);
    while observed.is_none() && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, _| {
            observed = Some(cqe.operation_id);
            Ok(())
        })?;
    }
    assert_eq!(observed, Some(expected));
    proactor.shutdown()?;
    assert!(proactor.ring_mut().is_null());
    assert!(proactor.submit().is_err());
    assert!(proactor.alloc_sqe(operation(1, 8)).is_err());
    proactor.shutdown()?;
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_timeout_expires_and_idle_wait_is_finite() -> TestResult {
    let timeout = Timeout::new(Duration::from_millis(10))?;
    let mut proactor = Proactor::new(config())?;
    let expected = operation(1, 17);
    proactor.prepare_sqe_with(expected, |sqe| {
        // SAFETY: The timeout owner was declared before the ring and remains
        // alive through final completion and every early ring teardown path.
        unsafe { timeout.prepare(sqe) };
    })?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut observed = None;
    while observed.is_none() && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, _| {
            observed = Some(cqe);
            Ok(())
        })?;
    }
    let observed = observed.ok_or("timeout CQE deadline elapsed")?;
    assert_eq!(observed.operation_id, expected);
    assert_eq!(observed.result, -libc::ETIME);
    let started = Instant::now();
    assert_eq!(
        wait_timeout(&mut proactor, Duration::from_millis(10), |_, _| {
            Err(UringError::InvalidConfig("unexpected idle completion"))
        })?,
        0
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

struct WorkerState {
    counts: [usize; 3],
    observed: BTreeSet<u64>,
}

struct WorkerDispatcher<'a>(&'a mut WorkerState);

impl CompletionDispatcher for WorkerDispatcher<'_> {
    fn dispatch(
        &mut self,
        completion: Completion,
        context: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        let route = completion.operation_id.subsystem_id().raw();
        assert!((1..=3).contains(&route));
        assert_eq!(completion.result, 0);
        self.0.counts[usize::from(route - 1)] += 1;
        assert!(
            self.0.observed.insert(completion.operation_id.raw()),
            "duplicate CQE"
        );
        if route == 1 && completion.operation_id.payload().raw() == 0 {
            for payload in 1..=128 {
                context.prepare_sqe_with(operation(route, payload), |sqe| {
                    // SAFETY: The callback owns initialized exclusive SQE storage.
                    unsafe { prep_nop(sqe) };
                })?;
            }
        }
        Ok(())
    }
}

#[test]
fn integration_scenario_three_subsystems_share_borrowed_worker_and_overfill_kernel_sq() -> TestResult
{
    let mut proactor = Proactor::new(config())?;
    let mut worker = WorkerState {
        counts: [0; 3],
        observed: BTreeSet::new(),
    };
    for route in 1..=3 {
        proactor.alloc_sqe(operation(route, 0))?;
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while worker.observed.len() < 131 && Instant::now() < deadline {
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(100)),
            &mut WorkerDispatcher(&mut worker),
        )?;
    }
    assert_eq!(worker.observed.len(), 131);
    assert_eq!(worker.counts, [129, 1, 1]);
    assert_eq!(proactor.operation_count(), 0);
    proactor.shutdown()?;
    assert_eq!(worker.counts, [129, 1, 1]);
    Ok(())
}

#[test]
fn integration_scenario_callback_error_preserves_staging_bound_and_consumes_cqe() -> TestResult {
    let mut small = config();
    small.staged_capacity = 2;
    let mut proactor = Proactor::new(small)?;
    proactor.alloc_sqe(operation(1, 0))?;
    let result = wait_timeout(&mut proactor, Duration::from_secs(1), |cqe, context| {
        assert_eq!(cqe.operation_id, operation(1, 0));
        for payload in 1..=2 {
            context.prepare_sqe_with(operation(1, payload), |sqe| {
                // SAFETY: The callback provides initialized exclusive SQE storage.
                unsafe { prep_nop(sqe) };
            })?;
        }
        assert!(matches!(
            context.prepare_sqe_with(operation(1, 3), |_| {
                panic!("a full queue must reject before preparation")
            }),
            Err(UringError::SqRingFull)
        ));
        Err(UringError::InvalidConfig("observer stopped"))
    });
    assert_eq!(result, Err(UringError::InvalidConfig("observer stopped")));
    let mut observed = BTreeSet::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while observed.len() < 2 && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, _| {
            assert!(observed.insert(cqe.operation_id.payload().raw()));
            Ok(())
        })?;
    }
    assert_eq!(observed, BTreeSet::from([1, 2]));
    Ok(())
}

#[test]
fn integration_scenario_callback_panic_acknowledges_batch_and_restores_dispatch() -> TestResult {
    let mut proactor = Proactor::new(config())?;
    proactor.alloc_sqe(operation(1, 0))?;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        wait_timeout(&mut proactor, Duration::from_secs(1), |_, context| {
            context.prepare_sqe_with(operation(1, 1), |sqe| {
                // SAFETY: The callback provides initialized exclusive SQE storage.
                unsafe { prep_nop(sqe) };
            })?;
            panic!("observer panic");
        })
    }));
    assert!(outcome.is_err());
    let mut observed = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while observed.is_empty() && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, _| {
            observed.push(cqe.operation_id);
            Ok(())
        })?;
    }
    assert_eq!(observed, [operation(1, 1)]);
    assert_eq!(proactor.operation_count(), 0);
    Ok(())
}

#[test]
fn lifecycle_shutdown_error_preserves_remaining_callbacks_for_retry() -> TestResult {
    let mut proactor = Proactor::new(config())?;
    for payload in 0..4 {
        proactor.alloc_sqe(operation(1, payload))?;
    }
    proactor.submit()?;
    let mut observed = BTreeSet::new();
    let error = proactor.shutdown_with(&mut |cqe: Completion, ctx: &mut SubmissionContext<'_>| {
        assert_eq!(ctx.remaining_capacity(), 0);
        assert!(observed.insert(cqe.operation_id.raw()));
        Err(UringError::InvalidConfig("teardown observer stopped"))
    });
    assert_eq!(
        error,
        Err(UringError::InvalidConfig("teardown observer stopped"))
    );
    assert!(proactor.alloc_sqe(operation(1, 9)).is_err());
    proactor.shutdown_with(&mut |cqe: Completion, ctx: &mut SubmissionContext<'_>| {
        assert_eq!(ctx.remaining_capacity(), 0);
        assert!(observed.insert(cqe.operation_id.raw()));
        Ok(())
    })?;
    assert_eq!(observed.len(), 4);
    proactor.shutdown()?;
    Ok(())
}
