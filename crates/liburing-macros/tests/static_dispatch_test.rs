//! Kernel-backed static dispatch contracts and shared worker ownership.

use std::time::{Duration, Instant};

use liburing::{OperationId, OperationPayload, Proactor, Result, SubsystemId, UringError};
use liburing_macros::define_subsystems;

define_subsystems! {
    enum Routes { Network = 1, Storage = 2, Timer = 3 }
}

#[derive(Default)]
struct Worker {
    counts: [usize; 3],
    failures: usize,
}

fn operation(route: u8, payload: u64) -> OperationId {
    OperationId::pack(
        SubsystemId::new_unchecked(route),
        OperationPayload::new_unchecked(payload),
    )
}

#[test]
fn integration_shared_worker_stages_each_subsystems_followup() -> Result<()> {
    let mut proactor = Proactor::builder()
        .entries(16)
        .staged_capacity(16)
        .build()?;
    let mut worker = Worker::default();
    for route in Routes::ALL {
        proactor.alloc_sqe(operation(route.id(), 0))?;
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut completed = 0;
    {
        let mut dispatcher = Routes::dispatcher(&mut worker, |route, state, completion, ctx| {
            assert_eq!(completion.result, 0);
            state.counts[usize::from(route.id() - 1)] += 1;
            completed += 1;
            if completion.operation_id.payload().raw() == 0 {
                ctx.prepare_sqe_with(operation(route.id(), 1), |sqe| {
                    // SAFETY: The callback exclusively borrows initialized SQE
                    // storage; NOP does not reference external resources.
                    unsafe { liburing::ops::prep_nop(sqe) };
                })?;
            }
            Ok(())
        });
        loop {
            proactor.wait_completions(1, Some(Duration::from_millis(10)), &mut dispatcher)?;
            if proactor.operation_count() == 0 {
                break;
            }
            if Instant::now() >= deadline {
                return Err(UringError::InvalidConfig("shared dispatch timed out"));
            }
        }
    }
    assert_eq!(completed, 6);
    assert_eq!(worker.counts, [2, 2, 2]);
    Ok(())
}

#[test]
fn lifecycle_unknown_route_is_consumed_once_then_dispatch_recovers() -> Result<()> {
    let mut proactor = Proactor::builder().entries(8).build()?;
    let mut worker = Worker::default();
    proactor.alloc_sqe(operation(255, 7))?;
    {
        let mut dispatcher = Routes::dispatcher(&mut worker, |route, state, _, _| {
            state.counts[usize::from(route.id() - 1)] += 1;
            Ok(())
        });
        assert_eq!(
            proactor.wait_completions(1, Some(Duration::from_secs(3)), &mut dispatcher),
            Err(UringError::InvalidSubsystemId(255))
        );
        assert_eq!(proactor.operation_count(), 0);
        assert_eq!(proactor.poll_completions(8, &mut dispatcher)?, 0);
        proactor.alloc_sqe(operation(Routes::Storage.id(), 8))?;
        assert_eq!(
            proactor.wait_completions(1, Some(Duration::from_secs(3)), &mut dispatcher)?,
            1
        );
    }
    assert_eq!(worker.counts, [0, 1, 0]);
    Ok(())
}

#[test]
fn scenario_callback_failure_retains_state_and_next_turn_works() -> Result<()> {
    let mut proactor = Proactor::builder().entries(8).build()?;
    let mut worker = Worker::default();
    {
        let mut dispatcher = Routes::dispatcher(&mut worker, |route, state, completion, _| {
            state.counts[usize::from(route.id() - 1)] += 1;
            if completion.operation_id.payload().raw() == 1 {
                state.failures += 1;
                return Err(UringError::InvalidConfig("worker rejected operation"));
            }
            Ok(())
        });
        proactor.alloc_sqe(operation(Routes::Network.id(), 1))?;
        assert_eq!(
            proactor.wait_completions(1, Some(Duration::from_secs(3)), &mut dispatcher),
            Err(UringError::InvalidConfig("worker rejected operation"))
        );
        assert_eq!(proactor.operation_count(), 0);
        proactor.alloc_sqe(operation(Routes::Timer.id(), 2))?;
        assert_eq!(
            proactor.wait_completions(1, Some(Duration::from_secs(3)), &mut dispatcher)?,
            1
        );
    }
    assert_eq!(worker.counts, [1, 0, 1]);
    assert_eq!(worker.failures, 1);
    Ok(())
}
