//! Integration checks for real kernel completion routing and control wakeups.
//!
//! Ring creation fails when io_uring is unavailable or forbidden; no simulated
//! ring or automatic kernel-test skip is used.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

use liburing::{
    Completion, CrossThreadCommandQueue, OpId, OpPayload, Proactor, ProactorConfig, ProactorWaker,
    Result, SubmissionContext, SubsystemHandler, SubsystemId, UringError,
    ops::{Timeout, prep_nop, wait_timeout},
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

static_assertions::assert_not_impl_any!(Proactor: Send, Sync);
static_assertions::assert_impl_all!(ProactorWaker: Send, Sync, Clone);
static_assertions::assert_impl_all!(CrossThreadCommandQueue<usize>: Send, Sync, Clone);

fn config(waker: bool) -> ProactorConfig {
    ProactorConfig {
        entries: 16,
        staged_capacity: 256,
        max_cqe_batch: 64,
        enable_waker: waker,
        ..ProactorConfig::default()
    }
}

fn op(subsystem: u8, payload: u64) -> OpId {
    OpId::pack(
        SubsystemId::new_unchecked(subsystem),
        OpPayload::new_unchecked(payload),
    )
}

#[test]
fn integration_scenario_nop_preserves_full_op_id() -> TestResult {
    let mut proactor = Proactor::new(config(false))?;
    let expected = op(254, OpPayload::MAX_RAW);
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
    assert_eq!(completion.op_id, expected);
    assert_eq!(completion.result, 0);
    assert_eq!(completion.op_id.unpack(), expected.unpack());
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_single_sqe_waker_cannot_strand_application_work() -> TestResult {
    let mut tiny = config(true);
    tiny.entries = 1;
    let mut proactor = Proactor::new(tiny)?;
    let waker = proactor.waker().ok_or("waker disabled")?;
    let expected = op(1, 7);
    proactor.alloc_sqe(expected)?;
    let mut observed = None;
    let deadline = Instant::now() + Duration::from_secs(2);
    while observed.is_none() && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, _| {
            observed = Some(cqe.op_id);
            Ok(())
        })?;
    }
    assert_eq!(observed, Some(expected));
    proactor.shutdown()?;
    assert!(proactor.ring_mut().is_null());
    assert!(proactor.submit().is_err());
    assert!(proactor.alloc_sqe(op(1, 8)).is_err());
    assert!(matches!(waker.wake(), Err(UringError::WakerClosed)));
    proactor.shutdown()?;
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_timeout_expires_and_idle_wait_is_finite() -> TestResult {
    let timeout = Timeout::new(Duration::from_millis(10))?;
    // The operand is declared first so unwinding also drops the ring before it.
    let mut proactor = Proactor::new(config(false))?;
    let expected = op(1, 17);
    proactor.prepare_sqe_with(expected, |sqe| {
        // SAFETY: SQE storage is exclusive; timeout remains alive until the
        // final CQE, and declaration order retains it through ring teardown.
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
    assert_eq!(observed.op_id, expected);
    assert_eq!(observed.result, -libc::ETIME);
    let started = Instant::now();
    let count = wait_timeout(&mut proactor, Duration::from_millis(10), |_, _| {
        Err(UringError::InvalidConfig("unexpected idle completion"))
    })?;
    assert_eq!(count, 0);
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

struct CountingHandler {
    id: SubsystemId,
    counts: Rc<RefCell<[usize; 3]>>,
    fanout: usize,
}

impl SubsystemHandler for CountingHandler {
    fn on_completion(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        assert_eq!(completion.op_id.subsystem_id(), self.id);
        assert_eq!(completion.result, 0);
        self.counts.borrow_mut()[usize::from(self.id.raw() - 1)] += 1;
        if completion.op_id.payload().raw() == 0 {
            for payload in 1..=self.fanout {
                submissions.prepare_sqe_with(op(self.id.raw(), payload as u64), |sqe| {
                    // SAFETY: The callback owns initialized, exclusive SQE storage.
                    unsafe { prep_nop(sqe) };
                })?;
            }
        }
        Ok(())
    }
}

#[test]
fn integration_scenario_three_subsystems_stage_more_than_sq_capacity() -> TestResult {
    let mut proactor = Proactor::new(config(false))?;
    let counts = Rc::new(RefCell::new([0; 3]));
    for id in 1..=3 {
        proactor.register_subsystem(
            SubsystemId::new_unchecked(id),
            CountingHandler {
                id: SubsystemId::new_unchecked(id),
                counts: Rc::clone(&counts),
                fanout: if id == 1 { 128 } else { 0 },
            },
        )?;
        proactor.alloc_sqe(op(id, 0))?;
    }
    let mut observed = BTreeSet::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while observed.len() < 131 && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, _| {
            assert!(observed.insert(cqe.op_id.raw()), "duplicate completion");
            Ok(())
        })?;
    }
    assert_eq!(observed.len(), 131);
    assert_eq!(*counts.borrow(), [129, 1, 1]);
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_command_queue_is_bounded_and_closes() -> TestResult {
    let waker = ProactorWaker::new()?;
    let queue = CrossThreadCommandQueue::new(2, waker.clone());
    queue.push(1)?;
    queue.push(2)?;
    assert!(matches!(queue.push(3), Err(UringError::CommandQueueFull)));
    assert_eq!(queue.pop()?, Some(1));
    assert_eq!(queue.pop()?, Some(2));
    assert_eq!(queue.pop()?, None);
    waker.drain()?;
    waker.close();
    assert!(matches!(queue.push(4), Err(UringError::WakerClosed)));
    assert!(queue.is_empty()?);
    assert!(matches!(waker.wake(), Err(UringError::WakerClosed)));
    Ok(())
}

#[test]
fn integration_scenario_four_threads_deliver_ten_thousand_unique_commands() -> TestResult {
    let waker = ProactorWaker::new()?;
    let queue = CrossThreadCommandQueue::new(10_000, waker.clone());
    let mut producers = Vec::new();
    for producer in 0..4 {
        let queue = queue.clone();
        producers.push(thread::spawn(move || -> Result<()> {
            for sequence in 0..2500 {
                queue.push(producer * 2500 + sequence)?;
            }
            Ok(())
        }));
    }
    for producer in producers {
        producer.join().map_err(|_| "command producer panicked")??;
    }
    let mut received = BTreeSet::new();
    while let Some(command) = queue.pop()? {
        assert!(received.insert(command), "duplicate command");
    }
    assert_eq!(received.len(), 10_000);
    assert_eq!(received.first(), Some(&0));
    assert_eq!(received.last(), Some(&9999));
    waker.drain()?;
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_cross_thread_waker_rearms_and_closes_on_drop() -> TestResult {
    let mut proactor = Proactor::new(config(true))?;
    let waker = proactor.waker().ok_or("waker disabled")?;
    for _ in 0..3 {
        let producer_waker = waker.clone();
        let producer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            producer_waker.wake()
        });
        let count = proactor.wait_completions(1, Some(Duration::from_secs(1)), |_, _| {
            Err(UringError::InvalidConfig("internal CQE reached observer"))
        })?;
        producer.join().map_err(|_| "wake producer panicked")??;
        assert!(
            count > 0,
            "wake did not complete before finite wait elapsed"
        );
    }
    drop(proactor);
    assert!(matches!(waker.wake(), Err(UringError::WakerClosed)));
    Ok(())
}

#[test]
fn integration_scenario_callback_error_preserves_staging_bound_and_consumes_cqe() -> TestResult {
    let mut small = config(false);
    small.staged_capacity = 2;
    let mut proactor = Proactor::new(small)?;
    proactor.alloc_sqe(op(1, 0))?;
    let result = proactor.wait_completions(1, Some(Duration::from_secs(1)), |cqe, context| {
        assert_eq!(cqe.op_id, op(1, 0));
        for payload in 1..=2 {
            context.prepare_sqe_with(op(1, payload), |sqe| {
                // SAFETY: The callback provides initialized, exclusive SQE storage.
                unsafe { prep_nop(sqe) };
            })?;
        }
        let rejected = context.prepare_sqe_with(op(1, 3), |_| {
            panic!("a full staging queue must reject before preparation")
        });
        assert!(matches!(rejected, Err(UringError::SqRingFull)));
        Err(UringError::InvalidConfig("observer stopped"))
    });
    assert!(matches!(
        result,
        Err(UringError::InvalidConfig("observer stopped"))
    ));
    let mut observed = BTreeSet::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while observed.len() < 2 && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, _| {
            assert!(observed.insert(cqe.op_id.payload().raw()));
            Ok(())
        })?;
    }
    assert_eq!(observed, BTreeSet::from([1, 2]));
    Ok(())
}

#[test]
fn integration_scenario_callback_panic_restores_dispatch_guard() -> TestResult {
    let mut proactor = Proactor::new(config(false))?;
    proactor.alloc_sqe(op(1, 0))?;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        proactor.wait_completions(1, Some(Duration::from_secs(1)), |_, context| {
            context.prepare_sqe_with(op(1, 1), |sqe| {
                // SAFETY: The callback provides initialized, exclusive SQE storage.
                unsafe { prep_nop(sqe) };
            })?;
            panic!("observer panic");
        })
    }));
    assert!(outcome.is_err());
    let mut observed = None;
    let deadline = Instant::now() + Duration::from_secs(3);
    while observed.is_none() && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, _| {
            observed = Some(cqe.op_id);
            Ok(())
        })?;
    }
    assert_eq!(observed, Some(op(1, 1)));
    Ok(())
}

#[test]
fn integration_scenario_kernel_wake_delivers_four_producers_ten_thousand_commands() -> TestResult {
    let mut proactor = Proactor::new(config(true))?;
    let queue = CrossThreadCommandQueue::new(10_000, proactor.waker().ok_or("waker disabled")?);
    let barrier = Arc::new(Barrier::new(5));
    let mut producers = Vec::new();
    for producer in 0..4 {
        let queue = queue.clone();
        let barrier = Arc::clone(&barrier);
        producers.push(thread::spawn(move || -> Result<()> {
            barrier.wait();
            for sequence in 0..2500 {
                queue.push(producer * 2500 + sequence)?;
            }
            Ok(())
        }));
    }
    proactor.submit()?;
    barrier.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = BTreeSet::new();
    while received.len() < 10_000 && Instant::now() < deadline {
        proactor.wait_completions(1, Some(Duration::from_millis(100)), |_, _| {
            Err(UringError::InvalidConfig("internal CQE reached observer"))
        })?;
        while let Some(command) = queue.pop()? {
            assert!(received.insert(command), "duplicate command");
        }
    }
    for producer in producers {
        producer.join().map_err(|_| "command producer panicked")??;
    }
    assert_eq!(received.len(), 10_000);
    assert_eq!(received.first(), Some(&0));
    assert_eq!(received.last(), Some(&9999));
    Ok(())
}

struct PendingReadOwner {
    fd: OwnedFd,
    buffer: Box<[u8; 1]>,
    drops: Rc<Cell<usize>>,
}

impl SubsystemHandler for PendingReadOwner {
    fn on_completion(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        assert_eq!(completion.result, -libc::ECANCELED);
        assert_eq!(completion.flags & liburing_sys::IORING_CQE_F_MORE, 0);
        assert_eq!(submissions.remaining_capacity(), 0);
        Ok(())
    }
}

impl Drop for PendingReadOwner {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn integration_lifecycle_scenario_drop_cancels_pending_handler_owned_pipe_read() -> TestResult {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors provides two writable integer slots; CLOEXEC is valid.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: pipe2 succeeded and returned two distinct fresh owned descriptors.
    let read_fd = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: The second fresh descriptor has not been adopted elsewhere.
    let _write_fd = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let drops = Rc::new(Cell::new(0));
    let mut owner = PendingReadOwner {
        fd: read_fd,
        buffer: Box::new([0]),
        drops: Rc::clone(&drops),
    };
    let fd = owner.fd.as_raw_fd();
    let buffer = owner.buffer.as_mut_ptr();
    let mut proactor = Proactor::new(config(false))?;
    proactor.register_subsystem(SubsystemId::new_unchecked(1), owner)?;
    proactor.prepare_sqe_with(op(1, 1), |sqe| {
        // SAFETY: The registered handler owns the descriptor and stable boxed
        // destination until ring teardown has retired the pending operation.
        unsafe { liburing_sys::uring_shim_prep_read(sqe, fd, buffer.cast(), 1, 0) };
    })?;
    proactor.submit()?;
    assert_eq!(drops.get(), 0);
    let started = Instant::now();
    drop(proactor);
    assert_eq!(drops.get(), 1);
    assert!(started.elapsed() < Duration::from_secs(3));
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_failed_shutdown_allows_only_drain_retries() -> TestResult {
    let mut bounded = config(true);
    bounded.entries = 64;
    bounded.cq_entries = Some(128);
    bounded.max_cqe_batch = 1;
    let mut proactor = Proactor::new(bounded)?;
    let counts = Rc::new(RefCell::new([0; 3]));
    proactor.register_subsystem(
        SubsystemId(1),
        CountingHandler {
            id: SubsystemId(1),
            counts: Rc::clone(&counts),
            fanout: 0,
        },
    )?;
    for payload in 0..64 {
        proactor.alloc_sqe(op(1, payload))?;
    }
    proactor.submit()?;
    // The one-CQE budget leaves completed operations pending after 33 drains.
    assert!(matches!(
        proactor.shutdown(),
        Err(UringError::Wait(libc::EBUSY))
    ));
    assert!(proactor.ring_mut().is_null());
    assert!(proactor.alloc_sqe(op(1, 65)).is_err());
    assert!(proactor.submit().is_err());
    assert!(proactor.tick().is_err());
    assert!(
        proactor
            .poll_completions(1, |_, _| panic!("dispatch during shutdown"))
            .is_err()
    );
    assert!(
        proactor
            .wait_completions(1, Some(Duration::ZERO), |_, _| {
                panic!("dispatch during shutdown")
            })
            .is_err()
    );
    assert!(
        proactor
            .register_subsystem(
                SubsystemId(2),
                CountingHandler {
                    id: SubsystemId(2),
                    counts: Rc::clone(&counts),
                    fanout: 0,
                },
            )
            .is_err()
    );
    let mut drained = false;
    for _ in 0..4 {
        match proactor.shutdown() {
            Ok(()) => {
                drained = true;
                break;
            }
            Err(UringError::Wait(libc::EBUSY)) => {}
            Err(error) => return Err(error.into()),
        }
    }
    assert!(
        drained,
        "bounded shutdown retries did not retire all operations"
    );
    assert_eq!(*counts.borrow(), [64, 0, 0]);
    proactor.shutdown()?;
    assert_eq!(
        *counts.borrow(),
        [64, 0, 0],
        "no duplicate shutdown delivery"
    );
    Ok(())
}

#[test]
fn integration_scenario_rejects_cqe_suppression_and_message_ring_in_both_paths() -> TestResult {
    let mut proactor = Proactor::new(config(false))?;
    for skip_completion in [false, true] {
        let rejected = proactor.prepare_sqe_with(op(1, 1), |sqe| {
            // SAFETY: The callback owns initialized exclusive SQE storage.
            unsafe {
                if skip_completion {
                    (*sqe).flags = liburing_sys::IOSQE_CQE_SKIP_SUCCESS as u8;
                } else {
                    (*sqe).opcode = liburing_sys::IORING_OP_MSG_RING as u8;
                }
            }
        });
        assert!(matches!(rejected, Err(UringError::InvalidConfig(_))));
    }
    proactor.alloc_sqe(op(1, 2))?;
    let mut observed = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while observed.len() < 2 && Instant::now() < deadline {
        wait_timeout(&mut proactor, Duration::from_millis(100), |cqe, context| {
            observed.push(cqe.op_id);
            if cqe.op_id == op(1, 2) {
                let available = context.remaining_capacity();
                for skip_completion in [false, true] {
                    let rejected = context.prepare_sqe_with(op(1, 3), |sqe| {
                        // SAFETY: The callback owns initialized exclusive SQE storage.
                        unsafe {
                            if skip_completion {
                                (*sqe).flags = liburing_sys::IOSQE_CQE_SKIP_SUCCESS as u8;
                            } else {
                                (*sqe).opcode = liburing_sys::IORING_OP_MSG_RING as u8;
                            }
                        }
                    });
                    assert!(matches!(rejected, Err(UringError::InvalidConfig(_))));
                    assert_eq!(context.remaining_capacity(), available);
                }
                context.prepare_sqe_with(op(1, 4), |sqe| {
                    // SAFETY: The callback owns initialized exclusive SQE storage.
                    unsafe { prep_nop(sqe) };
                })?;
            }
            Ok(())
        })?;
    }
    assert_eq!(observed, vec![op(1, 2), op(1, 4)]);
    proactor.shutdown()?;
    Ok(())
}
