//! Real-ring mode negotiation, publication, wakeup, and bounded-progress scenarios.

use std::{
    mem::ManuallyDrop,
    num::NonZeroU32,
    time::{Duration, Instant},
};

use liburing::{
    Completion, EventDrivenConfig, OperationId, OperationPayload, Proactor, ProactorConfig,
    ProactorMode, Result, SqPollConfig, SubmissionContext, SubsystemId, UringError, backend,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct Affinity {
    original: Vec<usize>,
}

impl Affinity {
    fn capture() -> TestResultValue<Self> {
        let mut original = vec![0usize; 16];
        loop {
            // SAFETY: The aligned initialized mask spans the given writable extent;
            // pid zero reads this test thread and no pointer escapes the call.
            if unsafe {
                libc::sched_getaffinity(
                    0,
                    std::mem::size_of_val(original.as_slice()),
                    original.as_mut_ptr().cast(),
                )
            } == 0
            {
                return Ok(Self { original });
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) || original.len() >= 1 << 14 {
                return Err(error.into());
            }
            original.resize(original.len() * 2, 0);
        }
    }

    fn cpus(&self) -> Vec<u32> {
        self.original
            .iter()
            .enumerate()
            .flat_map(|(index, word)| {
                (0..usize::BITS).filter_map(move |bit| {
                    (word & (1usize << bit) != 0)
                        .then_some((index * usize::BITS as usize + bit as usize) as u32)
                })
            })
            .collect()
    }

    fn pin(&self, cpu: u32) -> TestResult {
        let mut mask = vec![0usize; self.original.len()];
        mask[cpu as usize / usize::BITS as usize] = 1usize << (cpu % usize::BITS);
        // SAFETY: The initialized word-aligned mask remains readable for its full
        // extent, and only this calling test thread's scheduling mask is changed.
        if unsafe {
            libc::sched_setaffinity(
                0,
                std::mem::size_of_val(mask.as_slice()),
                mask.as_ptr().cast(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

impl Drop for Affinity {
    fn drop(&mut self) {
        // SAFETY: The captured initialized mask remains readable for its full
        // extent. Restore only the calling thread modified by this guard.
        let restored = unsafe {
            libc::sched_setaffinity(
                0,
                std::mem::size_of_val(self.original.as_slice()),
                self.original.as_ptr().cast(),
            )
        };
        assert_eq!(restored, 0, "test affinity restoration failed");
    }
}

type TestResultValue<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn pin_pair() -> TestResultValue<(Affinity, u32, u32)> {
    let guard = Affinity::capture()?;
    let cpus = guard.cpus();
    if cpus.len() < 2 {
        return Err("SQPOLL qualification requires two allowed CPUs".into());
    }
    guard.pin(cpus[0])?;
    Ok((guard, cpus[0], cpus[1]))
}

fn identity(value: u64) -> OperationId {
    OperationId::pack(SubsystemId(1), OperationPayload(value))
}

fn ring(mode: ProactorMode) -> Result<Proactor> {
    Proactor::new(ProactorConfig {
        mode,
        entries: 8,
        cq_entries: Some(16),
        staged_capacity: 64,
        operation_capacity: 64,
        max_cqe_batch: 16,
        ..ProactorConfig::default()
    })
}

fn drain(proactor: &mut Proactor, count: usize) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut completed = 0;
    while completed < count {
        assert!(Instant::now() < deadline, "completion progress timed out");
        proactor.tick(&mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.result, 0);
            completed += 1;
            Ok(())
        })?;
        core::hint::spin_loop();
    }
    assert!(proactor.is_idle());
    Ok(())
}

fn sq_flags(proactor: &mut Proactor) -> (bool, bool, bool) {
    // SAFETY: The live ring is exclusively borrowed on its owner thread; the SQ
    // view is discarded before any proactor method runs. No SQE is mutated.
    let raw = unsafe { &mut *proactor.ring_mut() };
    let sq = ManuallyDrop::new(raw.submission());
    (sq.is_empty(), sq.cq_overflow(), sq.need_wakeup())
}

#[test]
fn four_modes_negotiate_and_complete() -> TestResult {
    let (_guard, _, sq_cpu) = pin_pair()?;
    for mode in [
        ProactorMode::event_driven(),
        ProactorMode::sq_poll(sq_cpu),
        ProactorMode::io_poll(),
        ProactorMode::sq_poll_io_poll(sq_cpu),
    ] {
        let mut proactor = ring(mode)?;
        let features = proactor.kernel_features();
        assert_eq!(features.sq_poll(), mode.uses_sq_thread());
        assert_eq!(features.io_poll(), mode.uses_iopoll());
        assert_ne!(features.features & (1 << 1), 0, "NODROP required");
        assert_ne!(features.features & (1 << 8), 0, "EXT_ARG required");
        if mode.uses_sq_thread() {
            assert!(features.single_issuer());
            assert_eq!(
                features.setup_flags
                    & (backend::IORING_SETUP_COOP_TASKRUN
                        | backend::IORING_SETUP_DEFER_TASKRUN
                        | backend::IORING_SETUP_TASKRUN_FLAG),
                0
            );
        }
        proactor.alloc_sqe(identity(1))?;
        drain(&mut proactor, 1)?;
        proactor.shutdown()?;
    }
    Ok(())
}

#[test]
fn idle_ticks_issue_no_kernel_entries() -> TestResult {
    let (_guard, _, sq_cpu) = pin_pair()?;
    for mode in [
        ProactorMode::event_driven(),
        ProactorMode::sq_poll(sq_cpu),
        ProactorMode::io_poll(),
        ProactorMode::sq_poll_io_poll(sq_cpu),
    ] {
        let mut proactor = ring(mode)?;
        for _ in 0..1000 {
            assert_eq!(
                proactor.tick(&mut |_: Completion, _: &mut SubmissionContext<'_>| Ok(()))?,
                0
            );
        }
        assert_eq!(proactor.stats().enter_calls, 0, "idle mode {}", mode.name());
    }
    Ok(())
}

#[test]
fn sole_owner_cpu_conflict_is_rejected() -> TestResult {
    let (guard, owner, _) = pin_pair()?;
    for mode in [
        ProactorMode::sq_poll(owner),
        ProactorMode::sq_poll_io_poll(owner),
    ] {
        let result = ring(mode);
        assert!(matches!(
            result,
            Err(UringError::InvalidConfig(
                "sq thread cpu cannot share the owner's sole cpu"
            ))
        ));
    }
    drop(guard);
    Ok(())
}

#[test]
fn managed_flags_and_disabled_polling_fail() {
    for flags in [
        backend::IORING_SETUP_SQPOLL,
        backend::IORING_SETUP_SQ_AFF,
        backend::IORING_SETUP_IOPOLL,
        backend::IORING_SETUP_SINGLE_ISSUER,
        backend::IORING_SETUP_COOP_TASKRUN,
        backend::IORING_SETUP_TASKRUN_FLAG,
        backend::IORING_SETUP_DEFER_TASKRUN,
    ] {
        assert!(
            Proactor::builder()
                .setup_flags(flags)
                .build_config()
                .is_err()
        );
    }
    assert!(
        Proactor::builder()
            .io_poll()
            .enable_optimizations(false)
            .build_config()
            .is_err()
    );
}

#[test]
fn event_wait_fuses_submission_and_wait() -> TestResult {
    let mut proactor = Proactor::builder()
        .event_driven(EventDrivenConfig {
            no_iowait: true,
            batch_wait_usec: Some(NonZeroU32::MIN),
        })
        .build()?;
    proactor.alloc_sqe(identity(1))?;
    let mut completed = 0;
    assert_eq!(
        proactor.wait_completions(
            1,
            Some(Duration::from_secs(1)),
            &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
                assert_eq!(cqe.result, 0);
                completed += 1;
                Ok(())
            }
        )?,
        1
    );
    assert_eq!(completed, 1);
    assert_eq!(proactor.stats().enter_calls, 1);
    assert_eq!(proactor.stats().wait_calls, 1);
    Ok(())
}

#[test]
fn polling_wait_rejects_before_side_effects() -> TestResult {
    let (_guard, _, sq_cpu) = pin_pair()?;
    for mode in [
        ProactorMode::sq_poll(sq_cpu),
        ProactorMode::io_poll(),
        ProactorMode::sq_poll_io_poll(sq_cpu),
    ] {
        let mut proactor = ring(mode)?;
        proactor.alloc_sqe(identity(1))?;
        let capacity = proactor.remaining_capacity();
        let mut calls = 0;
        for (minimum, timeout) in [(1, None), (0, Some(Duration::ZERO))] {
            let result =
                proactor.wait_completions(minimum, timeout, &mut |_: Completion,
                                                                  _: &mut SubmissionContext<
                    '_,
                >| {
                    calls += 1;
                    Ok(())
                });
            assert_eq!(
                result,
                Err(UringError::BlockingWaitUnavailable { mode: mode.name() })
            );
            assert_eq!(calls, 0);
            assert_eq!(proactor.stats().enter_calls, 0);
            assert_eq!(proactor.remaining_capacity(), capacity);
        }
        let _ = proactor.wait_completions(
            0,
            None,
            &mut |_: Completion, _: &mut SubmissionContext<'_>| {
                calls += 1;
                Ok(())
            },
        )?;
        if calls == 0 {
            drain(&mut proactor, 1)?;
        }
        assert!(proactor.is_idle());
    }
    Ok(())
}

#[test]
fn warm_sqpoll_roundtrips_without_enter() -> TestResult {
    let (_guard, _, sq_cpu) = pin_pair()?;
    let mut proactor = ring(ProactorMode::sq_poll(sq_cpu))?;
    proactor.alloc_sqe(identity(0))?;
    drain(&mut proactor, 1)?;
    let before = proactor.stats().enter_calls;
    for value in 1..33 {
        proactor.alloc_sqe(identity(value))?;
        drain(&mut proactor, 1)?;
    }
    assert_eq!(proactor.stats().enter_calls, before);
    Ok(())
}

#[test]
fn sleeping_sqpoll_wakes_for_publication() -> TestResult {
    let (_guard, _, sq_cpu) = pin_pair()?;
    let config = SqPollConfig::pinned(sq_cpu).with_idle_ms(NonZeroU32::MIN);
    let mut proactor = ring(ProactorMode::SqPoll(config))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while !sq_flags(&mut proactor).2 {
        assert!(Instant::now() < deadline, "SQ thread never slept");
        core::hint::spin_loop();
    }
    let before = proactor.stats().sq_wakeups;
    proactor.alloc_sqe(identity(1))?;
    drain(&mut proactor, 1)?;
    assert!(proactor.stats().sq_wakeups > before);
    Ok(())
}

#[test]
fn submit_wakes_sqpoll_for_raw_sqe() -> TestResult {
    let (_guard, _, sq_cpu) = pin_pair()?;
    let config = SqPollConfig::pinned(sq_cpu).with_idle_ms(NonZeroU32::MIN);
    let mut proactor = ring(ProactorMode::SqPoll(config))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while !matches!(sq_flags(&mut proactor), (true, _, true)) {
        assert!(
            Instant::now() < deadline,
            "SQ thread never slept before raw push"
        );
        core::hint::spin_loop();
    }
    let wakes_before = proactor.stats().sq_wakeups;
    let entry = io_uring::opcode::Nop::new().build().user_data(0);
    {
        // SAFETY: This owner thread exclusively borrows the live ring while no
        // dispatch or preparation is active; the borrow ends before submit.
        let raw = unsafe { &mut *proactor.ring_mut() };
        let mut sq = ManuallyDrop::new(raw.submission());
        // SAFETY: NOP has no borrowed operands. Its initialized entry is copied
        // into exclusive SQ storage; subsystem zero never reaches user dispatch.
        unsafe { sq.push(&entry) }.map_err(|_| "raw SQ unexpectedly full")?;
        sq.sync();
    }
    assert_eq!(
        proactor.submit()?,
        0,
        "raw publication must leave staging empty"
    );
    assert_eq!(proactor.stats().sq_wakeups, wakes_before + 1);

    let mut callbacks = 0;
    let mut harvested = 0;
    while harvested == 0 {
        assert!(Instant::now() < deadline, "raw SQE completion was stranded");
        harvested +=
            proactor.poll_completions(8, &mut |_: Completion, _: &mut SubmissionContext<'_>| {
                callbacks += 1;
                Ok(())
            })?;
        core::hint::spin_loop();
    }
    assert_eq!(harvested, 1);
    assert_eq!(callbacks, 0);
    assert!(proactor.is_idle());
    Ok(())
}

#[test]
fn polling_publishes_callback_followups() -> TestResult {
    let (_guard, _, sq_cpu) = pin_pair()?;
    let config = SqPollConfig::pinned(sq_cpu).with_idle_ms(NonZeroU32::MIN);
    let mut proactor = ring(ProactorMode::SqPoll(config))?;
    proactor.alloc_sqe(identity(1))?;
    proactor.submit()?;
    let sleeping_deadline = Instant::now() + Duration::from_secs(3);
    while !matches!(sq_flags(&mut proactor), (true, _, true)) {
        assert!(
            Instant::now() < sleeping_deadline,
            "SQ thread never slept before callback"
        );
        core::hint::spin_loop();
    }
    let wakes_before = proactor.stats().sq_wakeups;
    let mut completed = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    while completed < 2 {
        assert!(Instant::now() < deadline, "callback SQE was stranded");
        proactor.poll_completions(
            8,
            &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                assert_eq!(cqe.result, 0);
                completed += 1;
                if cqe.operation_id == identity(1) {
                    context.prepare_sqe_with(identity(2), |sqe| {
                        // SAFETY: The preparation callback owns initialized SQE storage;
                        // NOP has no borrowed operands and its identity is rewritten.
                        unsafe { liburing::ops::prep_nop(sqe) };
                    })?;
                }
                Ok(())
            },
        )?;
    }
    assert!(proactor.is_idle());
    assert!(proactor.stats().sq_wakeups > wakes_before);
    Ok(())
}

#[test]
fn sqpoll_overflow_flushes_without_submission() -> TestResult {
    let (_guard, _, sq_cpu) = pin_pair()?;
    let mut proactor = Proactor::new(ProactorConfig {
        mode: ProactorMode::sq_poll(sq_cpu),
        entries: 2,
        cq_entries: Some(2),
        ..ProactorConfig::default()
    })?;
    for value in 0..4 {
        proactor.alloc_sqe(identity(value))?;
        proactor.submit()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while !sq_flags(&mut proactor).0 {
            assert!(Instant::now() < deadline, "SQ thread did not consume SQEs");
            core::hint::spin_loop();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while !sq_flags(&mut proactor).1 {
        assert!(Instant::now() < deadline, "CQ overflow was not observed");
        core::hint::spin_loop();
    }
    drain(&mut proactor, 4)?;
    assert!(proactor.stats().cq_overflow_flushes != 0);
    Ok(())
}

#[test]
fn full_sq_submit_remains_bounded() -> TestResult {
    let (_guard, _, sq_cpu) = pin_pair()?;
    let mut proactor = Proactor::new(ProactorConfig {
        mode: ProactorMode::sq_poll(sq_cpu),
        entries: 2,
        cq_entries: Some(64),
        staged_capacity: 64,
        operation_capacity: 64,
        ..ProactorConfig::default()
    })?;
    for value in 0..40 {
        proactor.prepare_sqe_with(identity(value), |sqe| {
            // SAFETY: The preparation callback owns initialized SQE storage;
            // NOP has no borrowed operands and its identity is rewritten.
            unsafe { liburing::ops::prep_nop(sqe) };
        })?;
    }
    let started = Instant::now();
    let mut published = proactor.submit()?;
    assert!(published <= 4, "submit exceeded the bounded SQ snapshot");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "submit spun on a full SQ"
    );
    assert!(proactor.stats().sq_full_events >= 1);

    // Finish explicit publication before harvesting: tick and poll can publish
    // remaining staging themselves, which would hide entries from this return sum.
    // The CQ fits all forty completions, so publication needs no CQ-space recovery.
    let deadline = Instant::now() + Duration::from_secs(3);
    while published < 40 {
        assert!(Instant::now() < deadline, "SQ publication did not progress");
        let count = proactor.submit()?;
        assert!(count <= 4, "submit exceeded the bounded SQ snapshot");
        published += count;
        core::hint::spin_loop();
    }
    let mut seen = [false; 40];
    let mut completed = 0;
    while completed < 40 {
        assert!(Instant::now() < deadline, "completions did not drain");
        published += proactor.submit()?;
        proactor.tick(&mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.result, 0);
            let index = (cqe.operation_id.raw() & ((1u64 << 56) - 1)) as usize;
            assert!(index < seen.len(), "unexpected completion identity");
            assert!(!seen[index], "duplicate completion identity");
            seen[index] = true;
            completed += 1;
            Ok(())
        })?;
        core::hint::spin_loop();
    }
    assert_eq!(published, 40, "publication returns counted entries twice");
    assert!(seen.into_iter().all(|completed| completed));
    assert!(proactor.is_idle());
    Ok(())
}

#[test]
fn iopoll_submission_polls_once() -> TestResult {
    let mut proactor = ring(ProactorMode::IoPoll)?;
    proactor.alloc_sqe(identity(1))?;
    assert_eq!(proactor.submit()?, 1);
    assert_eq!(proactor.stats().enter_calls, 1);
    let before = proactor.stats().enter_calls;
    let mut completed = 0;
    proactor.poll_completions(8, &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
        assert_eq!(cqe.result, 0);
        completed += 1;
        Ok(())
    })?;
    assert_eq!(completed, 1);
    assert_eq!(proactor.stats().enter_calls, before);
    assert!(proactor.is_idle());
    Ok(())
}

#[test]
fn ready_cqe_preserves_wait_minimum() -> TestResult {
    let mut proactor = ring(ProactorMode::event_driven())?;
    proactor.alloc_sqe(identity(1))?;
    proactor.submit()?;
    let before = proactor.stats().wait_calls;
    let mut completed = 0;
    proactor.wait_completions(
        2,
        Some(Duration::from_millis(5)),
        &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.result, 0);
            completed += 1;
            Ok(())
        },
    )?;
    assert_eq!(completed, 1);
    assert_eq!(proactor.stats().wait_calls, before + 1);
    assert!(proactor.is_idle());
    Ok(())
}
