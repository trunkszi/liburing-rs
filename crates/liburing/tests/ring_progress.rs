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
fn staged_nop_submits_with_one_enter() -> Result<()> {
    let mut ring = ProactorConfig::builder().build()?;
    let id = identity(42);
    ring.prepare_sqe_with(id, |sqe| {
        // SAFETY: The preparation callback exclusively owns initialized SQE storage.
        unsafe { liburing::ops::prep_nop(sqe) };
    })?;
    assert_eq!(ring.submit()?, 1);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut completed = 0;
    while completed == 0 {
        assert!(Instant::now() < deadline, "optimized NOP did not complete");
        ring.poll_completions(1, &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.operation_id, id);
            assert_eq!(cqe.result, 0);
            completed += 1;
            Ok(())
        })?;
    }
    assert_eq!(completed, 1);
    assert_eq!(ring.stats().enter_calls, 1);
    assert!(ring.is_idle());
    ring.shutdown()
}

#[test]
fn submits_forty_with_small_ring() -> Result<()> {
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
fn shutdown_drains_all_ready_batches() -> Result<()> {
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
fn poll_flushes_overflow_without_taskwork() -> Result<()> {
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

#[test]
fn futex_preparation_preserves_metadata() {
    use liburing::{FUTEX_BITSET_MATCH_ANY, FUTEX2_PRIVATE, FUTEX2_SIZE_U32, FutexWaitV};
    let word = std::sync::atomic::AtomicU32::new(0);
    let flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
    let mut sqe = liburing::backend::RawSqe {
        user_data: 0x1234_5678_9abc_def0,
        flags: 0x14,
        personality: 7,
        ..Default::default()
    };
    // SAFETY: Exclusive initialized SQE and aligned live atomic; these entries are never published.
    unsafe {
        liburing::prep_futex_wait(
            &mut sqe,
            word.as_ptr(),
            1 << 40,
            FUTEX_BITSET_MATCH_ANY,
            flags,
        )
    };
    assert_eq!(sqe.opcode, io_uring::opcode::FutexWait::CODE);
    assert_eq!(
        (sqe.fd, sqe.addr, sqe.off, sqe.addr3),
        (
            flags as i32,
            word.as_ptr() as u64,
            1 << 40,
            FUTEX_BITSET_MATCH_ANY
        )
    );
    assert_eq!(
        (sqe.user_data, sqe.flags, sqe.personality),
        (0x1234_5678_9abc_def0, 0x14, 7)
    );
    // SAFETY: The same exclusive SQE and aligned live word remain unpublished.
    unsafe { liburing::prep_futex_wake(&mut sqe, word.as_ptr(), 1 << 33, 3, flags) };
    assert_eq!(sqe.opcode, io_uring::opcode::FutexWake::CODE);
    assert_eq!(
        (sqe.fd, sqe.addr, sqe.off, sqe.addr3),
        (flags as i32, word.as_ptr() as u64, 1 << 33, 3)
    );
    assert_eq!(
        (sqe.user_data, sqe.flags, sqe.personality),
        (0x1234_5678_9abc_def0, 0x14, 7)
    );
    let waiters = [FutexWaitV::new()
        .uaddr(word.as_ptr() as u64)
        .val(0)
        .flags(flags); 2];
    // SAFETY: Exclusive SQE and initialized immutable vector stay live; no entry is published.
    unsafe { liburing::prep_futex_waitv(&mut sqe, waiters.as_ptr(), 2) };
    assert_eq!(sqe.opcode, io_uring::opcode::FutexWaitV::CODE);
    assert_eq!(
        (sqe.addr, sqe.len, sqe.operation_flags),
        (waiters.as_ptr() as u64, 2, 0)
    );
    assert_eq!(
        (sqe.user_data, sqe.flags, sqe.personality),
        (0x1234_5678_9abc_def0, 0x14, 7)
    );
}

fn wake_pending_futex(
    ring: &mut Proactor,
    words: &[std::sync::atomic::AtomicU32; 2],
    waiters: &[liburing::FutexWaitV; 2],
    vector: bool,
    flags: u32,
    spin: bool,
) -> Result<()> {
    ring.prepare_sqe_with(identity(1), |sqe| {
        // SAFETY: Callback owns SQE; test operands are retained for the process lifetime, including
        // failed cleanup.
        unsafe {
            if vector {
                liburing::prep_futex_waitv(sqe, waiters.as_ptr(), 2);
            } else {
                liburing::prep_futex_wait(
                    sqe,
                    words[0].as_ptr(),
                    0,
                    liburing::FUTEX_BITSET_MATCH_ANY,
                    flags,
                );
            }
        }
    })?;
    ring.submit()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut wait_seen = false;
    loop {
        ring.prepare_sqe_with(identity(2), |sqe| {
            // SAFETY: Exclusive SQE and aligned atomic storage stay live through both target CQEs.
            unsafe {
                liburing::prep_futex_wake(
                    sqe,
                    words[usize::from(vector)].as_ptr(),
                    1,
                    liburing::FUTEX_BITSET_MATCH_ANY,
                    flags,
                );
            }
        })?;
        let mut wake_seen = false;
        let mut woken = 0;
        while !wake_seen || (woken == 1 && !wait_seen) {
            assert!(
                Instant::now() < deadline,
                "futex target or wake CQE timed out"
            );
            let mut dispatch = |cqe: Completion, _: &mut SubmissionContext<'_>| {
                if cqe.operation_id == identity(1) {
                    assert!(!wait_seen, "wait delivered twice");
                    assert_eq!(
                        cqe.result,
                        i32::from(vector),
                        "Linux 6.7+ futex wait support is required"
                    );
                    wait_seen = true;
                } else {
                    assert_eq!(cqe.operation_id, identity(2));
                    assert!(!wake_seen, "wake delivered twice");
                    assert!(
                        (0..=1).contains(&cqe.result),
                        "futex wake failed: {}",
                        cqe.result
                    );
                    woken = cqe.result;
                    wake_seen = true;
                }
                Ok(())
            };
            if spin {
                ring.tick(&mut dispatch)?;
                std::hint::spin_loop();
            } else {
                ring.wait_completions(1, Some(Duration::from_millis(20)), &mut dispatch)?;
            }
        }
        if woken == 1 {
            assert!(wait_seen);
            assert!(ring.is_idle());
            return Ok(());
        }
        // A zero wake raced with enrollment; retry without changing the predicate or treating
        // EAGAIN as success.
        assert!(!wait_seen);
    }
}

fn futex_operands(
    flags: u32,
) -> (
    &'static [std::sync::atomic::AtomicU32; 2],
    &'static [liburing::FutexWaitV; 2],
) {
    // Test failure must not release a raw operand while a kernel target might still be pending.
    let words = Box::leak(Box::new(std::array::from_fn(|_| {
        std::sync::atomic::AtomicU32::new(0)
    })));
    let waiters = Box::leak(Box::new(std::array::from_fn(|i| {
        liburing::FutexWaitV::new()
            .uaddr(words[i].as_ptr() as u64)
            .val(0)
            .flags(flags)
    })));
    (words, waiters)
}

#[test]
fn futex_wait_and_wake_complete() -> Result<()> {
    for private in [0, liburing::FUTEX2_PRIVATE] {
        let flags = liburing::FUTEX2_SIZE_U32 | private;
        let (words, waiters) = futex_operands(flags);
        let mut ring = Proactor::new(ProactorConfig::default())?;
        wake_pending_futex(&mut ring, words, waiters, false, flags, false)?;
        ring.shutdown()?;
    }
    Ok(())
}

#[test]
fn futex_waitv_wakes_selected_word() -> Result<()> {
    for private in [0, liburing::FUTEX2_PRIVATE] {
        let flags = liburing::FUTEX2_SIZE_U32 | private;
        let (words, waiters) = futex_operands(flags);
        let mut ring = Proactor::new(ProactorConfig::default())?;
        wake_pending_futex(&mut ring, words, waiters, true, flags, false)?;
        ring.shutdown()?;
    }
    Ok(())
}

#[test]
fn forbidden_flag_errors_keep_precedence() -> Result<()> {
    use liburing::{UringError, backend};
    let mut ring = Proactor::new(ProactorConfig::default())?;
    for flags in 0..=u8::MAX {
        let drain =
            (backend::IOSQE_IO_DRAIN | backend::IOSQE_IO_LINK | backend::IOSQE_IO_HARDLINK) as u8;
        let forbidden = drain | backend::IOSQE_CQE_SKIP_SUCCESS as u8;
        if flags & forbidden == 0 {
            continue;
        }
        let error = ring.prepare_sqe_with(identity(3), |sqe| {
            // SAFETY: Preparation supplies initialized exclusive SQE storage and this changes only
            // its flags.
            unsafe {
                (*sqe).flags = flags;
            }
        });
        let expected = if flags & drain != 0 {
            "drain and linked operations cannot span bounded submission batches"
        } else {
            "every operation must deliver a final completion"
        };
        assert!(
            matches!(error, Err(UringError::InvalidPreparedSqe(message)) if message == expected)
        );
        assert!(ring.is_idle());
    }
    ring.shutdown()
}

struct FutexAffinity(Vec<usize>);
impl FutexAffinity {
    fn pin_pair() -> Result<(Self, u32)> {
        let mut original = vec![0usize; 16];
        loop {
            // SAFETY: The initialized aligned mask covers the writable extent for the calling
            // thread.
            if unsafe {
                libc::sched_getaffinity(
                    0,
                    std::mem::size_of_val(original.as_slice()),
                    original.as_mut_ptr().cast(),
                )
            } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) || original.len() >= 1 << 14 {
                return Err(error.into());
            }
            original.resize(original.len() * 2, 0);
        }
        let mut cpus = original.iter().enumerate().flat_map(|(i, word)| {
            (0..usize::BITS).filter_map(move |bit| {
                (word & (1usize << bit) != 0)
                    .then_some((i * usize::BITS as usize + bit as usize) as u32)
            })
        });
        let (Some(owner), Some(sq_cpu)) = (cpus.next(), cpus.next()) else {
            return Err(liburing::UringError::InvalidConfig(
                "futex SQPOLL requires two allowed CPUs",
            ));
        };
        let mut mask = vec![0usize; original.len()];
        mask[owner as usize / usize::BITS as usize] = 1usize << (owner % usize::BITS);
        let guard = Self(original);
        // SAFETY: The initialized readable mask pins only this thread to a CPU in its original
        // allowed set.
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
        Ok((guard, sq_cpu))
    }
}
impl Drop for FutexAffinity {
    fn drop(&mut self) {
        // SAFETY: The initialized captured mask restores only this calling thread's original CPU
        // set.
        let result = unsafe {
            libc::sched_setaffinity(
                0,
                std::mem::size_of_val(self.0.as_slice()),
                self.0.as_ptr().cast(),
            )
        };
        assert_eq!(result, 0, "futex affinity restoration failed");
    }
}

#[test]
fn futex_sq_poll_avoids_warm_enters() -> Result<()> {
    let (_affinity, sq_cpu) = FutexAffinity::pin_pair()?;
    let flags = liburing::FUTEX2_SIZE_U32;
    let (words, waiters) = futex_operands(flags);
    let mut ring = Proactor::new(ProactorConfig {
        mode: liburing::ProactorMode::sq_poll(sq_cpu),
        ..ProactorConfig::default()
    })?;
    wake_pending_futex(&mut ring, words, waiters, false, flags, true)?;
    let warmed = ring.stats().enter_calls;
    wake_pending_futex(&mut ring, words, waiters, false, flags, true)?;
    wake_pending_futex(&mut ring, words, waiters, true, flags, true)?;
    assert_eq!(
        ring.stats().enter_calls,
        warmed,
        "warm futex SQPOLL entered the kernel"
    );
    ring.shutdown()
}

#[test]
fn registered_slots_recycle_on_close() -> Result<()> {
    for explicit_shutdown in [false, true] {
        for iteration in 0..32 {
            let mut proactor = Proactor::new(ProactorConfig {
                entries: 2,
                ..ProactorConfig::default()
            })?;
            assert!(
                proactor.has_registered_ring_fd(),
                "registration lost at iteration {iteration}"
            );
            proactor.alloc_sqe(identity(iteration))?;
            let mut completions = 0;
            let deadline = Instant::now() + Duration::from_secs(2);
            while completions == 0 {
                assert!(Instant::now() < deadline, "registered NOP stalled");
                proactor.wait_completions(
                    1,
                    Some(Duration::from_secs(1)),
                    &mut |completion: Completion, _: &mut SubmissionContext<'_>| {
                        assert_eq!(completion.operation_id, identity(iteration));
                        assert_eq!(completion.result, 0);
                        completions += 1;
                        Ok(())
                    },
                )?;
            }
            assert_eq!(completions, 1);
            if explicit_shutdown {
                proactor.shutdown()?;
            }
            drop(proactor);
        }
    }
    Ok(())
}

#[test]
fn duplicate_identity_never_invokes_preparation() -> Result<()> {
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 2,
        staged_capacity: 1,
        operation_capacity: 1,
        ..ProactorConfig::default()
    })?;
    proactor.alloc_sqe(identity(17))?;
    assert_eq!(
        proactor.prepare_sqe_with(identity(17), |_| panic!("duplicate prepared")),
        Err(liburing::UringError::InvalidPayload(identity(17).raw()))
    );
    assert_eq!(
        proactor.prepare_sqe_with(identity(18), |_| panic!("full ring prepared")),
        Err(liburing::UringError::SqRingFull)
    );
    let mut completed = 0;
    proactor.wait_completions(
        1,
        Some(Duration::from_secs(1)),
        &mut |_: Completion, _: &mut SubmissionContext<'_>| {
            completed += 1;
            Ok(())
        },
    )?;
    assert_eq!(completed, 1);
    proactor.shutdown()
}

struct RingSlotGuard<'a>(Vec<io_uring::Submitter<'a>>);
impl Drop for RingSlotGuard<'_> {
    fn drop(&mut self) {
        for submitter in &mut self.0 {
            let _result = submitter.unregister_ring_fd();
        }
    }
}
#[test]
fn exhausted_registration_uses_raw_fd() -> Result<()> {
    let rings: Vec<_> = (0..16)
        .map(|_| io_uring::IoUring::new(2))
        .collect::<std::io::Result<_>>()?;
    let mut slots = RingSlotGuard(rings.iter().map(io_uring::IoUring::submitter).collect());
    for submitter in &mut slots.0 {
        submitter.register_ring_fd()?;
    }
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 2,
        ..ProactorConfig::default()
    })?;
    assert!(!proactor.has_registered_ring_fd());
    proactor.alloc_sqe(identity(19))?;
    let mut done = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !done {
        assert!(Instant::now() < deadline, "fallback NOP stalled");
        proactor.wait_completions(
            1,
            Some(Duration::from_secs(1)),
            &mut |completion: Completion, _: &mut SubmissionContext<'_>| {
                assert_eq!(completion.operation_id, identity(19));
                assert_eq!(completion.result, 0);
                done = true;
                Ok(())
            },
        )?;
    }
    proactor.shutdown()
}

#[test]
fn selected_buffers_share_contiguous_storage() -> Result<()> {
    use std::os::{fd::AsRawFd, unix::net::UnixDatagram};

    use liburing::{BufferGroupId, backend, ops::net};
    for length in [31usize, 1024, 512 * 1024] {
        let mut proactor = Proactor::new(ProactorConfig {
            entries: 8,
            ..ProactorConfig::default()
        })?;
        let group = BufferGroupId(7);
        proactor.register_buffer_ring(group, 4, length)?;
        let (socket, peer) = UnixDatagram::pair()?;
        let mut addresses = [0usize; 4];
        for sequence in 0..8u64 {
            assert_eq!(peer.send(&[sequence as u8])?, 1);
            proactor.prepare_sqe_with(identity(sequence), |sqe| {
                // SAFETY: The socket and registered group remain live until this receive's final
                // CQE.
                unsafe {
                    net::prep_recv(sqe, socket.as_raw_fd(), std::ptr::null_mut(), length, 0);
                    (*sqe).buf_index = group.raw();
                    (*sqe).flags |= backend::IOSQE_BUFFER_SELECT as u8;
                }
            })?;
            let mut complete = false;
            let deadline = Instant::now() + Duration::from_secs(2);
            while !complete {
                assert!(Instant::now() < deadline, "selected receive stalled");
                proactor.wait_completions(
                    1,
                    Some(Duration::from_secs(1)),
                    &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                        assert_eq!(cqe.result, 1);
                        // SAFETY: This unconsumed final receive CQE transfers its selected buffer
                        // exclusively.
                        let mut lease = unsafe {
                            context
                                .buffer_ring(group)?
                                .lease_from_cqe(cqe.flags, cqe.result)
                        }?;
                        let index = usize::from(lease.buffer_id().raw());
                        let address = lease.as_slice().as_ptr() as usize;
                        if sequence < 4 {
                            assert_eq!(addresses[index], 0);
                            addresses[index] = address;
                        }
                        assert_eq!(addresses[index], address);
                        assert_eq!(lease.as_slice(), &[sequence as u8]);
                        assert_eq!(lease.len(), 1);
                        assert!(!lease.is_empty());
                        lease.as_mut_slice()[0] = 255;
                        complete = true;
                        Ok(())
                    },
                )?;
            }
        }
        assert!(addresses.iter().all(|&address| address != 0));
        for index in 1..4 {
            assert_eq!(addresses[index] - addresses[0], index * length);
        }
        if length * 4 >= 4096 {
            assert_eq!(addresses[0] % 4096, 0);
        }
        assert_eq!(proactor.buffer_ring(group)?.returned_count(), 8);
        proactor.shutdown()?;
    }
    Ok(())
}

#[test]
fn empty_cq_poll_flushes_staged_work() -> Result<()> {
    for budget in [0, 1] {
        let mut proactor = Proactor::new(ProactorConfig::default())?;
        proactor.alloc_sqe(identity(27))?;
        assert_eq!(
            proactor.poll_completions(
                budget,
                &mut |_: Completion, _: &mut SubmissionContext<'_>| {
                    panic!("unpublished NOP cannot be ready");
                }
            )?,
            0
        );
        assert_eq!(proactor.submit()?, 0);
        let mut completed = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !completed {
            assert!(Instant::now() < deadline, "flushed NOP stalled");
            proactor.wait_completions(
                1,
                Some(Duration::from_secs(1)),
                &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
                    assert_eq!(cqe.operation_id, identity(27));
                    assert_eq!(cqe.result, 0);
                    completed = true;
                    Ok(())
                },
            )?;
        }
        proactor.shutdown()?;
    }
    Ok(())
}

#[test]
fn empty_submit_wakes_published_sq_work() -> Result<()> {
    let (_affinity, sq_cpu) = FutexAffinity::pin_pair()?;
    let mut sq = liburing::config::SqPollConfig::pinned(sq_cpu);
    sq.idle_ms = std::num::NonZeroU32::MIN;
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 2,
        mode: liburing::ProactorMode::SqPoll(sq),
        ..ProactorConfig::default()
    })?;
    let pointer = proactor.ring_mut();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: This owner retains the live ring and borrows its SQ only within this expression.
        let asleep = unsafe { std::mem::ManuallyDrop::new((*pointer).submission()).need_wakeup() };
        if asleep {
            break;
        }
        assert!(Instant::now() < deadline, "SQ thread never slept");
        std::thread::yield_now();
    }
    let entry = io_uring::opcode::Nop::new().build().user_data(0);
    // SAFETY: This pointer-free internal NOP has no DMA operands; the exclusive owner publishes
    // it without waking the sleeping SQ thread to exercise pending work outside staging.
    unsafe { (*pointer).submission().push(&entry) }
        .map_err(|_| liburing::UringError::SqRingFull)?;
    let before = proactor.stats().sq_wakeups;
    assert_eq!(proactor.submit()?, 0);
    assert_eq!(proactor.stats().sq_wakeups, before + 1);
    let mut harvested = 0;
    let deadline = Instant::now() + Duration::from_secs(2);
    while harvested == 0 {
        assert!(Instant::now() < deadline, "published SQ work stalled");
        harvested +=
            proactor.poll_completions(1, &mut |_: Completion, _: &mut SubmissionContext<'_>| {
                panic!("internal NOP dispatched to application");
            })?;
    }
    proactor.shutdown()
}

#[test]
fn repeated_cancel_preserves_full_staging() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 8,
        staged_capacity: 1,
        operation_capacity: 8,
        ..Default::default()
    })?;
    let id = identity(1);
    ring.alloc_sqe(id)?;
    ring.submit()?;
    assert!(ring.cancel(id)?);
    let before = ring.stats().enter_calls;
    assert_eq!(ring.pending_cancel_count(), 1);
    assert!(ring.cancel(id)?);
    assert!(ring.cancel_key(ring.operation_key(id)?)?);
    assert_eq!(ring.stats().enter_calls, before);
    assert_eq!(ring.pending_cancel_count(), 1);
    ring.shutdown()
}

#[test]
fn large_sector_pool_has_page_alignment() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig::default())?;
    ring.configure_direct_buffers(512, 4096, 512)?;
    // SAFETY: This thread owns the ring; the handle is dropped before teardown.
    let buffer = unsafe { ring.fixed_buffers() }?.checkout()?;
    assert_eq!(buffer.as_ptr() as usize % 4096, 0);
    assert_eq!(buffer.as_slice().len(), 4096);
    drop(buffer);
    ring.shutdown()
}
