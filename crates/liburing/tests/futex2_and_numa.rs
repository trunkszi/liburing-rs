//! Kernel regressions for futex2 wait, wake, requeue, NUMA node writeback, and io_uring.

use std::{
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    thread::{self, ScopedJoinHandle},
    time::{Duration, Instant},
};

use liburing::{
    Completion, FUTEX_BITSET_MATCH_ANY, OperationId, OperationPayload, Proactor, ProactorConfig,
    Result, SubmissionContext, SubsystemId, UringError,
    backend::sys::params::KernelTimespec,
    futex2::{
        FutexFlags, FutexNumaU32, FutexWaitV, FutexWaiter, FutexWord, futex_requeue_numa_u32,
        futex_requeue_u32, futex_wait_numa_u32, futex_wait_u32, futex_waitv, futex_wake_numa_u32,
        futex_wake_u32, sys_futex_requeue, sys_futex_waitv, sys_futex_wake,
    },
    ops::futex::{prep_futex_wait_numa_u32, prep_futex_wake_numa_u32},
};

const MASK: u64 = FUTEX_BITSET_MATCH_ANY;

fn identity(value: u64) -> OperationId {
    OperationId::pack(SubsystemId(1), OperationPayload(value))
}

fn errno_of(err: UringError) -> i32 {
    match err {
        UringError::Syscall { errno, .. } => errno,
        other => panic!("expected a syscall errno, observed {other}"),
    }
}

fn current_tid() -> i32 {
    // SAFETY: `SYS_gettid` takes no pointer arguments and returns this thread's id.
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn task_is_sleeping(tid: i32) -> bool {
    let path = format!("/proc/self/task/{tid}/stat");
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Some(end) = text.rfind(')') else {
        return false;
    };
    text.as_bytes().get(end.saturating_add(2)) == Some(&b'S')
}

fn wait_until_sleeping(tid: &AtomicI32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let id = tid.load(Ordering::Acquire);
        if id > 0 && task_is_sleeping(id) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "futex waiter did not reach interruptible sleep"
        );
        thread::yield_now();
    }
}

fn monotonic_after(after: Duration) -> KernelTimespec {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a writable timespec and `CLOCK_MONOTONIC` is a valid clock.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    assert_eq!(rc, 0, "clock_gettime failed");
    let mut nsec = now.tv_nsec + i64::from(after.subsec_nanos());
    let mut sec = now.tv_sec + i64::try_from(after.as_secs()).unwrap_or(i64::MAX);
    if nsec >= 1_000_000_000 {
        sec += 1;
        nsec -= 1_000_000_000;
    }
    KernelTimespec {
        tv_sec: sec,
        tv_nsec: nsec,
    }
}

fn join_waiter(handle: ScopedJoinHandle<'_, Result<()>>) {
    match handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("waiter returned {err}"),
        Err(_) => panic!("waiter thread panicked"),
    }
}

fn node_of(word: &FutexNumaU32) -> i32 {
    word.node.load(Ordering::Acquire)
}

#[test]
fn wait_mismatch_returns_eagain() {
    let word = FutexWord::new(1);
    let err = match futex_wait_u32(
        &word,
        0,
        MASK,
        FutexFlags::PRIVATE_U32,
        None,
        libc::CLOCK_MONOTONIC,
    ) {
        Ok(()) => panic!("mismatched wait returned success"),
        Err(err) => err,
    };
    assert_eq!(errno_of(err), libc::EAGAIN);
}

#[test]
fn wait_timeout_returns_etimedout() {
    let word = FutexWord::new(0);
    let past = KernelTimespec {
        tv_sec: 0,
        tv_nsec: 1,
    };
    let err = match futex_wait_u32(
        &word,
        0,
        MASK,
        FutexFlags::PRIVATE_U32,
        Some(&past),
        libc::CLOCK_MONOTONIC,
    ) {
        Ok(()) => panic!("expired wait returned success"),
        Err(err) => err,
    };
    assert_eq!(errno_of(err), libc::ETIMEDOUT);
}

#[test]
fn non_u32_size_returns_einval() {
    let word = FutexWord::new(0);
    for flags in [
        FutexFlags::SIZE_U8,
        FutexFlags::SIZE_U16,
        FutexFlags::SIZE_U64,
    ] {
        // SAFETY: `word` is a live aligned word. These sizes are rejected before a wait queue is
        // used.
        let err = match unsafe { sys_futex_wake(word.as_ptr(), MASK, 1, flags) } {
            Ok(count) => panic!("size {flags:?} woke {count}"),
            Err(err) => err,
        };
        assert_eq!(errno_of(err), libc::EINVAL, "{flags:?}");
    }
}

#[test]
fn bitset_mask_wakes_matching_waiter() {
    let word = FutexWord::new(0);
    let timeout = monotonic_after(Duration::from_secs(3));
    let tid = AtomicI32::new(0);
    thread::scope(|scope| {
        let handle = scope.spawn(|| {
            tid.store(current_tid(), Ordering::Release);
            futex_wait_u32(
                &word,
                0,
                0b01,
                FutexFlags::PRIVATE_U32,
                Some(&timeout),
                libc::CLOCK_MONOTONIC,
            )
        });
        wait_until_sleeping(&tid);
        match futex_wake_u32(&word, 0b10, 1, FutexFlags::PRIVATE_U32) {
            Ok(0) => {}
            Ok(count) => panic!("unmatched mask woke {count}"),
            Err(err) => panic!("unmatched wake failed: {err}"),
        }
        assert!(!handle.is_finished(), "unmatched mask completed the waiter");
        match futex_wake_u32(&word, 0b01, 1, FutexFlags::PRIVATE_U32) {
            Ok(1) => {}
            Ok(count) => panic!("matched mask woke {count}"),
            Err(err) => panic!("matched wake failed: {err}"),
        }
        join_waiter(handle);
    });
}

fn drive_requeue(
    tid: &AtomicI32,
    requeue: impl Fn() -> Result<u32>,
    wake_source: impl Fn() -> Result<u32>,
    wake_dest: impl Fn() -> Result<u32>,
) {
    wait_until_sleeping(tid);
    let deadline = Instant::now() + Duration::from_secs(2);
    let moved = loop {
        match requeue() {
            Ok(0) => {
                assert!(Instant::now() < deadline, "requeue observed no waiter");
                thread::yield_now();
            }
            Ok(count) => break count,
            Err(err) => panic!("requeue failed: {err}"),
        }
    };
    assert!(moved >= 1, "requeue count {moved}");
    match wake_source() {
        Ok(0) => {}
        Ok(count) => panic!("source still held {count} waiters"),
        Err(err) => panic!("source wake failed: {err}"),
    }
    match wake_dest() {
        Ok(1) => {}
        Ok(count) => panic!("destination wake count {count}"),
        Err(err) => panic!("destination wake failed: {err}"),
    }
}

#[test]
fn requeue_u32_moves_waiter() {
    let source = FutexWord::new(0);
    let destination = FutexWord::new(0);
    let timeout = monotonic_after(Duration::from_secs(3));
    let tid = AtomicI32::new(0);
    thread::scope(|scope| {
        let handle = scope.spawn(|| {
            tid.store(current_tid(), Ordering::Release);
            futex_wait_u32(
                &source,
                0,
                MASK,
                FutexFlags::PRIVATE_U32,
                Some(&timeout),
                libc::CLOCK_MONOTONIC,
            )
        });
        drive_requeue(
            &tid,
            || futex_requeue_u32(&source, &destination, 0, 0, 1, FutexFlags::PRIVATE_U32),
            || futex_wake_u32(&source, MASK, 1, FutexFlags::PRIVATE_U32),
            || futex_wake_u32(&destination, MASK, 1, FutexFlags::PRIVATE_U32),
        );
        join_waiter(handle);
    });
}

#[test]
fn requeue_numa_moves_waiter() {
    let source = FutexNumaU32::new(0);
    let destination = FutexNumaU32::new(0);
    assert_eq!(node_of(&source), -1);
    assert_eq!(node_of(&destination), -1);
    let timeout = monotonic_after(Duration::from_secs(3));
    let tid = AtomicI32::new(0);
    thread::scope(|scope| {
        let handle = scope.spawn(|| {
            tid.store(current_tid(), Ordering::Release);
            futex_wait_numa_u32(
                &source,
                0,
                MASK,
                FutexFlags::PRIVATE_U32_NUMA,
                Some(&timeout),
                libc::CLOCK_MONOTONIC,
            )
        });
        wait_until_sleeping(&tid);
        assert!(node_of(&source) >= 0, "wait did not publish a node");
        drive_requeue(
            &tid,
            || futex_requeue_numa_u32(&source, &destination, 0, 0, 1, FutexFlags::PRIVATE_U32_NUMA),
            || futex_wake_numa_u32(&source, MASK, 1, FutexFlags::PRIVATE_U32_NUMA),
            || futex_wake_numa_u32(&destination, MASK, 1, FutexFlags::PRIVATE_U32_NUMA),
        );
        join_waiter(handle);
    });
    assert!(
        node_of(&destination) >= 0,
        "requeue destination node stayed unset"
    );
}

#[test]
fn requeue_rejects_mismatched_flags() {
    let source = FutexWord::new(0);
    let destination = FutexWord::new(0);
    let private = FutexFlags::PRIVATE_U32.bits();
    let shared = FutexFlags::SHARED_U32.bits();
    let mismatched = [
        FutexWaitV::new()
            .uaddr(source.as_ptr() as u64)
            .val(0)
            .flags(private),
        FutexWaitV::new()
            .uaddr(destination.as_ptr() as u64)
            .flags(shared),
    ];
    // SAFETY: Both words are live. The flag mismatch is rejected before the kernel walks them.
    let mismatched_err = match unsafe { sys_futex_requeue(&mismatched, 0, 0, 1) } {
        Ok(count) => panic!("mismatched flags requeued {count}"),
        Err(err) => err,
    };
    assert_eq!(errno_of(mismatched_err), libc::EINVAL);
    let matched = [
        mismatched[0],
        FutexWaitV::new()
            .uaddr(destination.as_ptr() as u64)
            .flags(private),
    ];
    // SAFETY: Both words are live. A nonzero syscall flag is rejected before the kernel walk.
    let flags_err = match unsafe { sys_futex_requeue(&matched, 1, 0, 1) } {
        Ok(count) => panic!("nonzero requeue flags returned {count}"),
        Err(err) => err,
    };
    assert_eq!(errno_of(flags_err), libc::EINVAL);
}

#[test]
fn numa_rewrites_node_on_wait_wake() {
    let wake_word = FutexNumaU32::new(0);
    assert_eq!(node_of(&wake_word), -1);
    match futex_wake_numa_u32(&wake_word, MASK, 1, FutexFlags::PRIVATE_U32_NUMA) {
        Ok(0) => {}
        Ok(count) => panic!("idle wake returned {count}"),
        Err(err) => panic!("numa wake failed: {err}"),
    }
    assert!(
        node_of(&wake_word) >= 0,
        "wake left node at {}",
        node_of(&wake_word)
    );

    let wait_word = FutexNumaU32::new(0);
    assert_eq!(node_of(&wait_word), -1);
    let timeout = monotonic_after(Duration::from_secs(3));
    let tid = AtomicI32::new(0);
    thread::scope(|scope| {
        let handle = scope.spawn(|| {
            tid.store(current_tid(), Ordering::Release);
            futex_wait_numa_u32(
                &wait_word,
                0,
                MASK,
                FutexFlags::PRIVATE_U32_NUMA,
                Some(&timeout),
                libc::CLOCK_MONOTONIC,
            )
        });
        wait_until_sleeping(&tid);
        assert!(
            node_of(&wait_word) >= 0,
            "wait left node at {}",
            node_of(&wait_word)
        );
        match futex_wake_numa_u32(&wait_word, MASK, 1, FutexFlags::PRIVATE_U32_NUMA) {
            Ok(1) => {}
            Ok(count) => panic!("numa waiter wake count {count}"),
            Err(err) => panic!("numa waiter wake failed: {err}"),
        }
        join_waiter(handle);
    });
}

#[test]
fn numa_mpol_rewrites_node() {
    let wake_word = FutexNumaU32::new(0);
    // SAFETY: The NUMA pair is live and writable. MPOL is combined with NUMA and the private key.
    let wake = match unsafe {
        sys_futex_wake(
            wake_word.as_ptr(),
            MASK,
            1,
            FutexFlags::PRIVATE_U32_NUMA_MPOL,
        )
    } {
        Ok(count) => count,
        Err(err) => panic!("mpol wake failed: {err}"),
    };
    assert_eq!(wake, 0);
    assert!(node_of(&wake_word) >= 0, "mpol wake left node unset");

    let wait_word = FutexNumaU32::new(7);
    // SAFETY: Value 7 does not match 0, so the kernel returns EAGAIN after validating MPOL|NUMA.
    let err = match unsafe {
        liburing::futex2::sys_futex_wait(
            wait_word.as_ptr(),
            0,
            MASK,
            FutexFlags::PRIVATE_U32_NUMA_MPOL,
            None,
            libc::CLOCK_MONOTONIC,
        )
    } {
        Ok(()) => panic!("mpol mismatched wait succeeded"),
        Err(err) => err,
    };
    assert_eq!(errno_of(err), libc::EAGAIN);
    assert!(node_of(&wait_word) >= 0, "mpol wait left node unset");
}

#[test]
fn waitv_wakes_selected_index() {
    let words = [FutexWord::new(0), FutexWord::new(0)];
    let flags = FutexFlags::PRIVATE_U32;
    let timeout = monotonic_after(Duration::from_secs(3));
    let tid = AtomicI32::new(0);
    thread::scope(|scope| {
        let handle = scope.spawn(|| {
            tid.store(current_tid(), Ordering::Release);
            let waiters = [
                FutexWaiter::from_u32(&words[0], 0, flags),
                FutexWaiter::from_u32(&words[1], 0, flags),
            ];
            match futex_waitv(&waiters, Some(&timeout), libc::CLOCK_MONOTONIC) {
                Ok(1) => Ok(()),
                Ok(index) => panic!("waitv woke index {index}"),
                Err(err) => Err(err),
            }
        });
        wait_until_sleeping(&tid);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match futex_wake_u32(&words[1], MASK, 1, FutexFlags::PRIVATE_U32) {
                Ok(0) => {
                    assert!(Instant::now() < deadline, "waitv wake missed the waiter");
                    thread::yield_now();
                }
                Ok(1) => break,
                Ok(count) => panic!("waitv wake count {count}"),
                Err(err) => panic!("waitv wake failed: {err}"),
            }
        }
        join_waiter(handle);
    });
}

#[test]
fn waitv_rejects_nonzero_flags() {
    let word = FutexWord::new(0);
    let waiter = [FutexWaiter::from_u32(&word, 0, FutexFlags::PRIVATE_U32).as_waitv()];
    // SAFETY: The record names a live word. Nonzero syscall flags are rejected before the wait.
    let err = match unsafe { sys_futex_waitv(&waiter, 1, None, libc::CLOCK_MONOTONIC) } {
        Ok(index) => panic!("nonzero waitv flags returned {index}"),
        Err(err) => err,
    };
    assert_eq!(errno_of(err), libc::EINVAL);
    // SAFETY: The empty slice is rejected before any futex address is read.
    let empty = match unsafe { sys_futex_waitv(&[], 0, None, libc::CLOCK_MONOTONIC) } {
        Ok(index) => panic!("empty waitv returned {index}"),
        Err(err) => err,
    };
    assert_eq!(errno_of(empty), libc::EINVAL);
}

fn wait_for_cqe(ring: &mut Proactor, id: OperationId, accept: impl Fn(i32) -> bool) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(Instant::now() < deadline, "missing CQE for {id:?}");
        let mut found = None;
        ring.poll_completions(4, &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
            if cqe.operation_id == id {
                assert!(found.is_none(), "duplicate CQE for {id:?}");
                found = Some(cqe.result);
            }
            Ok(())
        })
        .unwrap_or_else(|err| panic!("poll failed: {err}"));
        if let Some(result) = found {
            assert!(accept(result), "CQE result {result} for {id:?}");
            return result;
        }
        thread::yield_now();
    }
}

fn submit_numa_wait(ring: &mut Proactor, word: &FutexNumaU32, flags: u32) -> Result<()> {
    let id = identity(1);
    ring.prepare_sqe_with(id, |sqe| {
        // SAFETY: The callback owns the SQE. `word` outlives shutdown of this ring.
        unsafe { prep_futex_wait_numa_u32(sqe, word.as_ptr().cast(), 0, MASK, flags) };
    })?;
    ring.submit()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while node_of(word) < 0 {
        assert!(
            Instant::now() < deadline,
            "io_uring wait did not publish a NUMA node"
        );
        thread::yield_now();
    }
    Ok(())
}

#[test]
fn uring_numa_wait_woken_by_syscall() -> Result<()> {
    let word = Arc::new(FutexNumaU32::new(0));
    let flags = FutexFlags::PRIVATE_U32_NUMA.bits();
    let mut ring = Proactor::new(ProactorConfig::default())?;
    submit_numa_wait(&mut ring, &word, flags)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match futex_wake_numa_u32(&word, MASK, 1, FutexFlags::PRIVATE_U32_NUMA) {
            Ok(0) => {
                assert!(
                    Instant::now() < deadline,
                    "syscall wake missed the uring waiter"
                );
                thread::yield_now();
            }
            Ok(1) => break,
            Ok(count) => panic!("syscall wake count {count}"),
            Err(err) => panic!("syscall wake failed: {err}"),
        }
    }
    assert_eq!(
        wait_for_cqe(&mut ring, identity(1), |result| result == 0),
        0
    );
    ring.shutdown()?;
    assert!(node_of(&word) >= 0);
    Ok(())
}

#[test]
fn uring_numa_wait_woken_by_sqe() -> Result<()> {
    let word = Arc::new(FutexNumaU32::new(0));
    let probe = FutexNumaU32::new(0);
    let flags = FutexFlags::PRIVATE_U32_NUMA.bits();
    assert_eq!(node_of(&probe), -1);
    let mut ring = Proactor::new(ProactorConfig::default())?;
    submit_numa_wait(&mut ring, &word, flags)?;
    ring.prepare_sqe_with(identity(3), |sqe| {
        // SAFETY: The callback owns the SQE. `probe` stays alive until this ring shuts down.
        unsafe { prep_futex_wake_numa_u32(sqe, probe.as_ptr().cast(), 1, MASK, flags) };
    })?;
    ring.submit()?;
    assert_eq!(
        wait_for_cqe(&mut ring, identity(3), |result| result == 0),
        0
    );
    assert!(
        node_of(&probe) >= 0,
        "io_uring wake left the probe node unset"
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut wait_result = None;
    loop {
        ring.prepare_sqe_with(identity(2), |sqe| {
            // SAFETY: The callback owns the SQE. `word` outlives shutdown.
            unsafe { prep_futex_wake_numa_u32(sqe, word.as_ptr().cast(), 1, MASK, flags) };
        })?;
        ring.submit()?;
        let mut wake_result = None;
        while wake_result.is_none() || (wake_result == Some(1) && wait_result.is_none()) {
            assert!(
                Instant::now() < deadline,
                "SQE wake missed the uring waiter"
            );
            ring.poll_completions(4, &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
                if cqe.operation_id == identity(1) {
                    assert!(wait_result.is_none(), "wait delivered twice");
                    wait_result = Some(cqe.result);
                } else {
                    assert_eq!(cqe.operation_id, identity(2));
                    assert!(wake_result.is_none(), "wake delivered twice");
                    wake_result = Some(cqe.result);
                }
                Ok(())
            })?;
            thread::yield_now();
        }
        match wake_result {
            Some(1) => break,
            Some(0) => assert!(wait_result.is_none(), "wait completed on a zero wake"),
            Some(result) => panic!("futex wake failed: {result}"),
            None => panic!("wake poll ended without a CQE"),
        }
    }
    assert_eq!(wait_result, Some(0));
    ring.shutdown()?;
    Ok(())
}

#[repr(C, align(8))]
struct Neighbor {
    word: FutexWord,
    plain: i32,
}

#[test]
fn plain_word_numa_flag_spares_neighbor() {
    const _: () = {
        assert!(core::mem::offset_of!(Neighbor, plain) == 4);
    };
    let neighbor = Neighbor {
        word: FutexWord::new(0),
        plain: -1,
    };
    // A mismatched value still reaches the kernel node store: EAGAIN is reported
    // after FUTEX2_NUMA writes the four bytes that follow the value.
    let waiter = FutexWaiter::from_u32(&neighbor.word, 2, FutexFlags::PRIVATE_U32_NUMA);
    assert_eq!(waiter.as_waitv().flags, FutexFlags::PRIVATE_U32.bits());
    let waitv_err = match futex_waitv(&[waiter], None, libc::CLOCK_MONOTONIC) {
        Ok(index) => panic!("mismatched waitv returned {index}"),
        Err(err) => err,
    };
    assert_eq!(errno_of(waitv_err), libc::EAGAIN);
    assert_eq!(neighbor.plain, -1);
    let wait_err = match futex_wait_u32(
        &neighbor.word,
        2,
        FUTEX_BITSET_MATCH_ANY,
        FutexFlags::PRIVATE_U32_NUMA,
        None,
        libc::CLOCK_MONOTONIC,
    ) {
        Ok(()) => panic!("mismatched wait returned success"),
        Err(err) => err,
    };
    assert_eq!(errno_of(wait_err), libc::EAGAIN);
    assert_eq!(neighbor.plain, -1);
}
