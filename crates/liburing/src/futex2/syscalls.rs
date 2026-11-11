//! Blocking futex2 syscalls above the raw Linux wrappers.
//!
//! Negative kernel returns become `UringError::Syscall` with a positive errno.
//! These calls can sleep and must not run inside a completion hook.

use crate::{
    backend::sys::{
        futex::{FUTEX_WAITV_MAX, FutexWaitv},
        params::KernelTimespec,
        {self as raw},
    },
    error::{Result, UringError},
    futex2::word::{FutexFlags, FutexNumaU32, FutexWaitV, FutexWaiter, FutexWord},
};

const WAITV_MAX: usize = FUTEX_WAITV_MAX as usize;

fn timeout_ptr(timeout: Option<&KernelTimespec>) -> *const KernelTimespec {
    match timeout {
        Some(value) => core::ptr::from_ref(value),
        None => core::ptr::null(),
    }
}

fn map_unit(operation: &'static str, raw_result: i32) -> Result<()> {
    if raw_result < 0 {
        Err(UringError::Syscall {
            operation,
            errno: raw_result.saturating_abs(),
        })
    } else {
        Ok(())
    }
}

fn map_count(operation: &'static str, raw_result: i32) -> Result<u32> {
    match u32::try_from(raw_result) {
        Ok(count) => Ok(count),
        Err(_) => Err(UringError::Syscall {
            operation,
            errno: raw_result.saturating_abs(),
        }),
    }
}

fn map_index(operation: &'static str, raw_result: i32) -> Result<usize> {
    match usize::try_from(raw_result) {
        Ok(index) => Ok(index),
        Err(_) => Err(UringError::Syscall {
            operation,
            errno: raw_result.saturating_abs(),
        }),
    }
}

fn reject(operation: &'static str) -> UringError {
    UringError::Syscall {
        operation,
        errno: libc::EINVAL,
    }
}

/// Waits until `*uaddr` changes, a matching wake arrives, or `timeout` expires.
///
/// `timeout` is absolute on `clockid` (`CLOCK_MONOTONIC` or `CLOCK_REALTIME`).
/// `None` waits without a timeout. A value mismatch returns `EAGAIN`.
///
/// # Errors
/// Returns `UringError::Syscall` with the positive errno from `sys_futex_wait`,
/// including `EAGAIN`, `ETIMEDOUT`, `EINVAL`, and `EINTR`.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `uaddr` must address a live, correctly aligned futex for `flags` throughout
/// the call. `FUTEX2_NUMA` requires a writable 8-byte value/node pair because
/// the kernel stores the resolved node on wait. `timeout`, when present, must
/// stay readable. Do not call this from a completion hook; it can block.
#[inline]
pub unsafe fn sys_futex_wait(
    uaddr: *const libc::c_void,
    val: u64,
    mask: u64,
    flags: FutexFlags,
    timeout: Option<&KernelTimespec>,
    clockid: libc::clockid_t,
) -> Result<()> {
    // SAFETY: The caller retains the aligned futex, permits the NUMA node store, and keeps
    // `timeout` readable for the duration of the blocking call.
    let raw_result = unsafe {
        raw::sys_futex_wait(
            uaddr.cast_mut(),
            val as libc::c_ulong,
            mask as libc::c_ulong,
            flags.bits(),
            timeout_ptr(timeout),
            clockid,
        )
    };
    map_unit("futex_wait", raw_result)
}

/// Wakes up to `nr` waiters whose bitset intersects `mask`.
///
/// # Errors
/// Returns `UringError::Syscall` with the positive errno from `sys_futex_wake`.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `uaddr` must address a live, correctly aligned futex for `flags` throughout
/// the call. `FUTEX2_NUMA` requires a writable node word: the kernel stores the
/// resolved node on wake when that word is `FUTEX_NO_NODE`.
#[inline]
pub unsafe fn sys_futex_wake(
    uaddr: *const libc::c_void,
    mask: u64,
    nr: i32,
    flags: FutexFlags,
) -> Result<u32> {
    // SAFETY: The caller retains the aligned mapping and allows a NUMA node store on wake.
    let raw_result =
        unsafe { raw::sys_futex_wake(uaddr.cast_mut(), mask as libc::c_ulong, nr, flags.bits()) };
    map_count("futex_wake", raw_result)
}

/// Requeues waiters from `waiters[0]` to `waiters[1]`.
///
/// The syscall flag word must be zero, and both records must carry identical
/// futex2 flags. `waiters[0].val` is the expected source value.
///
/// # Errors
/// Returns `UringError::Syscall` with `EINVAL` when `flags != 0` or the record
/// flags differ. Otherwise returns the kernel errno from `sys_futex_requeue`.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// Both records must name live, aligned futexes retained for the call. NUMA
/// node words must be writable. The two-record array must stay readable.
#[inline]
pub unsafe fn sys_futex_requeue(
    waiters: &[FutexWaitV; 2],
    flags: u32,
    nr_wake: i32,
    nr_requeue: i32,
) -> Result<u32> {
    if flags != 0 || waiters[0].flags != waiters[1].flags {
        return Err(reject("futex_requeue"));
    }
    // SAFETY: The caller retains both records and both aligned futex mappings. Layout matches
    // `FutexWaitv`, so the kernel reads the same 24-byte records.
    let raw_result = unsafe {
        raw::sys_futex_requeue(
            waiters.as_ptr().cast::<FutexWaitv>(),
            flags,
            nr_wake,
            nr_requeue,
        )
    };
    map_count("futex_requeue", raw_result)
}

/// Waits on `waiters` and returns the index of the awakened record.
///
/// The syscall flag word must be zero. `waiters.len()` must be in `1..=128`.
///
/// # Errors
/// Returns `UringError::Syscall` with `EINVAL` when `flags != 0` or the length
/// is outside `1..=FUTEX_WAITV_MAX`. Otherwise returns the kernel errno from
/// `sys_futex_waitv`.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `waiters` and every futex it names must stay valid for the call. NUMA node
/// words must be writable. `timeout`, when present, must stay readable. This
/// call can block and must not run inside a completion hook.
#[inline]
pub unsafe fn sys_futex_waitv(
    waiters: &[FutexWaitV],
    flags: u32,
    timeout: Option<&KernelTimespec>,
    clockid: libc::clockid_t,
) -> Result<usize> {
    if flags != 0 || waiters.is_empty() || waiters.len() > WAITV_MAX {
        return Err(reject("futex_waitv"));
    }
    let len = match u32::try_from(waiters.len()) {
        Ok(len) => len,
        Err(_) => return Err(reject("futex_waitv")),
    };
    // SAFETY: The caller retains the records, their futex words, and any timeout. The length was
    // checked against `FUTEX_WAITV_MAX`.
    let raw_result = unsafe {
        raw::sys_futex_waitv(
            waiters.as_ptr().cast::<FutexWaitv>(),
            len,
            flags,
            timeout_ptr(timeout),
            clockid,
        )
    };
    map_index("futex_waitv", raw_result)
}

/// Waits on a 32-bit word.
///
/// `flags` is narrowed with [`FutexFlags::for_u32`]: the size is `FUTEX2_SIZE_U32`
/// and only `FUTEX2_PRIVATE` is kept. `FUTEX2_NUMA` and `FUTEX2_MPOL` are dropped
/// so the kernel cannot store a node past the 4-byte word. Pass a flag word
/// without `FUTEX2_PRIVATE` for a shared mapping.
///
/// # Errors
/// Returns the same syscall errors as `sys_futex_wait`.
///
/// # Panics
/// Does not panic.
#[inline]
pub fn futex_wait_u32(
    word: &FutexWord,
    expected: u32,
    mask: u64,
    flags: FutexFlags,
    timeout: Option<&KernelTimespec>,
    clockid: libc::clockid_t,
) -> Result<()> {
    // SAFETY: `word` is a live 4-byte-aligned word. Flags no longer request a NUMA node store.
    unsafe {
        sys_futex_wait(
            word.as_ptr(),
            u64::from(expected),
            mask,
            flags.for_u32(),
            timeout,
            clockid,
        )
    }
}

/// Wakes waiters on a 32-bit word. Returns the number woken.
///
/// `flags` is narrowed with [`FutexFlags::for_u32`]. The private-key bit must
/// match the waiters.
///
/// # Errors
/// Returns the same syscall errors as `sys_futex_wake`.
///
/// # Panics
/// Does not panic.
#[inline]
pub fn futex_wake_u32(word: &FutexWord, mask: u64, nr: i32, flags: FutexFlags) -> Result<u32> {
    // SAFETY: `word` is a live 4-byte-aligned word. Flags no longer request a NUMA node store.
    unsafe { sys_futex_wake(word.as_ptr(), mask, nr, flags.for_u32()) }
}

/// Waits on a NUMA double word.
///
/// `flags` is narrowed with [`FutexFlags::for_numa_u32`]: size and NUMA are
/// forced on, and only `FUTEX2_PRIVATE` and `FUTEX2_MPOL` are kept. The kernel
/// may store the resolved node into `word.node`.
///
/// # Errors
/// Returns the same syscall errors as `sys_futex_wait`.
///
/// # Panics
/// Does not panic.
#[inline]
pub fn futex_wait_numa_u32(
    word: &FutexNumaU32,
    expected: u32,
    mask: u64,
    flags: FutexFlags,
    timeout: Option<&KernelTimespec>,
    clockid: libc::clockid_t,
) -> Result<()> {
    // SAFETY: `word` is a live 8-byte-aligned writable NUMA pair for the duration of this call.
    unsafe {
        sys_futex_wait(
            word.as_ptr(),
            u64::from(expected),
            mask,
            flags.for_numa_u32(),
            timeout,
            clockid,
        )
    }
}

/// Wakes waiters on a NUMA double word.
///
/// `flags` is narrowed with [`FutexFlags::for_numa_u32`]. The kernel may store
/// the resolved node into `word.node` on this wake.
///
/// # Errors
/// Returns the same syscall errors as `sys_futex_wake`.
///
/// # Panics
/// Does not panic.
#[inline]
pub fn futex_wake_numa_u32(
    word: &FutexNumaU32,
    mask: u64,
    nr: i32,
    flags: FutexFlags,
) -> Result<u32> {
    // SAFETY: `word` is a live 8-byte-aligned writable NUMA pair for the duration of this call.
    unsafe { sys_futex_wake(word.as_ptr(), mask, nr, flags.for_numa_u32()) }
}

/// Requeues from one 32-bit word to another.
///
/// `expected` is compared against `source`. `nr_wake` waiters are woken on the
/// source; `nr_requeue` waiters move to `destination`. `flags` is narrowed with
/// [`FutexFlags::for_u32`] and applied to both records.
///
/// # Errors
/// Returns the same syscall errors as `sys_futex_requeue`.
///
/// # Panics
/// Does not panic.
#[inline]
pub fn futex_requeue_u32(
    source: &FutexWord,
    destination: &FutexWord,
    expected: u32,
    nr_wake: i32,
    nr_requeue: i32,
    flags: FutexFlags,
) -> Result<u32> {
    let flags = flags.for_u32().bits();
    let waiters = [
        FutexWaitV::new()
            .uaddr(source.as_ptr() as u64)
            .val(u64::from(expected))
            .flags(flags),
        FutexWaitV::new()
            .uaddr(destination.as_ptr() as u64)
            .flags(flags),
    ];
    // SAFETY: Both words are live and 4-byte aligned. The shared flag word cannot request NUMA.
    unsafe { sys_futex_requeue(&waiters, 0, nr_wake, nr_requeue) }
}

/// Requeues between two NUMA double words.
///
/// `flags` is narrowed with [`FutexFlags::for_numa_u32`] and applied to both
/// records. Both node words are writable. The kernel may store a resolved node
/// into either word while parsing the records.
///
/// # Errors
/// Returns the same syscall errors as `sys_futex_requeue`.
///
/// # Panics
/// Does not panic.
#[inline]
pub fn futex_requeue_numa_u32(
    source: &FutexNumaU32,
    destination: &FutexNumaU32,
    expected: u32,
    nr_wake: i32,
    nr_requeue: i32,
    flags: FutexFlags,
) -> Result<u32> {
    let flags = flags.for_numa_u32().bits();
    let waiters = [
        FutexWaitV::new()
            .uaddr(source.as_ptr() as u64)
            .val(u64::from(expected))
            .flags(flags),
        FutexWaitV::new()
            .uaddr(destination.as_ptr() as u64)
            .flags(flags),
    ];
    // SAFETY: Both NUMA pairs are live, 8-byte aligned, and writable for the call.
    unsafe { sys_futex_requeue(&waiters, 0, nr_wake, nr_requeue) }
}

/// Waits on records borrowed from live futex words.
///
/// The syscall flag word is zero. Each record must already carry a valid size
/// and matching private or shared key.
///
/// # Errors
/// Returns `EINVAL` when `waiters` is empty or longer than 128. Otherwise
/// returns the same errors as `sys_futex_waitv`.
///
/// # Panics
/// Does not panic.
#[inline]
pub fn futex_waitv(
    waiters: &[FutexWaiter<'_>],
    timeout: Option<&KernelTimespec>,
    clockid: libc::clockid_t,
) -> Result<usize> {
    if waiters.is_empty() || waiters.len() > WAITV_MAX {
        return Err(reject("futex_waitv"));
    }
    let mut records = [FutexWaitV::new(); WAITV_MAX];
    let len = waiters.len();
    for (slot, waiter) in records.iter_mut().zip(waiters.iter()) {
        *slot = waiter.as_waitv();
    }
    // SAFETY: Each record was built from a word borrowed for this call, and `len` is in range.
    unsafe { sys_futex_waitv(&records[..len], 0, timeout, clockid) }
}
