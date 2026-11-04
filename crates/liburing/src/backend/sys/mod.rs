//! Native Linux x86_64 little-endian UAPI and raw syscall contracts.
//!
//! Raw calls return a nonnegative kernel result or negative errno. They neither
//! retry interruptions nor discover capabilities, own resources, or enforce the
//! kernel policy gate automatically. Callers retain operands for kernel use.
use std::sync::OnceLock;

use uarch::prelude::*;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("native UAPI requires Linux x86_64 little-endian");

pub mod cqe;
pub mod futex;
pub mod params;
pub mod query_bpf;
pub mod register;
pub mod sqe;
pub mod zcrx;

use futex::FutexWaitv;
use params::{IoUringParams, KernelTimespec};
pub const SYS_IO_URING_SETUP: libc::c_long = 425;
const _: () = assert!(SYS_IO_URING_SETUP == libc::SYS_io_uring_setup);
pub const SYS_IO_URING_ENTER: libc::c_long = 426;
const _: () = assert!(SYS_IO_URING_ENTER == libc::SYS_io_uring_enter);
pub const SYS_IO_URING_REGISTER: libc::c_long = 427;
const _: () = assert!(SYS_IO_URING_REGISTER == libc::SYS_io_uring_register);
pub const SYS_FUTEX_WAITV: libc::c_long = 449;
const _: () = assert!(SYS_FUTEX_WAITV == libc::SYS_futex_waitv);
// libc 0.2.191 omits these three names; the target-specific numbers are
// independently checked against asm/unistd.h by the UAPI integration test.
pub const SYS_FUTEX_WAKE: libc::c_long = 454;
pub const SYS_FUTEX_WAIT: libc::c_long = 455;
pub const SYS_FUTEX_REQUEUE: libc::c_long = 456;

/// Reads the calling thread's positive Linux errno immediately after a failed libc call.
/// # Errors
/// Does not return errors.
/// # Panics
/// Does not panic.
#[cold_sink]
pub fn last_os_errno() -> i32 {
    // SAFETY: On Linux libc returns a valid pointer to this thread's initialized errno cell.
    unsafe { *libc::__errno_location() }
}

#[hot_inline]
fn syscall_result(result: libc::c_long) -> i32 {
    if result == -1 {
        -last_os_errno()
    } else {
        result as i32
    }
}

/// Creates a ring; the result is a VFS fd or registered index according to setup flags.
///
/// Returns negative errno on failure, including EINTR; no retry occurs.
/// # Errors
/// Reports kernel failures as negative errno return values.
/// # Panics
/// Does not panic.
/// # Safety
/// `params` must be exclusively readable/writable for this call. NO_MMAP addresses must name
/// suitably aligned live allocations retained through ring teardown. The caller must adopt the
/// returned fd/index and release it in the correct namespace.
#[hot_inline]
pub unsafe fn sys_io_uring_setup(entries: u32, params: *mut IoUringParams) -> i32 {
    // SAFETY: The caller guarantees argument layout, accessibility and all kernel operand
    // lifetimes.
    syscall_result(unsafe { libc::syscall(SYS_IO_URING_SETUP, entries as libc::c_long, params) })
}

/// Submits or waits once; the result counts kernel-consumed submission units.
///
/// Returns negative errno on failure, including EINTR; no retry occurs.
/// # Errors
/// Reports kernel failures as negative errno return values.
/// # Panics
/// Does not panic.
/// # Safety
/// The ring handle must use the flags-selected namespace. Publish initialized SQEs before entry and
/// retain all referenced resources through terminal completion. `arg` must match the selected
/// signal/extended argument ABI and remain live for the call; registered argument indexes follow
/// their region lifetime contract.
#[hot_inline]
pub unsafe fn sys_io_uring_enter(
    fd: i32,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    arg: *const libc::c_void,
    argsz: usize,
) -> i32 {
    // SAFETY: The caller guarantees argument layout, accessibility and all kernel operand
    // lifetimes.
    syscall_result(unsafe {
        libc::syscall(
            SYS_IO_URING_ENTER,
            fd as libc::c_long,
            to_submit as libc::c_long,
            min_complete as libc::c_long,
            flags as libc::c_long,
            arg,
            argsz as libc::c_long,
        )
    })
}

/// Issues one control operation without interpreting opcode-specific count or result units.
///
/// Returns negative errno on failure, including EINTR; no retry occurs.
/// # Errors
/// Reports kernel failures as negative errno return values.
/// # Panics
/// Does not panic.
/// # Safety
/// `fd` and opcode tagging must select the correct ring namespace. `arg` must have the
/// opcode-specific layout, accessibility, alignment and extent for `nr_args`. Retain registered
/// memory and descriptors until confirmed release; adopt returned resources and account for partial
/// success.
#[hot_inline]
pub unsafe fn sys_io_uring_register(
    fd: i32,
    opcode: u32,
    arg: *mut libc::c_void,
    nr_args: u32,
) -> i32 {
    // SAFETY: The caller guarantees argument layout, accessibility and all kernel operand
    // lifetimes.
    syscall_result(unsafe {
        libc::syscall(
            SYS_IO_URING_REGISTER,
            fd as libc::c_long,
            opcode as libc::c_long,
            arg,
            nr_args as libc::c_long,
        )
    })
}

/// Waits once on a futex with an optional absolute timeout; this call can block.
///
/// Returns negative errno on failure, including EINTR; no retry occurs.
/// # Errors
/// Reports kernel failures as negative errno return values.
/// # Panics
/// Does not panic.
/// # Safety
/// Retain the correctly aligned futex mapping and optional readable timeout throughout this call.
/// NUMA doubles storage/alignment and permits kernel writes to the node word. Concurrent accesses
/// require a compatible atomic protocol. Do not call from an RTC hook.
#[hot_inline]
pub unsafe fn sys_futex_wait(
    uaddr: *mut libc::c_void,
    val: libc::c_ulong,
    mask: libc::c_ulong,
    flags: u32,
    timeout: *const KernelTimespec,
    clockid: libc::clockid_t,
) -> i32 {
    // SAFETY: The caller guarantees argument layout, accessibility and all kernel operand
    // lifetimes.
    syscall_result(unsafe {
        libc::syscall(
            SYS_FUTEX_WAIT,
            uaddr,
            val as libc::c_long,
            mask as libc::c_long,
            flags as libc::c_long,
            timeout,
            clockid as libc::c_long,
        )
    })
}

/// Wakes matching futex waiters; the result is the number woken.
///
/// Returns negative errno on failure, including EINTR; no retry occurs.
/// # Errors
/// Reports kernel failures as negative errno return values.
/// # Panics
/// Does not panic.
/// # Safety
/// Retain the correctly aligned mapping for the call. NUMA requires the doubled storage/alignment
/// and a kernel-writable node word even for wake. Follow a compatible atomic protocol; wake alone
/// does not publish application data.
#[hot_inline]
pub unsafe fn sys_futex_wake(
    uaddr: *mut libc::c_void,
    mask: libc::c_ulong,
    nr: i32,
    flags: u32,
) -> i32 {
    // SAFETY: The caller guarantees argument layout, accessibility and all kernel operand
    // lifetimes.
    syscall_result(unsafe {
        libc::syscall(
            SYS_FUTEX_WAKE,
            uaddr,
            mask as libc::c_long,
            nr as libc::c_long,
            flags as libc::c_long,
        )
    })
}

/// Requeues from two descriptors; top-level flags are separate from per-record flags.
///
/// Returns negative errno on failure, including EINTR; no retry occurs.
/// # Errors
/// Reports kernel failures as negative errno return values.
/// # Panics
/// Does not panic.
/// # Safety
/// `waiters` must name two initialized readable records throughout the call. Both futex mappings
/// must remain live, aligned and atomically accessible; NUMA node words must be writable. Source
/// comparison and destination flags follow the selected kernel ABI.
#[hot_inline]
pub unsafe fn sys_futex_requeue(
    waiters: *const FutexWaitv,
    flags: u32,
    nr_wake: i32,
    nr_requeue: i32,
) -> i32 {
    // SAFETY: The caller guarantees argument layout, accessibility and all kernel operand
    // lifetimes.
    syscall_result(unsafe {
        libc::syscall(
            SYS_FUTEX_REQUEUE,
            waiters,
            flags as libc::c_long,
            nr_wake as libc::c_long,
            nr_requeue as libc::c_long,
        )
    })
}

/// Waits on a vector with an optional absolute timeout; returns one awakened index.
///
/// Returns negative errno on failure, including EINTR; no retry occurs.
/// # Errors
/// Reports kernel failures as negative errno return values.
/// # Panics
/// Does not panic.
/// # Safety
/// Retain `nr_futexes` initialized readable records, their aligned futex mappings and the optional
/// readable timeout for the call. NUMA node words must be writable. Coordinate concurrent access
/// atomically. This call can block and must not run inside RTC hooks.
#[hot_inline]
pub unsafe fn sys_futex_waitv(
    waiters: *const FutexWaitv,
    nr_futexes: u32,
    flags: u32,
    timeout: *const KernelTimespec,
    clockid: libc::clockid_t,
) -> i32 {
    // SAFETY: The caller guarantees argument layout, accessibility and all kernel operand
    // lifetimes.
    syscall_result(unsafe {
        libc::syscall(
            SYS_FUTEX_WAITV,
            waiters,
            nr_futexes as libc::c_long,
            flags as libc::c_long,
            timeout,
            clockid as libc::c_long,
        )
    })
}

/// Checks a Linux release string against the project baseline; this is not feature discovery.
/// # Errors
/// Returns UnsupportedKernelVersion below 6.16 or InvalidConfig for a malformed release.
/// # Panics
/// Does not panic.
pub fn validate_kernel_release(release: &[u8]) -> crate::Result<()> {
    fn component(bytes: &[u8]) -> Option<(u32, usize)> {
        let mut value = 0u32;
        let mut len = 0;
        for &byte in bytes.iter().take_while(|byte| byte.is_ascii_digit()) {
            value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
            len += 1;
        }
        (len != 0).then_some((value, len))
    }
    let invalid = || crate::UringError::InvalidConfig("malformed Linux kernel release");
    let (major, offset) = component(release).ok_or_else(invalid)?;
    if release.get(offset) != Some(&b'.') {
        return Err(invalid());
    }
    let (minor, consumed) = component(&release[offset + 1..]).ok_or_else(invalid)?;
    if let Some(next) = release.get(offset + 1 + consumed)
        && !matches!(*next, b'.' | b'-' | b'+')
    {
        return Err(invalid());
    }
    if (major, minor) < (6, 16) {
        return Err(crate::UringError::UnsupportedKernelVersion {
            detected_major: major,
            detected_minor: minor,
            required_major: 6,
            required_minor: 16,
        });
    }
    Ok(())
}

/// Caches the process-wide Linux >=6.16 policy check, without caching ring capabilities.
/// # Errors
/// Returns uname errors, invalid release text, or UnsupportedKernelVersion.
/// # Panics
/// Does not panic.
pub fn ensure_kernel_baseline_6_16() -> crate::Result<()> {
    static BASELINE: OnceLock<crate::Result<()>> = OnceLock::new();
    *BASELINE.get_or_init(|| {
        // SAFETY: utsname consists of character arrays; all-zero bytes are valid initialized
        // storage.
        let mut name = unsafe { core::mem::zeroed::<libc::utsname>() };
        // SAFETY: The exclusive stack record is initialized, correctly aligned and writable in
        // full.
        if unsafe { libc::uname(&raw mut name) } < 0 {
            return Err(crate::UringError::cold_syscall("uname", last_os_errno()));
        }
        // SAFETY: Successful uname supplies a NUL-terminated release array within this live record.
        let release = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) };
        validate_kernel_release(release.to_bytes())
    })
}
