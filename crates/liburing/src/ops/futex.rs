//! Linux 6.7+ futex2 SQE preparation for shared-memory event loops.
//!
//! Preparation performs no syscall and transfers no operand ownership. Shared
//! mappings use the default shared key; add `FUTEX2_PRIVATE` only for private keys.

pub use io_uring::types::FutexWaitV;

use super::write_entry;
use crate::backend::RawSqe;

/// Selects a 32-bit futex word in the futex2 flags namespace.
pub const FUTEX2_SIZE_U32: u32 = 0x02;
/// Selects a process-private key instead of a shared-mapping futex key.
pub const FUTEX2_PRIVATE: u32 = 128;
/// Matches every bit of a 32-bit futex waiter's wake mask.
pub const FUTEX_BITSET_MATCH_ANY: u64 = u32::MAX as u64;

/// Prepares a wait for a matching 32-bit futex value and wake mask.
///
/// `futex_flags` uses futex2 flags, including `FUTEX2_SIZE_U32`, rather than
/// legacy `FUTEX_WAIT` command bits. A value mismatch completes with `-EAGAIN`.
/// Caller identity, SQE flags, and personality are preserved.
///
/// # Errors
/// Preparation reports no errors; kernel validation and wait results arrive in the CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must address initialized, exclusively writable, unpublished SQE storage.
/// `futex` must address a 4-byte-aligned, readable atomic word in a mapping retained
/// through the final target CQE, including staging, SQPOLL consumption, and cancellation.
/// Concurrent accesses must follow the caller's atomic shared-state protocol.
#[inline(always)]
pub unsafe fn prep_futex_wait(
    sqe: *mut RawSqe,
    futex: *const u32,
    expected: u64,
    mask: u64,
    futex_flags: u32,
) {
    // SAFETY: The caller exclusively owns the SQE and retains the aligned futex mapping through
    // completion.
    unsafe {
        write_entry(
            sqe,
            io_uring::opcode::FutexWait::new(futex, expected, mask, futex_flags).build(),
        );
    }
}

/// Prepares a wake of at most `max_wake` waiters whose bitsets intersect `mask`.
///
/// Use the same futex2 size/private-key flags as the waiters. Application payload
/// publication and observation still require the caller's atomic memory ordering.
/// Caller identity, SQE flags, and personality are preserved.
///
/// # Errors
/// Preparation reports no errors; the CQE contains the wake count or a negative errno.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must address initialized, exclusively writable, unpublished SQE storage.
/// `futex` must address a 4-byte-aligned atomic word in a readable mapping retained
/// through this wake's final CQE, including staging and SQPOLL consumption. Retain
/// each separate wait operand until that wait's own final CQE.
#[inline(always)]
pub unsafe fn prep_futex_wake(
    sqe: *mut RawSqe,
    futex: *const u32,
    max_wake: u64,
    mask: u64,
    futex_flags: u32,
) {
    // SAFETY: The caller owns the unpublished SQE and retains the aligned mapping through its final
    // CQE.
    unsafe {
        write_entry(
            sqe,
            io_uring::opcode::FutexWake::new(futex, max_wake, mask, futex_flags).build(),
        );
    }
}

/// Prepares one wait over `count` futex2 descriptors.
///
/// Each descriptor supplies its own address, expected value, and futex2 flags.
/// The successful CQE identifies the awakened descriptor's zero-based index.
/// Caller identity, SQE flags, and personality are preserved.
///
/// # Errors
/// Preparation reports no errors; unsupported operations, invalid vectors, or
/// mismatching values are reported through a negative CQE result.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must address initialized, exclusively writable, unpublished SQE storage.
/// `waiters` must address `count` initialized descriptors in immutable, aligned
/// storage. Retain that array and every referenced aligned atomic word/mapping
/// until the wait's final CQE, including staging, SQPOLL consumption, and cancellation.
/// Use 1..=128 descriptors with flags matching the corresponding waking operations.
#[inline(always)]
pub unsafe fn prep_futex_waitv(sqe: *mut RawSqe, waiters: *const FutexWaitV, count: u32) {
    // SAFETY: The caller owns the SQE and pins the immutable vector and all futex words through
    // completion.
    unsafe {
        write_entry(
            sqe,
            io_uring::opcode::FutexWaitV::new(waiters, count).build(),
        );
    }
}
