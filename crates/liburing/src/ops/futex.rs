//! Linux 6.7+ futex2 SQE preparation for shared-memory event loops.
//!
//! Preparation performs no syscall and transfers no operand ownership. Shared
//! mappings use the default shared key; add `FUTEX2_PRIVATE` only for private keys.
//! NUMA operands are prepared through the dedicated helpers: the kernel writes
//! the node word on both wait and wake.

use crate::backend::{
    RawSqe,
    sys::sqe::{IORING_OP_FUTEX_WAIT, IORING_OP_FUTEX_WAITV, IORING_OP_FUTEX_WAKE},
};
pub use crate::futex2::{FutexFlags, FutexNumaU32, FutexWaitV, FutexWaiter, FutexWord};

/// Selects a 32-bit futex word in the futex2 flags namespace.
pub const FUTEX2_SIZE_U32: u32 = 0x02;
/// Selects a process-private key instead of a shared-mapping futex key.
pub const FUTEX2_PRIVATE: u32 = 128;
/// Matches every bit of a 32-bit futex waiter's wake mask.
pub const FUTEX_BITSET_MATCH_ANY: u64 = u32::MAX as u64;

const _: () = {
    assert!(IORING_OP_FUTEX_WAIT == 51);
    assert!(IORING_OP_FUTEX_WAKE == 52);
    assert!(IORING_OP_FUTEX_WAITV == 53);
    assert!(FUTEX2_SIZE_U32 == FutexFlags::SIZE_U32.bits());
    assert!(FUTEX2_PRIVATE == FutexFlags::PRIVATE.bits());
};

/// Fills one futex SQE without touching caller identity, SQE flags, or personality.
///
/// # Safety
/// `sqe` must address initialized, exclusively writable, unpublished SQE storage.
#[inline(always)]
unsafe fn write_futex_sqe(
    sqe: *mut RawSqe,
    opcode: u8,
    fd: i32,
    addr: u64,
    off: u64,
    len: u32,
    addr3: u64,
) {
    // SAFETY: The caller owns the unpublished SQE. Operand fields are replaced in place so the
    // existing user_data, IOSQE flags, and personality survive.
    unsafe {
        let sqe = &mut *sqe;
        sqe.opcode = opcode;
        sqe.ioprio = 0;
        sqe.fd = fd;
        sqe.off = off;
        sqe.addr = addr;
        sqe.len = len;
        sqe.operation_flags = 0;
        sqe.buf_index = 0;
        sqe.splice_fd_in = 0;
        sqe.addr3 = addr3;
        sqe.pad2 = 0;
    }
}

/// Prepares a wait for a matching 32-bit futex value and wake mask.
///
/// `futex_flags` uses futex2 flags, including `FUTEX2_SIZE_U32`, rather than
/// legacy `FUTEX_WAIT` command bits. The stored flag word is
/// `FUTEX2_SIZE_U32 | (futex_flags & FUTEX2_PRIVATE)`. NUMA, MPOL, and other
/// sizes are cleared: this operand is a 4-byte word and does not own a following
/// node word. A value mismatch completes with `-EAGAIN`. Caller identity, SQE
/// flags, and personality are preserved. A NUMA double word must use
/// `prep_futex_wait_numa_u32`.
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
    let flags = FutexFlags::u32_flag_bits(futex_flags);
    // SAFETY: The caller exclusively owns the SQE and retains the aligned futex mapping through
    // completion. The stored flags do not request a NUMA node store.
    unsafe {
        write_futex_sqe(
            sqe,
            IORING_OP_FUTEX_WAIT,
            flags as i32,
            futex as u64,
            expected,
            0,
            mask,
        );
    }
}

/// Prepares a wake of at most `max_wake` waiters whose bitsets intersect `mask`.
///
/// The stored flag word keeps only `FUTEX2_SIZE_U32` and `FUTEX2_PRIVATE`, matching
/// [`FutexFlags::for_u32`]. Use the same private-key bit as the waiters. Application
/// payload publication and observation still require the caller's atomic memory
/// ordering. Caller identity, SQE flags, and personality are preserved.
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
/// each separate wait operand until that wait's own final CQE. NUMA wakes must use
/// `prep_futex_wake_numa_u32`: the kernel writes the node word on wake as well.
#[inline(always)]
pub unsafe fn prep_futex_wake(
    sqe: *mut RawSqe,
    futex: *const u32,
    max_wake: u64,
    mask: u64,
    futex_flags: u32,
) {
    let flags = FutexFlags::u32_flag_bits(futex_flags);
    // SAFETY: The caller owns the unpublished SQE and retains the aligned mapping through its final
    // CQE. The stored flags do not request a NUMA node store.
    unsafe {
        write_futex_sqe(
            sqe,
            IORING_OP_FUTEX_WAKE,
            flags as i32,
            futex as u64,
            max_wake,
            0,
            mask,
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
/// NUMA descriptors must name writable 8-byte pairs.
#[inline(always)]
pub unsafe fn prep_futex_waitv(sqe: *mut RawSqe, waiters: *const FutexWaitV, count: u32) {
    // SAFETY: The caller owns the SQE and pins the immutable vector and all futex words through
    // completion.
    unsafe {
        write_futex_sqe(sqe, IORING_OP_FUTEX_WAITV, 0, waiters as u64, 0, count, 0);
    }
}

/// Prepares a wait on a writable NUMA double word.
///
/// The stored flag word forces `FUTEX2_SIZE_U32 | FUTEX2_NUMA` and keeps only
/// `FUTEX2_PRIVATE` and `FUTEX2_MPOL` from `futex_flags`. The kernel stores the
/// resolved node into `futex.node` when that word is `FUTEX_NO_NODE`. Caller
/// identity, SQE flags, and personality are preserved.
///
/// # Errors
/// Preparation reports no errors; kernel validation and wait results arrive in the CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must address initialized, exclusively writable, unpublished SQE storage.
/// `futex` must address an 8-byte-aligned `FutexNumaU32` in writable memory retained
/// through the final CQE, including staging, SQPOLL consumption, and cancellation.
#[inline(always)]
pub unsafe fn prep_futex_wait_numa_u32(
    sqe: *mut RawSqe,
    futex: *mut FutexNumaU32,
    expected: u64,
    mask: u64,
    futex_flags: u32,
) {
    let flags = FutexFlags::numa_flag_bits(futex_flags);
    // SAFETY: The caller owns the SQE and retains the writable NUMA pair through completion.
    unsafe {
        write_futex_sqe(
            sqe,
            IORING_OP_FUTEX_WAIT,
            flags as i32,
            futex as u64,
            expected,
            0,
            mask,
        );
    }
}

/// Prepares a wake on a writable NUMA double word.
///
/// The stored flag word forces `FUTEX2_SIZE_U32 | FUTEX2_NUMA` and keeps only
/// `FUTEX2_PRIVATE` and `FUTEX2_MPOL`. It must use the same private-key bit as
/// the waiters. The kernel stores the resolved node on wake when `futex.node`
/// is `FUTEX_NO_NODE`. Caller identity, SQE flags, and personality are preserved.
///
/// # Errors
/// Preparation reports no errors; the CQE contains the wake count or a negative errno.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must address initialized, exclusively writable, unpublished SQE storage.
/// `futex` must address an 8-byte-aligned `FutexNumaU32` in writable memory retained
/// through this wake's final CQE. Retain each separate wait operand until that wait's
/// own final CQE.
#[inline(always)]
pub unsafe fn prep_futex_wake_numa_u32(
    sqe: *mut RawSqe,
    futex: *mut FutexNumaU32,
    max_wake: u64,
    mask: u64,
    futex_flags: u32,
) {
    let flags = FutexFlags::numa_flag_bits(futex_flags);
    // SAFETY: The caller owns the SQE and retains the writable NUMA pair through its final CQE.
    unsafe {
        write_futex_sqe(
            sqe,
            IORING_OP_FUTEX_WAKE,
            flags as i32,
            futex as u64,
            max_wake,
            0,
            mask,
        );
    }
}
