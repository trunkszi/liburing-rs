//! Polling, cancellation and timeout preparation without submission side effects.
use std::os::fd::RawFd;

use uarch::prelude::hot_inline;

use super::{KernelTimespec, init_sqe};
use crate::{
    backend::{RawSqe, sys::sqe::*},
    id::OperationId,
};

/// Prepare a no-op without changing the caller-assigned completion identity.
/// # Errors
/// Preparation is infallible; kernel results arrive in the CQE.
/// # Safety
/// `sqe` must point to live, initialized, exclusively writable SQE storage.
/// # Panics
/// Does not panic.
#[hot_inline]
pub unsafe fn prep_nop(sqe: *mut RawSqe) {
    // SAFETY: The caller guarantees exclusive initialized SQE storage.
    unsafe { init_sqe(sqe, IORING_OP_NOP, -1) };
}

/// Prepares cancellation of the operation identified by `target`.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The target user-data namespace and cancellation flags must identify the
/// intended operation. A successful cancel CQE does not authorize releasing
/// target resources; wait for the target final CQE.
#[hot_inline]
pub unsafe fn prep_cancel(sqe: *mut RawSqe, target: OperationId, flags: i32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_ASYNC_CANCEL, -1);
        (*sqe).addr = target.raw();
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares cancellation matching `fd` and the supplied cancel flags.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `fd` and flags must identify the intended descriptor or registered-file
/// index. Retain every affected resource until its own target final CQE.
#[hot_inline]
pub unsafe fn prep_cancel_fd(sqe: *mut RawSqe, fd: RawFd, flags: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_ASYNC_CANCEL, fd);
        (*sqe).operation_flags = flags | 2;
    }
}

/// Prepares one readiness completion for the poll event mask.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The descriptor must refer to the intended open file at submission.
/// Coordinate descriptor closing and reuse with the operation lifetime.
#[hot_inline]
pub unsafe fn prep_poll_add(sqe: *mut RawSqe, fd: RawFd, poll_mask: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_POLL_ADD, fd);
        (*sqe).operation_flags = poll_mask;
    }
}

/// Prepares repeated readiness completions for the poll event mask.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The descriptor must identify the intended file. Keep its ownership
/// coordinated through the poll final CQE, including after cancellation.
#[hot_inline]
pub unsafe fn prep_poll_multishot(sqe: *mut RawSqe, fd: RawFd, poll_mask: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_POLL_ADD, fd);
        (*sqe).operation_flags = poll_mask;
        (*sqe).len = 1;
    }
}

/// Prepares removal of the poll identified by `target`.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `target` must identify the intended poll. Its removal CQE alone does
/// not prove delivery of the target final CQE.
#[hot_inline]
pub unsafe fn prep_poll_remove(sqe: *mut RawSqe, target: OperationId) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_POLL_REMOVE, -1);
        (*sqe).addr = target.raw();
    }
}

/// Prepares NOP128 without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe128 storage.
/// Submit only on SQE128 or mixed-SQE geometry with the full 128-byte extent reserved.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_nop128(sqe: *mut RawSqe128) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(core::ptr::addr_of_mut!((*sqe).base), IORING_OP_NOP128, -1);
        (*sqe).cmd_ext = [0; 64];
    }
}

/// Prepares TIMEOUT without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_timeout(sqe: *mut RawSqe, ts: *const KernelTimespec, count: u32, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_TIMEOUT, -1);
        (*sqe).addr = ts as u64;
        (*sqe).len = 1;
        (*sqe).off = count as u64;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares TIMEOUT_REMOVE without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_timeout_remove(sqe: *mut RawSqe, target: u64, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_TIMEOUT_REMOVE, -1);
        (*sqe).addr = target;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares TIMEOUT_REMOVE without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_timeout_update(
    sqe: *mut RawSqe,
    ts: *const KernelTimespec,
    target: u64,
    flags: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_TIMEOUT_REMOVE, -1);
        (*sqe).addr = target;
        (*sqe).off = ts as u64;
        (*sqe).operation_flags = super::TimeoutOptions::new(flags)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::TimeoutOptions::UPDATE, true))
            .raw();
    }
}

/// Prepares LINK_TIMEOUT without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_link_timeout(sqe: *mut RawSqe, ts: *const KernelTimespec, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_LINK_TIMEOUT, -1);
        (*sqe).addr = ts as u64;
        (*sqe).len = 1;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares POLL_REMOVE without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_poll_update(sqe: *mut RawSqe, old: u64, new: u64, events: u32, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_POLL_REMOVE, -1);
        (*sqe).addr = old;
        (*sqe).off = new;
        (*sqe).len = flags;
        (*sqe).operation_flags = events;
    }
}

/// Prepares EPOLL_CTL without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_epoll_ctl(
    sqe: *mut RawSqe,
    epfd: RawFd,
    fd: RawFd,
    op: i32,
    event: *const libc::epoll_event,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_EPOLL_CTL, epfd);
        (*sqe).addr = event as u64;
        (*sqe).len = op as u32;
        (*sqe).off = fd as u32 as u64;
    }
}

/// Prepares EPOLL_WAIT without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_epoll_wait(
    sqe: *mut RawSqe,
    epfd: RawFd,
    events: *mut libc::epoll_event,
    max_events: u32,
    flags: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_EPOLL_WAIT, epfd);
        (*sqe).addr = events as u64;
        (*sqe).len = max_events;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares ASYNC_CANCEL without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_cancel_user_data(sqe: *mut RawSqe, target: u64, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_ASYNC_CANCEL, -1);
        (*sqe).addr = target;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares ASYNC_CANCEL without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_cancel_any(sqe: *mut RawSqe, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_ASYNC_CANCEL, -1);
        (*sqe).operation_flags = super::CancelOptions::new(flags)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::CancelOptions::ANY, true))
            .raw();
    }
}

/// Prepares ASYNC_CANCEL without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_cancel_fixed_fd(sqe: *mut RawSqe, slot: crate::UringFileSlot, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_ASYNC_CANCEL, slot.raw() as i32);
        (*sqe).operation_flags = super::CancelOptions::new(flags)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::CancelOptions::FD, true))
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::CancelOptions::FD_FIXED, true))
            .raw();
    }
}

/// Prepares ASYNC_CANCEL without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// Pointer operands must cover valid readable or exclusively writable storage of the supplied
/// sizes. If submitted, retain every referenced descriptor, pointer target and registered resource
/// through final kernel use.
#[hot_inline]
pub unsafe fn prep_cancel_op(sqe: *mut RawSqe, opcode: u8, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_ASYNC_CANCEL, -1);
        (*sqe).len = opcode as u32;
        (*sqe).operation_flags = super::CancelOptions::new(flags)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::CancelOptions::OP, true))
            .raw();
    }
}
