//! Allocation-free network, cancellation, and poll SQE builders.
//!
//! Fixed-buffer file reads and writes live in [`super::fs`] and are re-exported
//! here so existing `ops::net` callers keep compiling.
//!
//! Preparation only initializes an exclusively owned SQE. Submission and resource
//! retention belong to the caller. Cancellation never shortens the target's DMA
//! lifetime: retain its buffers until the target's final CQE, and zero-copy send
//! storage until its required notification CQE. Set `IOSQE_FIXED_FILE` separately
//! when an ordinary `fd` argument contains a registered-file slot index.

use std::os::fd::RawFd;

use io_uring::{opcode, types};

pub use super::fs::{prep_read_fixed, prep_write_fixed};
use super::write_entry;
use crate::{
    backend::RawSqe,
    id::{BufferGroupId, BufferId, OperationId, UringFileSlot},
};

/// Prepares Send from an existing registered fixed-buffer region.
/// Ordinary Send addresses the stable registered memory directly; its pool token
/// retains ownership until completion. SendZc additionally uses the kernel index.
/// # Errors
/// Preparation is infallible; kernel errors arrive in the CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// SQE storage must be exclusive and initialized. The immutable payload must lie
/// in the registered buffer and remain retained through the final send CQE.
pub unsafe fn prep_send_fixed(sqe: *mut RawSqe, fd: RawFd, buf: *const u8, len: usize, flags: i32) {
    // SAFETY: Caller provides the stated SQE and registered DMA ownership.
    unsafe {
        prep_send(sqe, fd, buf, len, flags);
    }
}

/// Prepares SendZc using an existing registered fixed-buffer region.
/// # Errors
/// Preparation is infallible; kernel errors arrive in the CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// SQE storage must be exclusive and initialized. Retain the registered payload
/// through the final main CQE and its notification when MORE requests one.
pub unsafe fn prep_send_zc_fixed(
    sqe: *mut RawSqe,
    fd: RawFd,
    buf: *const u8,
    len: usize,
    flags: i32,
    zc_flags: u32,
    buffer: BufferId,
) {
    // SAFETY: Caller retains the exact registered allocation through notification.
    unsafe {
        prep_send_zc(sqe, fd, buf, len, flags, zc_flags);
        (*sqe).ioprio |= 4;
        (*sqe).buf_index = buffer.raw();
    }
}

/// Prepares a socket send of `len` bytes with socket message `flags`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `len` must fit `u32`; larger values are truncated by
/// the Linux entry encoding. `buf` must remain readable for `len` bytes until the target final CQE.
pub unsafe fn prep_send(sqe: *mut RawSqe, fd: RawFd, buf: *const u8, len: usize, flags: i32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::Send::new(types::Fd(fd), buf, len as u32)
                .flags(flags)
                .build(),
        );
    }
}

/// Prepares a zero-copy socket send with message and zero-copy flags.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `len` must fit `u32`; larger values are truncated by
/// the Linux entry encoding. `buf` must remain readable for `len` bytes until the kernel
/// relinquishes it. When the send CQE carries `IORING_CQE_F_MORE`, retain storage through its
/// `IORING_CQE_F_NOTIF` notification, including after cancellation.
pub unsafe fn prep_send_zc(
    sqe: *mut RawSqe,
    fd: RawFd,
    buf: *const u8,
    len: usize,
    flags: i32,
    zc_flags: u32,
) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::SendZc::new(types::Fd(fd), buf, len as u32)
                .flags(flags)
                .zc_flags(zc_flags as u16)
                .build(),
        );
    }
}

/// Prepares a scatter/gather socket send described by `msg`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `msg`, its iovecs, address, control data, and payloads must remain valid
/// and readable until the target final CQE.
pub unsafe fn prep_sendmsg(sqe: *mut RawSqe, fd: RawFd, msg: *const libc::msghdr, flags: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::SendMsg::new(types::Fd(fd), msg)
                .flags(flags)
                .build(),
        );
    }
}

/// Prepares a socket receive into `len` writable bytes.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `len` must fit `u32`; larger values are truncated by
/// the Linux entry encoding. `buf` must remain exclusively writable for `len` bytes until the
/// target final CQE, including while cancellation is pending.
pub unsafe fn prep_recv(sqe: *mut RawSqe, fd: RawFd, buf: *mut u8, len: usize, flags: i32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::Recv::new(types::Fd(fd), buf, len as u32)
                .flags(flags)
                .build(),
        );
    }
}

/// Prepares multishot receive using kernel selection from `group`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `group` must remain registered through the receive
/// final CQE; an empty group may complete with `-ENOBUFS`. Each selected buffer
/// stays unavailable to the caller until its CQE grants exclusive access.
pub unsafe fn prep_recv_multishot(sqe: *mut RawSqe, fd: RawFd, group: BufferGroupId, flags: i32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::RecvMulti::new(types::Fd(fd), group.raw())
                .flags(flags)
                .build(),
        );
    }
}

/// Prepares a scatter/gather receive into the writable `msg` structure.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `msg`, its iovecs, address, control data, and payloads must remain valid
/// and exclusively writable until the target final CQE.
pub unsafe fn prep_recvmsg(sqe: *mut RawSqe, fd: RawFd, msg: *mut libc::msghdr, flags: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::RecvMsg::new(types::Fd(fd), msg)
                .flags(flags)
                .build(),
        );
    }
}

/// Prepares a connection to the `addrlen`-byte socket address.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `addr` must describe a valid address of `addrlen` bytes and remain
/// readable until the target final CQE.
pub unsafe fn prep_connect(
    sqe: *mut RawSqe,
    fd: RawFd,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::Connect::new(types::Fd(fd), addr, addrlen).build(),
        );
    }
}

/// Prepares one accept with optional peer-address output and accept flags.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `addr` and `addrlen` must either both be null or describe exclusive
/// writable peer-address output that remains alive until the final CQE.
pub unsafe fn prep_accept(
    sqe: *mut RawSqe,
    fd: RawFd,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
    flags: i32,
) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::Accept::new(types::Fd(fd), addr, addrlen)
                .flags(flags)
                .build(),
        );
    }
}

/// Prepares repeated accepts with optional peer-address output.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `addr` and `addrlen` must both be null or remain exclusively writable
/// until the multishot final CQE; shared output may be overwritten by later
/// accepts. Every nonnegative completion descriptor must be owned or closed.
pub unsafe fn prep_multishot_accept(
    sqe: *mut RawSqe,
    fd: RawFd,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
    flags: i32,
) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::Accept::new(types::Fd(fd), addr, addrlen)
                .flags(flags)
                .build(),
        );
        (*sqe).ioprio |= 1;
    }
}

/// Prepares cancellation of the operation identified by `target`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The target user-data namespace and cancellation flags must identify the
/// intended operation. A successful cancel CQE does not authorize releasing
/// target resources; wait for the target final CQE.
pub unsafe fn prep_cancel(sqe: *mut RawSqe, target: OperationId, flags: i32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(sqe, opcode::AsyncCancel::new(target.raw()).build());
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares cancellation matching `fd` and the supplied cancel flags.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `fd` and flags must identify the intended descriptor or registered-file
/// index. Retain every affected resource until its own target final CQE.
pub unsafe fn prep_cancel_fd(sqe: *mut RawSqe, fd: RawFd, flags: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(sqe, opcode::AsyncCancel::new(0).build());
        (*sqe).fd = fd;
        (*sqe).operation_flags = flags | 2;
    }
}

/// Prepares one readiness completion for the poll event mask.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The descriptor must refer to the intended open file at submission.
/// Coordinate descriptor closing and reuse with the operation lifetime.
pub unsafe fn prep_poll_add(sqe: *mut RawSqe, fd: RawFd, poll_mask: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(sqe, opcode::PollAdd::new(types::Fd(fd), poll_mask).build());
    }
}

/// Prepares repeated readiness completions for the poll event mask.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The descriptor must identify the intended file. Keep its ownership
/// coordinated through the poll final CQE, including after cancellation.
pub unsafe fn prep_poll_multishot(sqe: *mut RawSqe, fd: RawFd, poll_mask: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(
            sqe,
            opcode::PollAdd::new(types::Fd(fd), poll_mask)
                .multi(true)
                .build(),
        );
    }
}

/// Prepares removal of the poll identified by `target`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `target` must identify the intended poll. Its removal CQE alone does
/// not prove delivery of the target final CQE.
pub unsafe fn prep_poll_remove(sqe: *mut RawSqe, target: OperationId) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(sqe, opcode::PollRemove::new(target.raw()).build());
    }
}

/// Prepares closing an ordinary OS file descriptor.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The caller must transfer close responsibility exactly once and ensure
/// prior operations no longer need this descriptor before close executes.
pub unsafe fn prep_close(sqe: *mut RawSqe, fd: RawFd) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(sqe, opcode::Close::new(types::Fd(fd)).build());
    }
}

/// Prepares closing a registered-file slot without closing its source fd.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Panics if `slot.raw() == u32::MAX`: the direct-close encoding adds one to
/// the index, which wraps to zero and makes the kernel treat the request as an
/// ordinary close of descriptor 0 instead of a registered-file close.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `slot` must name a live registered file. Retire prior operations before
/// close executes and recycle the table slot only after successful close CQE.
/// Do not set `IOSQE_FIXED_FILE` on this SQE: a direct close already targets the
/// registered file, and the flag makes the request complete with `-EBADF`.
pub unsafe fn prep_close_direct(sqe: *mut RawSqe, slot: UringFileSlot) {
    assert_ne!(
        slot.raw(),
        u32::MAX,
        "slot u32::MAX cannot be encoded as a direct close"
    );
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        write_entry(sqe, opcode::Close::new(types::Fd(0)).build());
        (*sqe).splice_fd_in = (slot.raw() + 1) as i32;
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use super::*;

    #[test]
    fn close_direct_encodes_slot_zero_as_index_one() {
        // SAFETY: An all-zero SQE is valid initialized storage; the helper
        // initializes the fields read below.
        let mut sqe = unsafe { MaybeUninit::<RawSqe>::zeroed().assume_init() };
        // SAFETY: Exclusive initialized SQE storage.
        unsafe { prep_close_direct(&mut sqe, UringFileSlot(0)) };
        assert_eq!(sqe.fd, 0);
        assert_eq!(sqe.splice_fd_in, 1);
    }

    #[test]
    #[should_panic(expected = "u32::MAX")]
    fn close_direct_rejects_unrepresentable_slot() {
        // SAFETY: An all-zero SQE is valid initialized storage; the slot is
        // rejected before any field is encoded.
        let mut sqe = unsafe { MaybeUninit::<RawSqe>::zeroed().assume_init() };
        // SAFETY: Exclusive initialized SQE storage; the input is deliberately
        // unrepresentable and must panic.
        unsafe { prep_close_direct(&mut sqe, UringFileSlot(u32::MAX)) };
    }
}
