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

use uarch::prelude::hot_inline;

use super::init_sqe;
pub use super::{
    fs::{prep_close, prep_close_direct, prep_read_fixed, prep_write_fixed},
    poll_time::{
        prep_cancel, prep_cancel_fd, prep_poll_add, prep_poll_multishot, prep_poll_remove,
    },
};
use crate::{
    backend::{
        RawSqe,
        sys::{register::IoUringRecvmsgOut, sqe::*},
    },
    id::{BufferGroupId, BufferId},
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
#[hot_inline]
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
#[hot_inline]
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
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `len` must fit `u32`; larger values are truncated by
/// the Linux entry encoding. `buf` must remain readable for `len` bytes until the target final CQE.
#[hot_inline]
pub unsafe fn prep_send(sqe: *mut RawSqe, fd: RawFd, buf: *const u8, len: usize, flags: i32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_SEND, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len as u32;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares a zero-copy socket send with message and zero-copy flags.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `len` must fit `u32`; larger values are truncated by
/// the Linux entry encoding. `buf` must remain readable for `len` bytes until the kernel
/// relinquishes it. When the send CQE carries `IORING_CQE_F_MORE`, retain storage through its
/// `IORING_CQE_F_NOTIF` notification, including after cancellation.
#[hot_inline]
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
        init_sqe(sqe, IORING_OP_SEND_ZC, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len as u32;
        (*sqe).operation_flags = flags as u32;
        (*sqe).ioprio = zc_flags as u16;
    }
}

/// Prepares a scatter/gather socket send described by `msg`.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `msg`, its iovecs, address, control data, and payloads must remain valid
/// and readable until the target final CQE.
#[hot_inline]
pub unsafe fn prep_sendmsg(sqe: *mut RawSqe, fd: RawFd, msg: *const libc::msghdr, flags: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_SENDMSG, fd);
        (*sqe).addr = msg as u64;
        (*sqe).len = 1;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares a socket receive into `len` writable bytes.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `len` must fit `u32`; larger values are truncated by
/// the Linux entry encoding. `buf` must remain exclusively writable for `len` bytes until the
/// target final CQE, including while cancellation is pending.
#[hot_inline]
pub unsafe fn prep_recv(sqe: *mut RawSqe, fd: RawFd, buf: *mut u8, len: usize, flags: i32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_RECV, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len as u32;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares multishot receive using kernel selection from `group`.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `group` must remain registered through the receive
/// final CQE; an empty group may complete with `-ENOBUFS`. Each selected buffer
/// stays unavailable to the caller until its CQE grants exclusive access.
#[hot_inline]
pub unsafe fn prep_recv_multishot(sqe: *mut RawSqe, fd: RawFd, group: BufferGroupId, flags: i32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_RECV, fd);
        (*sqe).buf_index = group.raw();
        (*sqe).flags |= crate::backend::IOSQE_BUFFER_SELECT as u8;
        (*sqe).ioprio = crate::backend::IORING_RECV_MULTISHOT;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares a scatter/gather receive into the writable `msg` structure.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `msg`, its iovecs, address, control data, and payloads must remain valid
/// and exclusively writable until the target final CQE.
#[hot_inline]
pub unsafe fn prep_recvmsg(sqe: *mut RawSqe, fd: RawFd, msg: *mut libc::msghdr, flags: u32) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_RECVMSG, fd);
        (*sqe).addr = msg as u64;
        (*sqe).len = 1;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares a connection to the `addrlen`-byte socket address.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `addr` must describe a valid address of `addrlen` bytes and remain
/// readable until the target final CQE.
#[hot_inline]
pub unsafe fn prep_connect(
    sqe: *mut RawSqe,
    fd: RawFd,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_CONNECT, fd);
        (*sqe).addr = addr as u64;
        (*sqe).off = u64::from(addrlen);
    }
}

/// Prepares one accept with optional peer-address output and accept flags.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `addr` and `addrlen` must either both be null or describe exclusive
/// writable peer-address output that remains alive until the final CQE.
#[hot_inline]
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
        init_sqe(sqe, IORING_OP_ACCEPT, fd);
        (*sqe).addr = addr as u64;
        (*sqe).off = addrlen as u64;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares repeated accepts with optional peer-address output.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `addr` and `addrlen` must both be null or remain exclusively writable
/// until the multishot final CQE; shared output may be overwritten by later
/// accepts. Every nonnegative completion descriptor must be owned or closed.
#[hot_inline]
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
        init_sqe(sqe, IORING_OP_ACCEPT, fd);
        (*sqe).addr = addr as u64;
        (*sqe).off = addrlen as u64;
        (*sqe).operation_flags = flags as u32;
        (*sqe).ioprio |= 1;
    }
}

/// Prepares SOCKET without publishing the SQE.
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
pub unsafe fn prep_socket(sqe: *mut RawSqe, domain: i32, kind: i32, protocol: i32, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_SOCKET, domain);
        (*sqe).off = kind as u32 as u64;
        (*sqe).len = protocol as u32;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares BIND without publishing the SQE.
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
pub unsafe fn prep_bind(
    sqe: *mut RawSqe,
    fd: RawFd,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_BIND, fd);
        (*sqe).addr = addr as u64;
        (*sqe).off = len as u64;
    }
}

/// Prepares LISTEN without publishing the SQE.
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
pub unsafe fn prep_listen(sqe: *mut RawSqe, fd: RawFd, backlog: i32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_LISTEN, fd);
        (*sqe).len = backlog as u32;
    }
}

/// Prepares SENDMSG_ZC without publishing the SQE.
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
pub unsafe fn prep_sendmsg_zc(sqe: *mut RawSqe, fd: RawFd, msg: *const libc::msghdr, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_SENDMSG_ZC, fd);
        (*sqe).addr = msg as u64;
        (*sqe).len = 1;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares SHUTDOWN without publishing the SQE.
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
pub unsafe fn prep_shutdown(sqe: *mut RawSqe, fd: RawFd, how: i32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_SHUTDOWN, fd);
        (*sqe).len = how as u32;
    }
}

/// Prepares PROVIDE_BUFFERS without publishing the SQE.
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
pub unsafe fn prep_provide_buffers(
    sqe: *mut RawSqe,
    addr: *mut u8,
    len: u32,
    count: i32,
    group: BufferGroupId,
    first_id: u16,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_PROVIDE_BUFFERS, count);
        (*sqe).addr = addr as u64;
        (*sqe).len = len;
        (*sqe).off = first_id as u64;
        (*sqe).buf_index = group.raw();
    }
}

/// Prepares REMOVE_BUFFERS without publishing the SQE.
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
pub unsafe fn prep_remove_buffers(sqe: *mut RawSqe, count: i32, group: BufferGroupId) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_REMOVE_BUFFERS, count);
        (*sqe).buf_index = group.raw();
    }
}

/// Prepares RECV_ZC without publishing the SQE.
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
pub unsafe fn prep_recv_zc(sqe: *mut RawSqe, fd: RawFd, len: u32, ifq: u32, options: u16) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_RECV_ZC, fd);
        (*sqe).len = len;
        (*sqe).set_file_index(ifq);
        (*sqe).ioprio = super::IoOptions::new(options)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::IoOptions::RECV_MULTISHOT, true))
            .raw();
    }
}

/// Prepares SOCKET without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain socket/address outputs and fixed-file table; u32::MAX requests kernel slot
/// allocation.
#[hot_inline]
pub unsafe fn prep_socket_direct(
    sqe: *mut RawSqe,
    domain: i32,
    kind: i32,
    protocol: i32,
    flags: u32,
    index: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_socket(sqe, domain, kind, protocol, flags);
        super::set_target_index(sqe, index);
    }
}

/// Prepares ACCEPT without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain socket/address outputs and fixed-file table; u32::MAX requests kernel slot
/// allocation.
#[hot_inline]
pub unsafe fn prep_accept_direct(
    sqe: *mut RawSqe,
    fd: RawFd,
    addr: *mut libc::sockaddr,
    len: *mut libc::socklen_t,
    flags: i32,
    index: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_accept(sqe, fd, addr, len, flags);
        super::set_target_index(sqe, index);
    }
}

/// Prepares ACCEPT without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the socket and fixed-file table through the final CQE; account for every
/// allocated direct slot.
#[hot_inline]
pub unsafe fn prep_multishot_accept_direct(sqe: *mut RawSqe, fd: RawFd, flags: i32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_multishot_accept(sqe, fd, core::ptr::null_mut(), core::ptr::null_mut(), flags);
        super::set_target_index(sqe, IORING_FILE_INDEX_ALLOC);
    }
}

/// Prepares RECV without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the buffer group through final multishot completion and every delivered
/// lease through its release.
#[hot_inline]
pub unsafe fn prep_recv_multishot_buffer_select(
    sqe: *mut RawSqe,
    fd: RawFd,
    group: BufferGroupId,
    flags: i32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_recv_multishot(sqe, fd, group, flags);
    }
}

/// Prepares RECVMSG without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the msghdr reserved capacities and buffer group through the final multishot
/// CQE, and each selected lease until released.
#[hot_inline]
pub unsafe fn prep_recvmsg_multishot(
    sqe: *mut RawSqe,
    fd: RawFd,
    msg: *mut libc::msghdr,
    flags: u32,
    group: BufferGroupId,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_recvmsg(sqe, fd, msg, flags);
        (*sqe).buf_index = group.raw();
        (*sqe).flags |= IOSQE_BUFFER_SELECT;
        (*sqe).ioprio = super::IoOptions::new((*sqe).ioprio)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::IoOptions::RECV_MULTISHOT, true))
            .raw();
    }
}

/// Prepares SEND without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the provided-buffer group and all kernel-selected buffer leases through
/// final use.
#[hot_inline]
pub unsafe fn prep_send_bundle(
    sqe: *mut RawSqe,
    fd: RawFd,
    group: BufferGroupId,
    len: usize,
    flags: i32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_send(sqe, fd, core::ptr::null_mut(), len, flags);
        (*sqe).buf_index = group.raw();
        (*sqe).flags |= IOSQE_BUFFER_SELECT;
        (*sqe).ioprio = super::IoOptions::new((*sqe).ioprio)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::IoOptions::BUNDLE, true))
            .raw();
    }
}

/// Prepares RECV without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the provided-buffer group and all kernel-selected buffer leases through
/// final use.
#[hot_inline]
pub unsafe fn prep_recv_bundle(
    sqe: *mut RawSqe,
    fd: RawFd,
    group: BufferGroupId,
    len: usize,
    flags: i32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_recv(sqe, fd, core::ptr::null_mut(), len, flags);
        (*sqe).buf_index = group.raw();
        (*sqe).flags |= IOSQE_BUFFER_SELECT;
        (*sqe).ioprio = super::IoOptions::new((*sqe).ioprio)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::IoOptions::BUNDLE, true))
            .raw();
    }
}

/// Prepares SEND without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the immutable iovecs and payload buffers through final completion,
/// including any required zero-copy notification.
#[hot_inline]
pub unsafe fn prep_send_vectored(
    sqe: *mut RawSqe,
    fd: RawFd,
    iov: *const libc::iovec,
    count: u32,
    flags: i32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_send(sqe, fd, iov.cast(), count as usize, flags);
        (*sqe).ioprio = super::IoOptions::new((*sqe).ioprio)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::IoOptions::VECTORIZED, true))
            .raw();
    }
}

/// Prepares SEND_ZC without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the immutable iovecs and payload buffers through final completion,
/// including any required zero-copy notification.
#[hot_inline]
pub unsafe fn prep_send_zc_vectored(
    sqe: *mut RawSqe,
    fd: RawFd,
    iov: *const libc::iovec,
    count: u32,
    flags: i32,
    zc_flags: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_send_zc(sqe, fd, iov.cast(), count as usize, flags, zc_flags);
        (*sqe).ioprio = super::IoOptions::new((*sqe).ioprio)
            .patch(uarch::bits::BitPatch::EMPTY.with_flag(super::IoOptions::VECTORIZED, true))
            .raw();
    }
}

/// Prepares SEND_ZC without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the immutable payload through the notification CQE; notification results
/// are usage flags, not errno.
#[hot_inline]
pub unsafe fn prep_send_zc_report_usage(
    sqe: *mut RawSqe,
    fd: RawFd,
    buf: *const u8,
    len: usize,
    flags: i32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_send_zc(
            sqe,
            fd,
            buf,
            len,
            flags,
            super::IoOptions::REPORT_USAGE.mask() as u32,
        );
    }
}

/// Borrowed regions of one buffer-selected multishot recvmsg completion.
#[derive(Debug, PartialEq, Eq)]
pub struct RecvmsgOutput<'a> {
    /// Received address, clamped to the reserved address capacity.
    pub name: &'a [u8],
    /// Received ancillary data, clamped to its reserved capacity.
    pub control: &'a [u8],
    /// Received payload, clamped to the delivered buffer extent.
    pub payload: &'a [u8],
    /// Kernel recvmsg flags, including truncation indications.
    pub flags: u32,
}

/// Parses the reserved name/control layout of a multishot recvmsg buffer.
/// `name_capacity` and `control_capacity` must match the submitted msghdr.
/// Header lengths describe received data; reserved capacities determine offsets.
/// # Errors
/// Returns `None` for short headers, overflowing offsets, or missing reserved regions.
/// # Panics
/// Does not panic.
#[hot_inline]
pub fn parse_recvmsg(
    bytes: &[u8],
    name_capacity: usize,
    control_capacity: usize,
) -> Option<RecvmsgOutput<'_>> {
    let header_size = size_of::<IoUringRecvmsgOut>();
    if bytes.len() < header_size {
        return None;
    }
    // SAFETY: The length check covers the complete integer-only UAPI record;
    // read_unaligned accepts arbitrary selected-buffer alignment.
    let header = unsafe { bytes.as_ptr().cast::<IoUringRecvmsgOut>().read_unaligned() };
    let control_start = header_size.checked_add(name_capacity)?;
    let payload_start = control_start.checked_add(control_capacity)?;
    let name = bytes.get(header_size..control_start)?;
    let control = bytes.get(control_start..payload_start)?;
    let payload = bytes.get(payload_start..)?;
    Some(RecvmsgOutput {
        name: &name[..name.len().min(header.namelen as usize)],
        control: &control[..control.len().min(header.controllen as usize)],
        payload: &payload[..payload.len().min(header.payloadlen as usize)],
        flags: header.flags,
    })
}
