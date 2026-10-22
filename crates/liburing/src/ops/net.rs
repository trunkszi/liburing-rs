//! Allocation-free network, cancellation, poll, and registered-I/O SQE builders.
//!
//! Preparation only initializes an exclusively owned SQE. Submission and resource
//! retention belong to the caller. Cancellation never shortens the target's DMA
//! lifetime: retain its buffers until the target's final CQE, and zero-copy send
//! storage until its required notification CQE. Set `IOSQE_FIXED_FILE` separately
//! when an ordinary `fd` argument contains a registered-file slot index.

use std::os::fd::RawFd;

use liburing_sys::io_uring_sqe;

use crate::id::{BufGroupId, BufferId, OpId, UringFileSlot};

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
/// liburing. `buf` must remain readable for `len` bytes until the target final CQE.
pub unsafe fn prep_send(sqe: *mut io_uring_sqe, fd: RawFd, buf: *const u8, len: usize, flags: i32) {
    // SAFETY: SQE storage is exclusively writable. The shim encodes the buffer
    // address and length; the caller retains readable bytes through completion.
    unsafe {
        liburing_sys::uring_shim_prep_send(sqe, fd, buf.cast(), len, flags);
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
/// liburing. `buf` must remain readable for `len` bytes until the kernel relinquishes it.
/// When the send CQE carries `IORING_CQE_F_MORE`, retain storage through its
/// `IORING_CQE_F_NOTIF` notification, including after cancellation.
pub unsafe fn prep_send_zc(
    sqe: *mut io_uring_sqe,
    fd: RawFd,
    buf: *const u8,
    len: usize,
    flags: i32,
    zc_flags: u32,
) {
    // SAFETY: SQE storage is exclusively writable. The shim encodes the buffer
    // address; the caller retains bytes through any zero-copy notification.
    unsafe {
        liburing_sys::uring_shim_prep_send_zc(sqe, fd, buf.cast(), len, flags, zc_flags);
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
pub unsafe fn prep_sendmsg(
    sqe: *mut io_uring_sqe,
    fd: RawFd,
    msg: *const libc::msghdr,
    flags: u32,
) {
    // SAFETY: SQE storage is exclusively writable and libc::msghdr is the shim
    // ABI type. The caller retains the header, vectors, and all pointed storage.
    unsafe {
        liburing_sys::uring_shim_prep_sendmsg(sqe, fd, msg, flags);
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
/// liburing. `buf` must remain exclusively writable for `len` bytes until the target
/// final CQE, including while cancellation is pending.
pub unsafe fn prep_recv(sqe: *mut io_uring_sqe, fd: RawFd, buf: *mut u8, len: usize, flags: i32) {
    // SAFETY: SQE storage is exclusively writable. The shim encodes the output
    // address; the caller keeps the buffer exclusive until the final CQE.
    unsafe {
        liburing_sys::uring_shim_prep_recv(sqe, fd, buf.cast(), len, flags);
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
pub unsafe fn prep_recv_multishot(
    sqe: *mut io_uring_sqe,
    fd: RawFd,
    group: BufGroupId,
    flags: i32,
) {
    // SAFETY: SQE storage is exclusively writable and unpublished. These writes
    // modify that SQE only; the caller retains the registered group
    // through the multishot receive final CQE and owns each returned lease.
    unsafe {
        liburing_sys::uring_shim_prep_recv_multishot(sqe, fd, std::ptr::null_mut(), 0, flags);
        liburing_sys::uring_shim_sqe_set_buf_group(sqe, group.raw());
        (*sqe).flags |= liburing_sys::IOSQE_BUFFER_SELECT as u8;
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
pub unsafe fn prep_recvmsg(sqe: *mut io_uring_sqe, fd: RawFd, msg: *mut libc::msghdr, flags: u32) {
    // SAFETY: SQE storage is exclusively writable and libc::msghdr matches the
    // shim ABI. The caller retains exclusive header and payload storage.
    unsafe {
        liburing_sys::uring_shim_prep_recvmsg(sqe, fd, msg, flags);
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
    sqe: *mut io_uring_sqe,
    fd: RawFd,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) {
    // SAFETY: SQE storage is exclusively writable and libc::sockaddr matches
    // the shim ABI. The caller retains the address until connect completes.
    unsafe {
        liburing_sys::uring_shim_prep_connect(sqe, fd, addr, addrlen);
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
    sqe: *mut io_uring_sqe,
    fd: RawFd,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
    flags: i32,
) {
    // SAFETY: SQE storage is exclusively writable. The shim encodes the peer
    // output pointers; the caller retains exclusive output through completion.
    unsafe {
        liburing_sys::uring_shim_prep_accept(sqe, fd, addr, addrlen, flags);
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
    sqe: *mut io_uring_sqe,
    fd: RawFd,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
    flags: i32,
) {
    // SAFETY: SQE storage is exclusively writable. The shim encodes peer output
    // pointers, which the caller retains until the multishot final completion.
    unsafe {
        liburing_sys::uring_shim_prep_multishot_accept(sqe, fd, addr, addrlen, flags);
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
pub unsafe fn prep_cancel(sqe: *mut io_uring_sqe, target: OpId, flags: i32) {
    // SAFETY: SQE storage is exclusively writable and target.raw() preserves the
    // exact user_data match. Target DMA remains retained independently.
    unsafe {
        liburing_sys::uring_shim_prep_cancel64(sqe, target.raw(), flags);
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
pub unsafe fn prep_cancel_fd(sqe: *mut io_uring_sqe, fd: RawFd, flags: u32) {
    // SAFETY: SQE storage is exclusively writable. The descriptor and flags are
    // encoded by value, while affected DMA lifetimes remain with the caller.
    unsafe {
        liburing_sys::uring_shim_prep_cancel_fd(sqe, fd, flags);
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
pub unsafe fn prep_poll_add(sqe: *mut io_uring_sqe, fd: RawFd, poll_mask: u32) {
    // SAFETY: SQE storage is exclusively writable. Only the descriptor and poll
    // mask values are encoded; the caller coordinates descriptor retirement.
    unsafe {
        liburing_sys::uring_shim_prep_poll_add(sqe, fd, poll_mask);
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
pub unsafe fn prep_poll_multishot(sqe: *mut io_uring_sqe, fd: RawFd, poll_mask: u32) {
    // SAFETY: SQE storage is exclusively writable. Descriptor and event-mask
    // values are copied; the caller retains the multishot poll lifetime.
    unsafe {
        liburing_sys::uring_shim_prep_poll_multishot(sqe, fd, poll_mask);
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
pub unsafe fn prep_poll_remove(sqe: *mut io_uring_sqe, target: OpId) {
    // SAFETY: SQE storage is exclusively writable and target.raw() preserves the
    // poll user_data match. Removal does not release target-owned resources.
    unsafe {
        liburing_sys::uring_shim_prep_poll_remove(sqe, target.raw());
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
pub unsafe fn prep_close(sqe: *mut io_uring_sqe, fd: RawFd) {
    // SAFETY: SQE storage is exclusively writable. The shim encodes the caller
    // owned descriptor, whose unique close responsibility transfers on submission.
    unsafe {
        liburing_sys::uring_shim_prep_close(sqe, fd);
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
pub unsafe fn prep_close_direct(sqe: *mut io_uring_sqe, slot: UringFileSlot) {
    assert_ne!(
        slot.raw(),
        u32::MAX,
        "slot u32::MAX cannot be encoded as a direct close: file_index + 1 wraps to 0"
    );
    // SAFETY: SQE storage is exclusively writable. The live fixed-file slot is
    // encoded as a direct-close index; reclamation waits for its successful CQE.
    unsafe {
        liburing_sys::uring_shim_prep_close_direct(sqe, slot.raw());
    }
}

/// Prepares reading into registered buffer `buffer` at file byte `offset`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf..buf+len` must lie within the registered `buffer` allocation and
/// remain exclusively writable through the target final CQE. Transition its
/// handle to in-flight before publishing this SQE.
pub unsafe fn prep_read_fixed(
    sqe: *mut io_uring_sqe,
    fd: RawFd,
    buf: *mut u8,
    len: u32,
    offset: u64,
    buffer: BufferId,
) {
    // SAFETY: SQE storage is exclusively writable. The caller retains the exact
    // registered allocation and index, with exclusive DMA access until completion.
    unsafe {
        liburing_sys::uring_shim_prep_read_fixed(
            sqe,
            fd,
            buf.cast(),
            len,
            offset,
            i32::from(buffer.raw()),
        );
    }
}

/// Prepares writing registered buffer `buffer` at file byte `offset`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf..buf+len` must lie within the registered `buffer` allocation and
/// remain readable and immutable through the target final CQE. Transition
/// its handle to in-flight before publishing this SQE.
pub unsafe fn prep_write_fixed(
    sqe: *mut io_uring_sqe,
    fd: RawFd,
    buf: *const u8,
    len: u32,
    offset: u64,
    buffer: BufferId,
) {
    // SAFETY: SQE storage is exclusively writable. The caller retains immutable
    // registered bytes and their matching buffer index until the final CQE.
    unsafe {
        liburing_sys::uring_shim_prep_write_fixed(
            sqe,
            fd,
            buf.cast(),
            len,
            offset,
            i32::from(buffer.raw()),
        );
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
        let mut sqe = unsafe { MaybeUninit::<io_uring_sqe>::zeroed().assume_init() };
        // SAFETY: Exclusive initialized SQE storage.
        unsafe { prep_close_direct(&mut sqe, UringFileSlot(0)) };
        assert_eq!(sqe.fd, 0);
        // SAFETY: The helper initialized the file_index union field.
        assert_eq!(unsafe { sqe.__bindgen_anon_5.file_index }, 1);
    }

    #[test]
    #[should_panic(expected = "u32::MAX")]
    fn close_direct_rejects_unrepresentable_slot() {
        // SAFETY: An all-zero SQE is valid initialized storage; the slot is
        // rejected before any field is encoded.
        let mut sqe = unsafe { MaybeUninit::<io_uring_sqe>::zeroed().assume_init() };
        // SAFETY: Exclusive initialized SQE storage; the input is deliberately
        // unrepresentable and must panic.
        unsafe { prep_close_direct(&mut sqe, UringFileSlot(u32::MAX)) };
    }
}
