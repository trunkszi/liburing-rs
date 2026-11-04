//! Process events, ring messages and device/socket commands.
use std::os::fd::RawFd;

use uarch::prelude::hot_inline;

use super::{init_sqe, set_target_index};
use crate::backend::{RawSqe, sys::sqe::*};

/// Prepares WAITID without publishing the SQE.
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
pub unsafe fn prep_waitid(
    sqe: *mut RawSqe,
    idtype: libc::idtype_t,
    id: libc::id_t,
    info: *mut libc::siginfo_t,
    options: i32,
    flags: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_WAITID, id as i32);
        (*sqe).len = idtype;
        (*sqe).off = info as u64;
        (*sqe).set_file_index(options as u32);
        (*sqe).operation_flags = flags;
    }
}

/// Prepares MSG_RING without publishing the SQE.
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
pub unsafe fn prep_msg_ring(sqe: *mut RawSqe, fd: RawFd, result: u32, data: u64, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_MSG_RING, fd);
        (*sqe).len = result;
        (*sqe).off = data;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares MSG_RING without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain both rings and the source fixed file; adopt or close the installed target
/// slot exactly once.
#[hot_inline]
pub unsafe fn prep_msg_ring_fd(
    sqe: *mut RawSqe,
    fd: RawFd,
    source_slot: u32,
    target_slot: u32,
    data: u64,
    flags: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_MSG_RING, fd);
        (*sqe).addr = 1;
        (*sqe).off = data;
        (*sqe).addr3 = source_slot as u64;
        (*sqe).operation_flags = flags;
        set_target_index(sqe, target_slot);
    }
}

/// Prepares URING_CMD without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the descriptor and command-specific buffers; fill only the command extent
/// available for the selected geometry.
#[hot_inline]
pub unsafe fn prep_uring_cmd(sqe: *mut RawSqe, cmd_op: u32, fd: RawFd) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_URING_CMD, fd);
        (*sqe).set_cmd_op(cmd_op);
    }
}

/// Prepares URING_CMD128 without publishing the SQE.
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
pub unsafe fn prep_uring_cmd128(sqe: *mut RawSqe128, cmd_op: u32, fd: RawFd) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(
            core::ptr::addr_of_mut!((*sqe).base),
            IORING_OP_URING_CMD128,
            fd,
        );
        (*sqe).base.set_cmd_op(cmd_op);
        (*sqe).cmd_ext = [0; 64];
    }
}

/// Prepares URING_CMD without publishing the SQE.
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
pub unsafe fn prep_cmd_sock(
    sqe: *mut RawSqe,
    cmd_op: u32,
    fd: RawFd,
    level: i32,
    optname: i32,
    optval: *mut libc::c_void,
    optlen: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_uring_cmd(sqe, cmd_op, fd);
        (*sqe).set_level_optname(level as u32, optname as u32);
        (*sqe).set_optval(optval as u64);
        // Kernel reads the length from the optlen/file_index union, not sqe.len.
        (*sqe).set_file_index(optlen);
    }
}

/// Prepares URING_CMD without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the socket through completion; the queued byte count is returned in the CQE
/// result.
#[hot_inline]
pub unsafe fn prep_cmd_siocinq(sqe: *mut RawSqe, fd: RawFd) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_uring_cmd(sqe, 0, fd);
    }
}

/// Prepares URING_CMD without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the socket through completion; the queued byte count is returned in the CQE
/// result.
#[hot_inline]
pub unsafe fn prep_cmd_siocoutq(sqe: *mut RawSqe, fd: RawFd) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_uring_cmd(sqe, 1, fd);
    }
}

/// Prepares URING_CMD without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, use CQE32-capable ring geometry and retain the timestamped socket through the
/// final multishot CQE.
#[hot_inline]
pub unsafe fn prep_cmd_tx_timestamp(sqe: *mut RawSqe, fd: RawFd) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_uring_cmd(sqe, 4, fd);
    }
}

/// Prepares URING_CMD without publishing the SQE.
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
pub unsafe fn prep_cmd_getsockopt(
    sqe: *mut RawSqe,
    fd: RawFd,
    level: i32,
    optname: i32,
    optval: *mut libc::c_void,
    optlen: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_cmd_sock(sqe, 2, fd, level, optname, optval, optlen);
    }
}

/// Prepares URING_CMD without publishing the SQE.
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
pub unsafe fn prep_cmd_setsockopt(
    sqe: *mut RawSqe,
    fd: RawFd,
    level: i32,
    optname: i32,
    optval: *const libc::c_void,
    optlen: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_cmd_sock(
            sqe,
            3,
            fd,
            level,
            optname,
            optval as *mut libc::c_void,
            optlen,
        );
    }
}

/// Prepares URING_CMD without publishing the SQE.
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
pub unsafe fn prep_cmd_getsockname(
    sqe: *mut RawSqe,
    fd: RawFd,
    addr: *mut libc::sockaddr,
    len: *mut libc::socklen_t,
    peer: bool,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_uring_cmd(sqe, 5, fd);
        (*sqe).addr = addr as u64;
        (*sqe).addr3 = len as u64;
        // Kernel rejects a nonzero sqe.len and reads the peer flag from optlen.
        (*sqe).set_file_index(u32::from(peer));
    }
}
