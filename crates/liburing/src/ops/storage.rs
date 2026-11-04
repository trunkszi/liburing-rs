//! File and block SQE builders, including registered-buffer direct I/O.
//!
//! Preparation only writes an exclusively owned SQE. The caller retains every
//! descriptor, iovec, and buffer until the operation's final CQE. Under
//! `SQPOLL` the kernel SQ thread reads those operands when it consumes the
//! SQE, which can be after `submit` returns.

use std::os::fd::RawFd;

use uarch::prelude::hot_inline;

use super::init_sqe;
use crate::{
    backend::{RawSqe, sys::sqe::*},
    id::BufferId,
};

/// Prepares a positioned file read into `buf`.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf` must remain writable for `len` bytes until the
/// target final CQE. Under `SQPOLL` the kernel SQ thread may read `fd` and
/// `buf` after `submit` returns, so neither may be released at submission.
#[hot_inline]
pub unsafe fn prep_read(sqe: *mut RawSqe, fd: RawFd, buf: *mut u8, len: u32, offset: u64) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor
    // and buffer through the target final completion, including SQPOLL consumption.
    unsafe {
        init_sqe(sqe, IORING_OP_READ, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len;
        (*sqe).off = offset;
    }
}

/// Prepares a positioned file write from `buf`.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf` must remain readable for `len` bytes until the
/// target final CQE. Under `SQPOLL` the kernel SQ thread may read `fd` and
/// `buf` after `submit` returns, so neither may be released at submission.
#[hot_inline]
pub unsafe fn prep_write(sqe: *mut RawSqe, fd: RawFd, buf: *const u8, len: u32, offset: u64) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor
    // and buffer through the target final completion, including SQPOLL consumption.
    unsafe {
        init_sqe(sqe, IORING_OP_WRITE, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len;
        (*sqe).off = offset;
    }
}

/// Prepares a positioned vectored file read.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The `count` iovecs at `iov`, and every buffer they
/// name, must stay readable by the kernel until the target final CQE. Under
/// `SQPOLL` that read can happen after `submit` returns.
#[hot_inline]
pub unsafe fn prep_readv(
    sqe: *mut RawSqe,
    fd: RawFd,
    iov: *const libc::iovec,
    count: u32,
    offset: u64,
) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor,
    // iovecs, and buffers through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_READV, fd);
        (*sqe).addr = iov as u64;
        (*sqe).len = count;
        (*sqe).off = offset;
    }
}

/// Prepares a positioned vectored file write.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The `count` iovecs at `iov`, and every buffer they
/// name, must stay immutable until the target final CQE. Under `SQPOLL` the
/// kernel SQ thread may read them after `submit` returns.
#[hot_inline]
pub unsafe fn prep_writev(
    sqe: *mut RawSqe,
    fd: RawFd,
    iov: *const libc::iovec,
    count: u32,
    offset: u64,
) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor,
    // iovecs, and buffers through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_WRITEV, fd);
        (*sqe).addr = iov as u64;
        (*sqe).len = count;
        (*sqe).off = offset;
    }
}

/// Prepares a positioned read into registered buffer `buf_index`.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf..buf+len` must lie within the registered
/// `buf_index` allocation and remain exclusively writable through the target
/// final CQE. Transition its handle to in-flight before publishing this SQE.
/// Under `SQPOLL` the kernel SQ thread may read `fd` and `buf` after `submit`
/// returns.
#[hot_inline]
pub unsafe fn prep_read_fixed(
    sqe: *mut RawSqe,
    fd: RawFd,
    buf: *mut u8,
    len: u32,
    offset: u64,
    buf_index: BufferId,
) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor
    // and registered buffer through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_READ_FIXED, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len;
        (*sqe).off = offset;
        (*sqe).buf_index = buf_index.raw();
    }
}

/// Prepares a positioned write from registered buffer `buf_index`.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf..buf+len` must lie within the registered
/// `buf_index` allocation and remain readable through the target final CQE.
/// Transition its handle to in-flight before publishing this SQE. Under
/// `SQPOLL` the kernel SQ thread may read `fd` and `buf` after `submit` returns.
#[hot_inline]
pub unsafe fn prep_write_fixed(
    sqe: *mut RawSqe,
    fd: RawFd,
    buf: *const u8,
    len: u32,
    offset: u64,
    buf_index: BufferId,
) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor
    // and registered buffer through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_WRITE_FIXED, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len;
        (*sqe).off = offset;
        (*sqe).buf_index = buf_index.raw();
    }
}

/// Prepares a positioned vectored read into registered buffer `buf_index`.
/// Requires Linux 6.15 or newer (`IORING_OP_READV_FIXED`).
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `iov` must address `count` initialized descriptors in
/// readable, immutable user memory until the kernel has consumed the SQE. Under
/// `SQPOLL` this can be after `submit` returns; retaining them through the final
/// CQE is sufficient. The descriptors need not be in registered memory. Every
/// `iov_base..iov_base+iov_len` range must lie within the allocation registered
/// at `buf_index` and remain exclusively writable through the target final CQE.
/// Keep `fd` live and transition the buffer handle to in-flight before publication.
#[hot_inline]
pub unsafe fn prep_readv_fixed(
    sqe: *mut RawSqe,
    fd: RawFd,
    iov: *const libc::iovec,
    count: u32,
    offset: u64,
    buf_index: BufferId,
) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor,
    // ordinary user-memory iovecs through consumption and each registered
    // buffer range through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_READV_FIXED, fd);
        (*sqe).addr = iov as u64;
        (*sqe).len = count;
        (*sqe).off = offset;
        (*sqe).buf_index = buf_index.raw();
    }
}

/// Prepares a positioned vectored write from registered buffer `buf_index`.
/// Requires Linux 6.15 or newer (`IORING_OP_WRITEV_FIXED`).
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `iov` must address `count` initialized descriptors in
/// readable, immutable user memory until the kernel has consumed the SQE. Under
/// `SQPOLL` this can be after `submit` returns; retaining them through the final
/// CQE is sufficient. The descriptors need not be in registered memory. Every
/// `iov_base..iov_base+iov_len` range must lie within the allocation registered
/// at `buf_index` and remain readable and immutable through the target final CQE.
/// Keep `fd` live and transition the buffer handle to in-flight before publication.
#[hot_inline]
pub unsafe fn prep_writev_fixed(
    sqe: *mut RawSqe,
    fd: RawFd,
    iov: *const libc::iovec,
    count: u32,
    offset: u64,
    buf_index: BufferId,
) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor,
    // ordinary user-memory iovecs through consumption and each registered
    // buffer range through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_WRITEV_FIXED, fd);
        (*sqe).addr = iov as u64;
        (*sqe).len = count;
        (*sqe).off = offset;
        (*sqe).buf_index = buf_index.raw();
    }
}

/// Prepares READ_MULTISHOT without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the selected-buffer group and each delivered lease until its own release
/// and the final multishot CQE.
#[hot_inline]
pub unsafe fn prep_read_multishot(
    sqe: *mut RawSqe,
    fd: RawFd,
    len: u32,
    offset: u64,
    group: crate::BufferGroupId,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_READ_MULTISHOT, fd);
        (*sqe).len = len;
        (*sqe).off = offset;
        (*sqe).buf_index = group.raw();
        (*sqe).flags |= IOSQE_BUFFER_SELECT;
    }
}

/// Prepares FSYNC without publishing the SQE.
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
pub unsafe fn prep_fsync(sqe: *mut RawSqe, fd: RawFd, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_FSYNC, fd);
        (*sqe).operation_flags = flags;
    }
}

/// Prepares SYNC_FILE_RANGE without publishing the SQE.
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
pub unsafe fn prep_sync_file_range(sqe: *mut RawSqe, fd: RawFd, len: u32, offset: u64, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_SYNC_FILE_RANGE, fd);
        (*sqe).len = len;
        (*sqe).off = offset;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares FALLOCATE without publishing the SQE.
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
pub unsafe fn prep_fallocate(sqe: *mut RawSqe, fd: RawFd, mode: i32, offset: u64, len: u64) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_FALLOCATE, fd);
        (*sqe).len = mode as u32;
        (*sqe).off = offset;
        (*sqe).addr = len;
    }
}

/// Prepares FADVISE without publishing the SQE.
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
pub unsafe fn prep_fadvise(sqe: *mut RawSqe, fd: RawFd, offset: u64, len: u32, advice: i32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_FADVISE, fd);
        (*sqe).off = offset;
        (*sqe).len = len;
        (*sqe).operation_flags = advice as u32;
    }
}

/// Prepares MADVISE without publishing the SQE.
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
pub unsafe fn prep_madvise(sqe: *mut RawSqe, addr: *mut libc::c_void, len: u32, advice: i32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_MADVISE, -1);
        (*sqe).addr = addr as u64;
        (*sqe).len = len;
        (*sqe).operation_flags = advice as u32;
    }
}

/// Prepares SPLICE without publishing the SQE.
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
pub unsafe fn prep_splice(
    sqe: *mut RawSqe,
    fd_in: RawFd,
    off_in: i64,
    fd_out: RawFd,
    off_out: i64,
    len: u32,
    flags: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_SPLICE, fd_out);
        (*sqe).addr = off_in as u64;
        (*sqe).off = off_out as u64;
        (*sqe).len = len;
        (*sqe).splice_fd_in = fd_in;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares TEE without publishing the SQE.
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
pub unsafe fn prep_tee(sqe: *mut RawSqe, fd_in: RawFd, fd_out: RawFd, len: u32, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_TEE, fd_out);
        (*sqe).splice_fd_in = fd_in;
        (*sqe).len = len;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares PIPE without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain writable storage for two returned descriptors and adopt each successful
/// descriptor exactly once.
#[hot_inline]
pub unsafe fn prep_pipe(sqe: *mut RawSqe, fds: *mut i32, flags: i32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_PIPE, 0);
        (*sqe).addr = fds as u64;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares PIPE without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain descriptor output storage and the destination fixed-file table through
/// completion; u32::MAX requests slot allocation.
#[hot_inline]
pub unsafe fn prep_pipe_direct(sqe: *mut RawSqe, fds: *mut i32, flags: i32, index: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_pipe(sqe, fds, flags);
        super::set_target_index(sqe, index);
    }
}

/// Attaches protection information to an already prepared read/write SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the initialized protection-information record and its referenced memory
/// through final completion.
#[hot_inline]
pub unsafe fn prep_rw_attr_pi(sqe: *mut RawSqe, attr: *const IoUringAttrPi) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        (*sqe).set_attr(attr as u64, IORING_RW_ATTR_FLAG_PI as u64);
    }
}
