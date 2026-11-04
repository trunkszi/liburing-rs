//! File and block SQE builders, including registered-buffer direct I/O.
//!
//! Preparation only writes an exclusively owned SQE. The caller retains every
//! descriptor, iovec, and buffer until the operation's final CQE. Under
//! `SQPOLL` the kernel SQ thread reads those operands when it consumes the
//! SQE, which can be after `submit` returns.

use std::os::fd::RawFd;

use io_uring::opcode;

use super::init_sqe;
use crate::{backend::RawSqe, id::BufferId};

/// Prepares a positioned file read into `buf`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf` must remain writable for `len` bytes until the
/// target final CQE. Under `SQPOLL` the kernel SQ thread may read `fd` and
/// `buf` after `submit` returns, so neither may be released at submission.
#[inline(always)]
pub unsafe fn prep_read(sqe: *mut RawSqe, fd: RawFd, buf: *mut u8, len: u32, offset: u64) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor
    // and buffer through the target final completion, including SQPOLL consumption.
    unsafe {
        init_sqe(sqe, opcode::Read::CODE, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len;
        (*sqe).off = offset;
    }
}

/// Prepares a positioned file write from `buf`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf` must remain readable for `len` bytes until the
/// target final CQE. Under `SQPOLL` the kernel SQ thread may read `fd` and
/// `buf` after `submit` returns, so neither may be released at submission.
#[inline(always)]
pub unsafe fn prep_write(sqe: *mut RawSqe, fd: RawFd, buf: *const u8, len: u32, offset: u64) {
    // SAFETY: The caller owns initialized SQE storage and retains the descriptor
    // and buffer through the target final completion, including SQPOLL consumption.
    unsafe {
        init_sqe(sqe, opcode::Write::CODE, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len;
        (*sqe).off = offset;
    }
}

/// Prepares a positioned vectored file read.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The `count` iovecs at `iov`, and every buffer they
/// name, must stay readable by the kernel until the target final CQE. Under
/// `SQPOLL` that read can happen after `submit` returns.
#[inline(always)]
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
        init_sqe(sqe, opcode::Readv::CODE, fd);
        (*sqe).addr = iov as u64;
        (*sqe).len = count;
        (*sqe).off = offset;
    }
}

/// Prepares a positioned vectored file write.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The `count` iovecs at `iov`, and every buffer they
/// name, must stay immutable until the target final CQE. Under `SQPOLL` the
/// kernel SQ thread may read them after `submit` returns.
#[inline(always)]
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
        init_sqe(sqe, opcode::Writev::CODE, fd);
        (*sqe).addr = iov as u64;
        (*sqe).len = count;
        (*sqe).off = offset;
    }
}

/// Prepares a positioned read into registered buffer `buf_index`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf..buf+len` must lie within the registered
/// `buf_index` allocation and remain exclusively writable through the target
/// final CQE. Transition its handle to in-flight before publishing this SQE.
/// Under `SQPOLL` the kernel SQ thread may read `fd` and `buf` after `submit`
/// returns.
#[inline(always)]
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
        init_sqe(sqe, opcode::ReadFixed::CODE, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len;
        (*sqe).off = offset;
        (*sqe).buf_index = buf_index.raw();
    }
}

/// Prepares a positioned write from registered buffer `buf_index`.
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `buf..buf+len` must lie within the registered
/// `buf_index` allocation and remain readable through the target final CQE.
/// Transition its handle to in-flight before publishing this SQE. Under
/// `SQPOLL` the kernel SQ thread may read `fd` and `buf` after `submit` returns.
#[inline(always)]
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
        init_sqe(sqe, opcode::WriteFixed::CODE, fd);
        (*sqe).addr = buf as u64;
        (*sqe).len = len;
        (*sqe).off = offset;
        (*sqe).buf_index = buf_index.raw();
    }
}

/// Prepares a positioned vectored read into registered buffer `buf_index`.
///
/// Requires Linux 6.15 or newer (`IORING_OP_READV_FIXED`).
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `iov` must address `count` initialized descriptors in
/// readable, immutable user memory until the kernel has consumed the SQE. Under
/// `SQPOLL` this can be after `submit` returns; retaining them through the final
/// CQE is sufficient. The descriptors need not be in registered memory. Every
/// `iov_base..iov_base+iov_len` range must lie within the allocation registered
/// at `buf_index` and remain exclusively writable through the target final CQE.
/// Keep `fd` live and transition the buffer handle to in-flight before publication.
#[inline(always)]
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
        init_sqe(sqe, opcode::ReadvFixed::CODE, fd);
        (*sqe).addr = iov as u64;
        (*sqe).len = count;
        (*sqe).off = offset;
        (*sqe).buf_index = buf_index.raw();
    }
}

/// Prepares a positioned vectored write from registered buffer `buf_index`.
///
/// Requires Linux 6.15 or newer (`IORING_OP_WRITEV_FIXED`).
///
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
///
/// # Panics
/// Does not panic.
///
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `iov` must address `count` initialized descriptors in
/// readable, immutable user memory until the kernel has consumed the SQE. Under
/// `SQPOLL` this can be after `submit` returns; retaining them through the final
/// CQE is sufficient. The descriptors need not be in registered memory. Every
/// `iov_base..iov_base+iov_len` range must lie within the allocation registered
/// at `buf_index` and remain readable and immutable through the target final CQE.
/// Keep `fd` live and transition the buffer handle to in-flight before publication.
#[inline(always)]
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
        init_sqe(sqe, opcode::WritevFixed::CODE, fd);
        (*sqe).addr = iov as u64;
        (*sqe).len = count;
        (*sqe).off = offset;
        (*sqe).buf_index = buf_index.raw();
    }
}
