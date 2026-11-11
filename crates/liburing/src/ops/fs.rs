//! Filesystem metadata, path operations and direct descriptor preparation.
use std::os::fd::RawFd;

use uarch::prelude::hot_inline;

pub use super::storage::*;
use super::{init_sqe, set_target_index};
pub use crate::backend::sys::statx::{STATX_BASIC_STATS, STATX_DIOALIGN, Statx, StatxTimestamp};
use crate::{
    backend::{RawSqe, sys::sqe::*},
    id::UringFileSlot,
};

/// Prepares closing an ordinary OS file descriptor.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. The caller must transfer close responsibility exactly once and ensure
/// prior operations no longer need this descriptor before close executes.
#[hot_inline]
pub unsafe fn prep_close(sqe: *mut RawSqe, fd: RawFd) {
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_CLOSE, fd);
    }
}

/// Prepares closing a registered-file slot without closing its source fd.
/// # Errors
/// Preparation reports no errors; the operation result is returned in its CQE.
/// # Panics
/// Panics if `slot.raw() == u32::MAX`: the direct-close encoding adds one to
/// the index, which wraps to zero and makes the kernel treat the request as an
/// ordinary close of descriptor 0 instead of a registered-file close.
/// # Safety
/// `sqe` must point to one initialized, exclusively owned, writable SQE that
/// has not been published. `slot` must name a live registered file. Retire prior operations before
/// close executes and recycle the table slot only after successful close CQE.
/// Do not set `IOSQE_FIXED_FILE` on this SQE: a direct close already targets the
/// registered file, and the flag makes the request complete with `-EBADF`.
#[hot_inline]
pub unsafe fn prep_close_direct(sqe: *mut RawSqe, slot: UringFileSlot) {
    assert_ne!(
        slot.raw(),
        u32::MAX,
        "slot u32::MAX cannot be encoded as a direct close"
    );
    // SAFETY: The caller owns initialized SQE storage and retains all referenced
    // descriptors and DMA operands through the target final completion.
    unsafe {
        init_sqe(sqe, IORING_OP_CLOSE, 0);
        (*sqe).splice_fd_in = (slot.raw() + 1) as i32;
    }
}

/// Linux openat2 policy record; reserved resolve bits must be zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenHow {
    /// Open flags.
    pub flags: u64,
    /// Creation mode.
    pub mode: u64,
    /// Path resolution policy.
    pub resolve: u64,
}
uarch::layout::assert_layout!(OpenHow, size = 24, align = 8, fields = { flags: 0, mode: 8, resolve: 16 });

/// Prepares OPENAT without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the NUL-terminated path and directory descriptor; adopt a successful
/// returned descriptor exactly once.
#[hot_inline]
pub unsafe fn prep_openat(
    sqe: *mut RawSqe,
    dfd: RawFd,
    path: *const libc::c_char,
    flags: i32,
    mode: libc::mode_t,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_OPENAT, dfd);
        (*sqe).addr = path as u64;
        (*sqe).len = mode;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares OPENAT2 without publishing the SQE.
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
pub unsafe fn prep_openat2(
    sqe: *mut RawSqe,
    dfd: RawFd,
    path: *const libc::c_char,
    how: *const OpenHow,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_OPENAT2, dfd);
        (*sqe).addr = path as u64;
        (*sqe).off = how as u64;
        (*sqe).len = size_of::<OpenHow>() as u32;
    }
}

/// Prepares OPENAT without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain paths, policy and the fixed-file table; u32::MAX requests kernel slot
/// allocation.
#[hot_inline]
pub unsafe fn prep_openat_direct(
    sqe: *mut RawSqe,
    dfd: RawFd,
    path: *const libc::c_char,
    flags: i32,
    mode: libc::mode_t,
    index: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_openat(sqe, dfd, path, flags, mode);
        set_target_index(sqe, index);
    }
}

/// Prepares OPENAT2 without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain paths, policy and the fixed-file table; u32::MAX requests kernel slot
/// allocation.
#[hot_inline]
pub unsafe fn prep_openat2_direct(
    sqe: *mut RawSqe,
    dfd: RawFd,
    path: *const libc::c_char,
    how: *const OpenHow,
    index: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        prep_openat2(sqe, dfd, path, how);
        set_target_index(sqe, index);
    }
}

/// Prepares STATX without publishing the SQE.
/// # Errors
/// Preparation is infallible; validation and results arrive in CQEs.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must name exclusive, initialized, unpublished RawSqe storage.
/// If submitted, retain the readable NUL-terminated path and exclusively writable statx output
/// through completion.
#[hot_inline]
pub unsafe fn prep_statx(
    sqe: *mut RawSqe,
    dfd: RawFd,
    path: *const libc::c_char,
    flags: i32,
    mask: u32,
    output: *mut Statx,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_STATX, dfd);
        (*sqe).addr = path as u64;
        (*sqe).off = output as u64;
        (*sqe).len = mask;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares RENAMEAT without publishing the SQE.
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
pub unsafe fn prep_renameat(
    sqe: *mut RawSqe,
    old_dfd: RawFd,
    old_path: *const libc::c_char,
    new_dfd: RawFd,
    new_path: *const libc::c_char,
    flags: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_RENAMEAT, old_dfd);
        (*sqe).addr = old_path as u64;
        (*sqe).off = new_path as u64;
        (*sqe).len = new_dfd as u32;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares UNLINKAT without publishing the SQE.
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
pub unsafe fn prep_unlinkat(sqe: *mut RawSqe, dfd: RawFd, path: *const libc::c_char, flags: i32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_UNLINKAT, dfd);
        (*sqe).addr = path as u64;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares MKDIRAT without publishing the SQE.
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
pub unsafe fn prep_mkdirat(
    sqe: *mut RawSqe,
    dfd: RawFd,
    path: *const libc::c_char,
    mode: libc::mode_t,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_MKDIRAT, dfd);
        (*sqe).addr = path as u64;
        (*sqe).len = mode;
    }
}

/// Prepares SYMLINKAT without publishing the SQE.
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
pub unsafe fn prep_symlinkat(
    sqe: *mut RawSqe,
    target: *const libc::c_char,
    dfd: RawFd,
    linkpath: *const libc::c_char,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_SYMLINKAT, dfd);
        (*sqe).addr = target as u64;
        (*sqe).off = linkpath as u64;
    }
}

/// Prepares LINKAT without publishing the SQE.
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
pub unsafe fn prep_linkat(
    sqe: *mut RawSqe,
    old_dfd: RawFd,
    old_path: *const libc::c_char,
    new_dfd: RawFd,
    new_path: *const libc::c_char,
    flags: i32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_LINKAT, old_dfd);
        (*sqe).addr = old_path as u64;
        (*sqe).off = new_path as u64;
        (*sqe).len = new_dfd as u32;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares FTRUNCATE without publishing the SQE.
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
pub unsafe fn prep_ftruncate(sqe: *mut RawSqe, fd: RawFd, len: i64) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_FTRUNCATE, fd);
        (*sqe).off = len as u64;
    }
}

/// Prepares FILES_UPDATE without publishing the SQE.
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
pub unsafe fn prep_files_update(sqe: *mut RawSqe, fds: *const i32, count: u32, offset: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_FILES_UPDATE, -1);
        (*sqe).addr = fds as u64;
        (*sqe).len = count;
        (*sqe).off = offset as u64;
    }
}

/// Prepares FIXED_FD_INSTALL without publishing the SQE.
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
pub unsafe fn prep_fixed_fd_install(sqe: *mut RawSqe, slot: UringFileSlot, flags: u32) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_FIXED_FD_INSTALL, slot.raw() as i32);
        (*sqe).flags |= IOSQE_FIXED_FILE;
        (*sqe).operation_flags = flags;
    }
}

/// Prepares FSETXATTR without publishing the SQE.
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
pub unsafe fn prep_fsetxattr(
    sqe: *mut RawSqe,
    fd: RawFd,
    name: *const libc::c_char,
    value: *const u8,
    len: u32,
    flags: i32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_FSETXATTR, fd);
        (*sqe).addr = name as u64;
        (*sqe).off = value as u64;
        (*sqe).len = len;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares SETXATTR without publishing the SQE.
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
pub unsafe fn prep_setxattr(
    sqe: *mut RawSqe,
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *const u8,
    len: u32,
    flags: i32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_SETXATTR, 0);
        (*sqe).addr = name as u64;
        (*sqe).off = value as u64;
        (*sqe).len = len;
        (*sqe).addr3 = path as u64;
        (*sqe).operation_flags = flags as u32;
    }
}

/// Prepares FGETXATTR without publishing the SQE.
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
pub unsafe fn prep_fgetxattr(
    sqe: *mut RawSqe,
    fd: RawFd,
    name: *const libc::c_char,
    value: *mut u8,
    len: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_FGETXATTR, fd);
        (*sqe).addr = name as u64;
        (*sqe).off = value as u64;
        (*sqe).len = len;
    }
}

/// Prepares GETXATTR without publishing the SQE.
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
pub unsafe fn prep_getxattr(
    sqe: *mut RawSqe,
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *mut u8,
    len: u32,
) {
    // SAFETY: Caller guarantees initialized exclusive SQE storage and operand lifetimes.
    unsafe {
        init_sqe(sqe, IORING_OP_GETXATTR, 0);
        (*sqe).addr = name as u64;
        (*sqe).off = value as u64;
        (*sqe).len = len;
        (*sqe).addr3 = path as u64;
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use super::*;
    use crate::id::UringFileSlot;

    #[test]
    fn close_direct_encodes_first_slot() {
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
    fn close_direct_rejects_invalid_slot() {
        // SAFETY: An all-zero SQE is valid initialized storage; the slot is
        // rejected before any field is encoded.
        let mut sqe = unsafe { MaybeUninit::<RawSqe>::zeroed().assume_init() };
        // SAFETY: Exclusive initialized SQE storage; the input is deliberately
        // unrepresentable and must panic.
        unsafe { prep_close_direct(&mut sqe, UringFileSlot(u32::MAX)) };
    }
}
