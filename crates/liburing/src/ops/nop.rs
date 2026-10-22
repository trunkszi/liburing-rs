//! Pointer-free no-op submissions for completion routing.

use liburing_sys as sys;

/// Prepare a no-op without changing the caller-assigned completion identity.
///
/// # Safety
/// `sqe` must point to live, initialized, exclusively writable SQE storage.
///
/// # Panics
/// Does not panic.
pub unsafe fn prep_nop(sqe: *mut sys::io_uring_sqe) {
    // SAFETY: The caller guarantees exclusive initialized SQE storage.
    unsafe { sys::uring_shim_prep_nop(sqe) };
}
