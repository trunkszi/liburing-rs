//! Worker affinity, polling configuration and ring memory control.
use uarch::prelude::cold_sink;

use super::{RegisterTarget, count};
use crate::{
    Result,
    backend::sys::{params::IoUringParams, register::*},
};

/// Sets a native CPU affinity bitmap; the count is bytes, not CPU count.
/// # Errors
/// Returns syscall errors with positive errno and rejects counts larger than u32.
/// Successful return values preserve the kernel result, including partial updates.
/// # Panics
/// Does not panic.
/// # Safety
/// Use a live ring in the calling task and initialized records with zero reserved fields.
/// All embedded pointers must have the required extent and read/write access.
/// Retain registered memory and referenced resources through final kernel use;
/// unregister or resize only after quiescing affected operations and mappings.
#[cold_sink]
pub unsafe fn register_iowq_aff(target: RegisterTarget, mask: &[u8]) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterIowqAff,
            mask.as_ptr().cast_mut().cast(),
            count(mask.len())?,
        )
    }
}

/// Restores default worker affinity.
/// # Errors
/// Returns syscall errors with positive errno and rejects counts larger than u32.
/// Successful return values preserve the kernel result, including partial updates.
/// # Panics
/// Does not panic.
/// # Safety
/// Use a live ring in the calling task and initialized records with zero reserved fields.
/// All embedded pointers must have the required extent and read/write access.
/// Retain registered memory and referenced resources through final kernel use;
/// unregister or resize only after quiescing affected operations and mappings.
#[cold_sink]
pub unsafe fn unregister_iowq_aff(target: RegisterTarget) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe { target.register(RegisterOpcode::UnregisterIowqAff, core::ptr::null_mut(), 0) }
}

/// Sets bound/unbound worker limits and receives the previous limits.
/// # Errors
/// Returns syscall errors with positive errno and rejects counts larger than u32.
/// Successful return values preserve the kernel result, including partial updates.
/// # Panics
/// Does not panic.
/// # Safety
/// Use a live ring in the calling task and initialized records with zero reserved fields.
/// All embedded pointers must have the required extent and read/write access.
/// Retain registered memory and referenced resources through final kernel use;
/// unregister or resize only after quiescing affected operations and mappings.
#[cold_sink]
pub unsafe fn register_iowq_max_workers(
    target: RegisterTarget,
    workers: &mut [u32; 2],
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterIowqMaxWorkers,
            workers.as_mut_ptr().cast(),
            2,
        )
    }
}

/// Sets NAPI configuration and receives the previous configuration.
/// # Errors
/// Returns syscall errors with positive errno and rejects counts larger than u32.
/// Successful return values preserve the kernel result, including partial updates.
/// # Panics
/// Does not panic.
/// # Safety
/// Use a live ring in the calling task and initialized records with zero reserved fields.
/// All embedded pointers must have the required extent and read/write access.
/// Retain registered memory and referenced resources through final kernel use;
/// unregister or resize only after quiescing affected operations and mappings.
#[cold_sink]
pub unsafe fn register_napi(target: RegisterTarget, record: &mut IoUringNapi) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterNapi,
            (record as *mut IoUringNapi).cast(),
            1,
        )
    }
}

/// Disables NAPI tracking and receives its previous configuration.
/// # Errors
/// Returns syscall errors with positive errno and rejects counts larger than u32.
/// Successful return values preserve the kernel result, including partial updates.
/// # Panics
/// Does not panic.
/// # Safety
/// Use a live ring in the calling task and initialized records with zero reserved fields.
/// All embedded pointers must have the required extent and read/write access.
/// Retain registered memory and referenced resources through final kernel use;
/// unregister or resize only after quiescing affected operations and mappings.
#[cold_sink]
pub unsafe fn unregister_napi(target: RegisterTarget, record: &mut IoUringNapi) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::UnregisterNapi,
            (record as *mut IoUringNapi).cast(),
            1,
        )
    }
}

/// Selects the ring clock; nr_args must be zero.
/// # Errors
/// Returns syscall errors with positive errno and rejects counts larger than u32.
/// Successful return values preserve the kernel result, including partial updates.
/// # Panics
/// Does not panic.
/// # Safety
/// Use a live ring in the calling task and initialized records with zero reserved fields.
/// All embedded pointers must have the required extent and read/write access.
/// Retain registered memory and referenced resources through final kernel use;
/// unregister or resize only after quiescing affected operations and mappings.
#[cold_sink]
pub unsafe fn register_clock(target: RegisterTarget, record: &IoUringClockRegister) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterClock,
            (record as *const IoUringClockRegister).cast_mut().cast(),
            0,
        )
    }
}

/// Resizes an exclusively quiesced ring. The caller must remap and replace all old views.
/// # Errors
/// Returns syscall errors with positive errno and rejects counts larger than u32.
/// Successful return values preserve the kernel result, including partial updates.
/// # Panics
/// Does not panic.
/// # Safety
/// Use a live ring in the calling task and initialized records with zero reserved fields.
/// All embedded pointers must have the required extent and read/write access.
/// Retain registered memory and referenced resources through final kernel use;
/// unregister or resize only after quiescing affected operations and mappings.
#[cold_sink]
pub unsafe fn register_resize_rings(
    target: RegisterTarget,
    record: &mut IoUringParams,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterResizeRings,
            (record as *mut IoUringParams).cast(),
            1,
        )
    }
}

/// Registers a region whose pointed-to descriptor can be updated by the kernel.
/// # Errors
/// Returns syscall errors with positive errno and rejects counts larger than u32.
/// Successful return values preserve the kernel result, including partial updates.
/// # Panics
/// Does not panic.
/// # Safety
/// Use a live ring in the calling task and initialized records with zero reserved fields.
/// All embedded pointers must have the required extent and read/write access.
/// Retain registered memory and referenced resources through final kernel use;
/// unregister or resize only after quiescing affected operations and mappings.
#[cold_sink]
pub unsafe fn register_mem_region(
    target: RegisterTarget,
    record: &mut IoUringMemRegionReg,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterMemRegion,
            (record as *mut IoUringMemRegionReg).cast(),
            1,
        )
    }
}
