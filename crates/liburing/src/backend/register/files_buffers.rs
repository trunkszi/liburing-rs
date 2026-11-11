//! Fixed file, buffer and task-local ring tables. Calls do not own their operands.
use std::os::fd::RawFd;

use uarch::prelude::cold_sink;

use super::{RegisterTarget, count};
use crate::{Result, backend::sys::register::*};

/// Registers buffers; retain every referenced allocation through final DMA and unregister.
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
pub unsafe fn register_buffers(target: RegisterTarget, buffers: &[libc::iovec]) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterBuffers,
            buffers.as_ptr().cast_mut().cast(),
            count(buffers.len())?,
        )
    }
}

/// Unregisters the fixed buffer table after its users have finished.
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
pub unsafe fn unregister_buffers(target: RegisterTarget) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe { target.register(RegisterOpcode::UnregisterBuffers, core::ptr::null_mut(), 0) }
}

/// Registers file descriptors; the kernel acquires its own references.
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
pub unsafe fn register_files(target: RegisterTarget, files: &[RawFd]) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterFiles,
            files.as_ptr().cast_mut().cast(),
            count(files.len())?,
        )
    }
}

/// Unregisters the fixed file table.
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
pub unsafe fn unregister_files(target: RegisterTarget) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe { target.register(RegisterOpcode::UnregisterFiles, core::ptr::null_mut(), 0) }
}

/// Registers sparse or tagged file slots from the pointed-to arrays.
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
pub unsafe fn register_files2(target: RegisterTarget, record: &IoUringRsrcRegister) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterFiles2,
            (record as *const IoUringRsrcRegister).cast_mut().cast(),
            size_of::<IoUringRsrcRegister>() as u32,
        )
    }
}

/// Updates tagged file slots and preserves the kernel partial-update count.
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
pub unsafe fn register_files_update2(
    target: RegisterTarget,
    record: &IoUringRsrcUpdate2,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterFilesUpdate2,
            (record as *const IoUringRsrcUpdate2).cast_mut().cast(),
            size_of::<IoUringRsrcUpdate2>() as u32,
        )
    }
}

/// Registers sparse or tagged buffers from the pointed-to arrays.
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
pub unsafe fn register_buffers2(
    target: RegisterTarget,
    record: &IoUringRsrcRegister,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterBuffers2,
            (record as *const IoUringRsrcRegister).cast_mut().cast(),
            size_of::<IoUringRsrcRegister>() as u32,
        )
    }
}

/// Updates tagged buffers while preserving old resources through their final CQEs.
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
pub unsafe fn register_buffers_update(
    target: RegisterTarget,
    record: &IoUringRsrcUpdate2,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterBuffersUpdate,
            (record as *const IoUringRsrcUpdate2).cast_mut().cast(),
            size_of::<IoUringRsrcUpdate2>() as u32,
        )
    }
}

/// Registers task-local ring slots; updated offsets identify allocations. Preserve partial counts.
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
pub unsafe fn register_ring_fds(
    target: RegisterTarget,
    updates: &mut [IoUringRsrcUpdate],
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterRingFds,
            updates.as_mut_ptr().cast(),
            count(updates.len())?,
        )
    }
}

/// Unregisters the task-local slots named by each update offset.
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
pub unsafe fn unregister_ring_fds(
    target: RegisterTarget,
    updates: &[IoUringRsrcUpdate],
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::UnregisterRingFds,
            updates.as_ptr().cast_mut().cast(),
            count(updates.len())?,
        )
    }
}

/// Registers provided buffers, including MMAP and incremental modes selected by flags.
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
pub unsafe fn register_pbuf_ring(
    target: RegisterTarget,
    record: &mut IoUringBufReg,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterPbufRing,
            (record as *mut IoUringBufReg).cast(),
            1,
        )
    }
}

/// Reads a provided-buffer group head into the caller record.
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
pub unsafe fn register_pbuf_status(
    target: RegisterTarget,
    record: &mut IoUringBufStatus,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterPbufStatus,
            (record as *mut IoUringBufStatus).cast(),
            1,
        )
    }
}

/// Sets the allocation range for direct file descriptors; nr_args must be zero.
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
pub unsafe fn register_file_alloc_range(
    target: RegisterTarget,
    record: &IoUringFileIndexRange,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterFileAllocRange,
            (record as *const IoUringFileIndexRange).cast_mut().cast(),
            0,
        )
    }
}

/// Clones buffer registrations; the record selects the source descriptor namespace.
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
pub unsafe fn register_clone_buffers(
    target: RegisterTarget,
    record: &IoUringCloneBuffers,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterCloneBuffers,
            (record as *const IoUringCloneBuffers).cast_mut().cast(),
            1,
        )
    }
}

/// Updates file descriptors starting at the given table offset.
/// # Errors
/// Returns syscall errors or an overflowing count; preserves partial-update counts.
/// # Panics
/// Does not panic.
/// # Safety
/// The ring and table must be live and updates must preserve in-flight resource ownership.
#[cold_sink]
pub unsafe fn register_files_update(
    target: RegisterTarget,
    offset: u32,
    files: &[RawFd],
) -> Result<u32> {
    let record = IoUringFilesUpdate {
        offset,
        fds: files.as_ptr() as u64,
        ..Default::default()
    };
    // SAFETY: The descriptor slice and stack record are initialized and live for the call.
    unsafe {
        target.register(
            RegisterOpcode::RegisterFilesUpdate,
            (&raw const record).cast_mut().cast(),
            count(files.len())?,
        )
    }
}

/// Unregisters a provided-buffer group.
/// # Errors
/// Propagates the kernel error.
/// # Panics
/// Does not panic.
/// # Safety
/// No operation or lease may still use the group's buffers or mapped ring storage.
#[cold_sink]
pub unsafe fn unregister_pbuf_ring(target: RegisterTarget, group: u16) -> Result<u32> {
    let record = IoUringBufReg {
        bgid: group,
        ..Default::default()
    };
    // SAFETY: The initialized record is live and the caller has quiesced all group users.
    unsafe {
        target.register(
            RegisterOpcode::UnregisterPbufRing,
            (&raw const record).cast_mut().cast(),
            1,
        )
    }
}
