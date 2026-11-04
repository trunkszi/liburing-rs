//! Ring restrictions, identity, cancellation and optional zero-copy receive controls.
use std::os::fd::RawFd;

use uarch::prelude::cold_sink;

use super::RegisterTarget;
use crate::{
    Result, UringError,
    backend::sys::{
        query_bpf::IoUringBpf,
        register::*,
        sqe::{IORING_OP_ASYNC_CANCEL, IORING_OP_NOP, IOSQE_CQE_SKIP_SUCCESS, RawSqe},
        zcrx::*,
    },
};

/// Registers an eventfd notification source.
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
pub unsafe fn register_eventfd(target: RegisterTarget, fd: RawFd) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterEventfd,
            (&raw const fd).cast_mut().cast(),
            1,
        )
    }
}

/// Registers an eventfd for asynchronous completion notifications only.
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
pub unsafe fn register_eventfd_async(target: RegisterTarget, fd: RawFd) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterEventfdAsync,
            (&raw const fd).cast_mut().cast(),
            1,
        )
    }
}

/// Unregisters the eventfd notification source.
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
pub unsafe fn unregister_eventfd(target: RegisterTarget) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe { target.register(RegisterOpcode::UnregisterEventfd, core::ptr::null_mut(), 0) }
}

/// Registers caller credentials and returns the allocated personality identifier.
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
pub unsafe fn register_personality(target: RegisterTarget) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterPersonality,
            core::ptr::null_mut(),
            0,
        )
    }
}

/// Unregisters the personality identifier passed in nr_args.
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
pub unsafe fn unregister_personality(target: RegisterTarget, id: u32) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::UnregisterPersonality,
            core::ptr::null_mut(),
            id,
        )
    }
}

/// Enables a ring created with R_DISABLED after installing restrictions.
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
pub unsafe fn register_enable_rings(target: RegisterTarget) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterEnableRings,
            core::ptr::null_mut(),
            0,
        )
    }
}

/// Synchronously cancels matching operations; this can block and must stay outside RTC hooks.
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
pub unsafe fn register_sync_cancel(
    target: RegisterTarget,
    record: &IoUringSyncCancelReg,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterSyncCancel,
            (record as *const IoUringSyncCancelReg).cast_mut().cast(),
            1,
        )
    }
}

/// Registers a zero-copy receive interface; embedded area and region storage must remain valid.
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
pub unsafe fn register_zcrx_ifq(
    target: RegisterTarget,
    record: &mut IoUringZcrxIfqReg,
) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterZcrxIfq,
            (record as *mut IoUringZcrxIfqReg).cast(),
            1,
        )
    }
}

/// Controls a zero-copy receive interface; exported fds must be adopted exactly once.
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
pub unsafe fn register_zcrx_ctrl(target: RegisterTarget, record: &mut ZcrxCtrl) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterZcrxCtrl,
            (record as *mut ZcrxCtrl).cast(),
            0,
        )
    }
}

/// Installs a BPF filter from the pointed-to initialized instruction array.
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
pub unsafe fn register_bpf_filter(target: RegisterTarget, record: &IoUringBpf) -> Result<u32> {
    // SAFETY: The caller guarantees record validity, namespace and resource lifetimes.
    unsafe {
        target.register(
            RegisterOpcode::RegisterBpfFilter,
            (record as *const IoUringBpf).cast_mut().cast(),
            1,
        )
    }
}

/// Sends a synchronous MSG_RING SQE without a source ring descriptor.
/// # Errors
/// Propagates the syscall error; preserves the kernel result.
/// # Panics
/// Does not panic.
/// # Safety
/// The SQE must reference live destination resources. Any descriptor transfer and
/// completion delivery must be accounted for, including failures and partial work.
#[cold_sink]
pub unsafe fn register_send_msg_ring(sqe: &RawSqe) -> Result<u32> {
    // SAFETY: The caller owns destination resources; the source SQE is readable for this call.
    unsafe {
        RegisterTarget::VfsFd(-1).register(
            RegisterOpcode::RegisterSendMsgRing,
            (sqe as *const RawSqe).cast_mut().cast(),
            1,
        )
    }
}

/// Installs ring restrictions while retaining framework NOP, cancellation and teardown access.
/// SQE allowlisting retains NOP, cancellation and the padding skip-success flag.
/// Caller-supplied allowed flag bits are preserved.
/// A flags-only record still arms the kernel opcode allowlist, so those opcodes are injected.
/// Mandatory register entries are appended only when register allowlisting is present.
/// # Errors
/// Rejects exhausted restriction budgets, blind registration and nonzero required SQE flags.
/// Propagates syscall errors.
/// # Panics
/// Does not panic.
/// # Safety
/// The ring must be disabled and exclusively owned. The caller must account for
/// all other irreversible restrictions; no active operation may depend on disallowed work.
#[cold_sink]
pub unsafe fn register_restrictions(
    target: RegisterTarget,
    restrictions: &[IoUringRestriction],
) -> Result<u32> {
    const LIMIT: usize = IORING_RESTRICTION_LAST as usize
        + IORING_REGISTER_LAST as usize
        + crate::backend::sys::sqe::IORING_OP_LAST as usize;
    if restrictions.len() > LIMIT || matches!(target, RegisterTarget::VfsFd(-1)) {
        return Err(UringError::InvalidConfig(
            "invalid ring restriction request",
        ));
    }
    if restrictions.iter().any(|record| {
        record.opcode == IORING_RESTRICTION_SQE_FLAGS_REQUIRED && record.register_op != 0
    }) {
        return Err(UringError::InvalidConfig(
            "required SQE flags would reject framework control operations",
        ));
    }
    let mut records = [IoUringRestriction::default(); LIMIT];
    records[..restrictions.len()].copy_from_slice(restrictions);
    let mut len = restrictions.len();
    // Linux enables opcode filtering for an allowed-flag or required-flag record
    // even when no SQE_OP entry is present. An empty allowlist then rejects NOP.
    let sqe_restricted = restrictions.iter().any(|record| {
        matches!(
            record.opcode,
            IORING_RESTRICTION_SQE_OP
                | IORING_RESTRICTION_SQE_FLAGS_ALLOWED
                | IORING_RESTRICTION_SQE_FLAGS_REQUIRED
        )
    });
    let register_restricted = restrictions
        .iter()
        .any(|r| r.opcode == IORING_RESTRICTION_REGISTER_OP);
    if sqe_restricted {
        let mut flags_present = false;
        for record in &mut records[..len] {
            if record.opcode == IORING_RESTRICTION_SQE_FLAGS_ALLOWED {
                record.register_op |= IOSQE_CQE_SKIP_SUCCESS;
                flags_present = true;
            }
        }
        if !flags_present {
            if len == LIMIT {
                return Err(UringError::InvalidConfig("restriction budget exhausted"));
            }
            records[len] = IoUringRestriction {
                opcode: IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
                register_op: IOSQE_CQE_SKIP_SUCCESS,
                ..Default::default()
            };
            len += 1;
        }
    }
    for (enabled, kind, entries) in [
        (
            sqe_restricted,
            IORING_RESTRICTION_SQE_OP,
            &[IORING_OP_NOP, IORING_OP_ASYNC_CANCEL][..],
        ),
        (
            register_restricted,
            IORING_RESTRICTION_REGISTER_OP,
            &[
                IORING_UNREGISTER_BUFFERS as u8,
                IORING_UNREGISTER_FILES as u8,
                IORING_UNREGISTER_EVENTFD as u8,
                IORING_UNREGISTER_PERSONALITY as u8,
                IORING_UNREGISTER_IOWQ_AFF as u8,
                IORING_UNREGISTER_RING_FDS as u8,
                IORING_UNREGISTER_PBUF_RING as u8,
                IORING_UNREGISTER_NAPI as u8,
                IORING_REGISTER_SYNC_CANCEL as u8,
                IORING_REGISTER_ENABLE_RINGS as u8,
            ][..],
        ),
    ] {
        if !enabled {
            continue;
        }
        for &op in entries {
            if records[..len]
                .iter()
                .any(|r| r.opcode == kind && r.register_op == op)
            {
                continue;
            }
            if len == LIMIT {
                return Err(UringError::InvalidConfig("restriction budget exhausted"));
            }
            records[len] = IoUringRestriction {
                opcode: kind,
                register_op: op,
                ..Default::default()
            };
            len += 1;
        }
    }
    // SAFETY: Only initialized bounded records are passed, with no embedded pointers.
    unsafe {
        target.register(
            RegisterOpcode::RegisterRestrictions,
            records.as_mut_ptr().cast(),
            len as u32,
        )
    }
}
