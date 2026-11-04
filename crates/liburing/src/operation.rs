//! Internal generation tracking and caller-identity translation.

use std::{collections::VecDeque, os::fd::OwnedFd, rc::Rc};

use uarch::prelude::{assert_layout, cache_line, cold_sink, hot_inline};

use crate::{
    BufferGroupId, OperationId, Result, SubsystemId, UringError,
    backend::{self, RawSqe},
    config::OpcodeSet,
    fixed_buffers::InFlightWaitingBuffer,
    operation_slab::{OperationKey, OperationKind, OperationSlab},
};

pub(crate) struct TrackedOperation {
    pub(crate) original: OperationId,
    pub(crate) keyed: bool,
    pub(crate) selected_buffer_group: Option<BufferGroupId>,
    pub(crate) buffer: Option<InFlightWaitingBuffer>,
    pub(crate) socket: Option<Rc<OwnedFd>>,
}

impl TrackedOperation {
    #[inline]
    pub(crate) fn release(mut self) -> Result<()> {
        if let Some(buffer) = self.buffer.take() {
            // SAFETY: Called only after terminal slab observation, including the
            // required notification, or rollback before publishing the SQE.
            drop(unsafe { buffer.complete() }?);
        }
        drop(self.socket.take());
        Ok(())
    }
}

pub(crate) struct PendingBuffer(
    pub(crate) Option<InFlightWaitingBuffer>,
    pub(crate) Option<Rc<OwnedFd>>,
);

impl Drop for PendingBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.0.take() {
            // SAFETY: The guard still owns the token only before publication.
            // A successfully staged operation takes the token out of this guard.
            drop(unsafe { buffer.complete() });
        }
    }
}

#[cache_line]
pub(crate) struct StagedSqe {
    pub(crate) sqe: RawSqe,
}

assert_layout!(StagedSqe, size = 64, align = 64, fields = {sqe:0});

const FORBIDDEN_SQE_FLAGS: u8 = (backend::IOSQE_IO_DRAIN
    | backend::IOSQE_IO_LINK
    | backend::IOSQE_IO_HARDLINK
    | backend::IOSQE_CQE_SKIP_SUCCESS) as u8;

#[cold_sink]
fn reject_sqe_flags(flags: u8) -> Result<()> {
    if flags & (backend::IOSQE_IO_DRAIN | backend::IOSQE_IO_LINK | backend::IOSQE_IO_HARDLINK) as u8
        != 0
    {
        Err(UringError::InvalidPreparedSqe(
            "drain and linked operations cannot span bounded submission batches",
        ))
    } else {
        Err(UringError::InvalidPreparedSqe(
            "every operation must deliver a final completion",
        ))
    }
}

#[hot_inline]
pub(crate) fn validate(sqe: &RawSqe, admission: OpcodeSet, mode_name: &'static str) -> Result<()> {
    if !admission.contains(sqe.opcode) {
        return opcode_not_admitted(sqe.opcode, mode_name);
    }
    if matches!(
        sqe.opcode,
        crate::backend::sys::sqe::IORING_OP_NOP128
            | crate::backend::sys::sqe::IORING_OP_URING_CMD128
    ) {
        return Err(UringError::InvalidPreparedSqe(
            "wide opcode requires a native SQE128 or mixed ring",
        ));
    }
    if sqe.opcode == backend::sys::sqe::IORING_OP_POLL_REMOVE && sqe.len & (1 << 2) != 0 {
        return Err(UringError::InvalidPreparedSqe(
            "poll user_data update is not supported on Proactor-managed operations",
        ));
    }
    if sqe.flags & FORBIDDEN_SQE_FLAGS != 0 {
        return reject_sqe_flags(sqe.flags);
    }
    if sqe.opcode == crate::backend::opcode::MsgRingData::CODE {
        return message_ring_rejected();
    }
    Ok(())
}

pub(crate) enum OperationIdentity {
    Caller(OperationId),
    Keyed(SubsystemId),
}

#[allow(clippy::too_many_arguments)]
#[hot_inline]
pub(crate) fn stage(
    staged: &mut VecDeque<StagedSqe>,
    capacity: usize,
    admission: OpcodeSet,
    mode_name: &'static str,
    operations: &mut OperationSlab<TrackedOperation>,
    identities: &mut crate::identity_map::IdentityMap,
    identity: OperationIdentity,
    prepare: impl FnOnce(*mut RawSqe),
    mut buffer: PendingBuffer,
) -> Result<OperationKey> {
    let (mut original, keyed) = match identity {
        OperationIdentity::Caller(id) => (id, false),
        OperationIdentity::Keyed(subsystem) => (
            OperationId::pack(subsystem, crate::OperationPayload(0)),
            true,
        ),
    };
    if original.subsystem_id() == SubsystemId::INTERNAL {
        return internal_subsystem();
    }
    let vacant_slot = if keyed {
        None
    } else {
        Some(identities.probe_vacant(original)?)
    };
    if staged.len() >= capacity || operations.available() == 0 {
        return Err(UringError::SqRingFull);
    }
    let mut sqe = RawSqe::default();
    prepare(&raw mut sqe);
    validate(&sqe, admission, mode_name)?;
    let kind = operation_kind(&sqe);
    let translate_target = match sqe.opcode {
        backend::sys::sqe::IORING_OP_ASYNC_CANCEL => sqe.operation_flags & (2 | 4) == 0,
        backend::sys::sqe::IORING_OP_POLL_REMOVE | backend::sys::sqe::IORING_OP_TIMEOUT_REMOVE => {
            true
        }
        _ => false,
    };
    let cancels_target = match sqe.opcode {
        backend::sys::sqe::IORING_OP_POLL_REMOVE => sqe.len == 0,
        backend::sys::sqe::IORING_OP_TIMEOUT_REMOVE => sqe.operation_flags & (1 << 1) == 0,
        _ => true,
    };
    let target = if translate_target {
        let id = OperationId::from_raw(sqe.addr);
        if keyed {
            OperationKey::from_payload(id.payload()).ok().filter(|key| {
                operations
                    .get(*key)
                    .is_ok_and(|metadata| metadata.original == id && metadata.keyed)
            })
        } else {
            identities.get(&id).copied()
        }
    } else {
        None
    };
    if translate_target {
        sqe.addr = match target {
            Some(key) => {
                let target = operations.get(key)?.original;
                OperationId::pack(target.subsystem_id(), key.payload()).raw()
            }
            None if sqe.opcode == backend::sys::sqe::IORING_OP_TIMEOUT_REMOVE => {
                return Err(UringError::UnknownOperation(OperationId::from_raw(
                    sqe.addr,
                )));
            }
            None => 0,
        };
    }
    let key = operations.insert_with(kind, |key| {
        if keyed {
            original = OperationId::pack(original.subsystem_id(), key.payload());
        }
        TrackedOperation {
            original,
            keyed,
            selected_buffer_group: (sqe.flags & backend::IOSQE_BUFFER_SELECT as u8 != 0)
                .then_some(BufferGroupId(sqe.buf_index)),
            buffer: buffer.0.take(),
            socket: buffer.1.take(),
        }
    })?;
    if let Some(target) = target.filter(|_| cancels_target) {
        operations.mark_canceling(target)?;
    }
    sqe.user_data = OperationId::pack(original.subsystem_id(), key.payload()).raw();
    if let Some(slot) = vacant_slot {
        identities.insert_at(slot, original, key);
    }
    staged.push_back(StagedSqe { sqe });
    Ok(key)
}

#[cold_sink]
fn opcode_not_admitted<T>(opcode: u8, mode: &'static str) -> Result<T> {
    Err(UringError::OpcodeNotAdmitted { opcode, mode })
}

#[cold_sink]
fn message_ring_rejected<T>() -> Result<T> {
    Err(UringError::InvalidPreparedSqe(
        "message ring bypasses generation tracking",
    ))
}

#[cold_sink]
pub(crate) fn internal_subsystem<T>() -> Result<T> {
    Err(UringError::InvalidSubsystemId(0))
}

#[hot_inline]
fn operation_kind(sqe: &RawSqe) -> OperationKind {
    use backend::sys::sqe::*;
    match sqe.opcode {
        IORING_OP_SEND_ZC | IORING_OP_SENDMSG_ZC => OperationKind::ZeroCopy,
        IORING_OP_ASYNC_CANCEL | IORING_OP_POLL_REMOVE | IORING_OP_TIMEOUT_REMOVE => {
            OperationKind::CancelControl
        }
        IORING_OP_READ_MULTISHOT | IORING_OP_RECV_ZC => OperationKind::Multishot,
        IORING_OP_RECV | IORING_OP_RECVMSG if sqe.ioprio & IORING_RECV_MULTISHOT != 0 => {
            OperationKind::Multishot
        }
        IORING_OP_ACCEPT if sqe.ioprio & 1 != 0 => OperationKind::Multishot,
        IORING_OP_POLL_ADD if sqe.len & 1 != 0 => OperationKind::Multishot,
        IORING_OP_TIMEOUT if sqe.operation_flags & (1 << 6) != 0 => OperationKind::Multishot,
        IORING_OP_URING_CMD if sqe.operation_flags & (1 << 1) != 0 => OperationKind::Multishot,
        _ => OperationKind::Single,
    }
}

#[cfg(test)]
#[path = "../tests/operation/classification.rs"]
mod classification_tests;
