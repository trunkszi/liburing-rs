//! Internal generation tracking and caller-identity translation.

use std::{collections::VecDeque, os::fd::OwnedFd, rc::Rc};

use crate::{
    OperationId, Result, SubsystemId, UringError,
    backend::{self, RawSqe},
    config::OpcodeSet,
    fixed_buffers::InFlightWaitingBuffer,
    operation_slab::{OperationKey, OperationKind, OperationSlab},
};

pub(crate) struct TrackedOperation {
    pub(crate) original: OperationId,
    pub(crate) keyed: bool,
    pub(crate) buffer: Option<InFlightWaitingBuffer>,
    pub(crate) socket: Option<Rc<OwnedFd>>,
}

impl TrackedOperation {
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

pub(crate) struct StagedSqe {
    pub(crate) sqe: RawSqe,
}

const _: () = assert!(size_of::<StagedSqe>() == 64);

const FORBIDDEN_SQE_FLAGS: u8 = (backend::IOSQE_IO_DRAIN
    | backend::IOSQE_IO_LINK
    | backend::IOSQE_IO_HARDLINK
    | backend::IOSQE_CQE_SKIP_SUCCESS) as u8;

#[cold]
#[inline(never)]
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

#[inline(always)]
pub(crate) fn validate(sqe: &RawSqe, admission: OpcodeSet, mode_name: &'static str) -> Result<()> {
    if !admission.contains(sqe.opcode) {
        return opcode_not_admitted(sqe.opcode, mode_name);
    }
    if sqe.flags & FORBIDDEN_SQE_FLAGS != 0 {
        return reject_sqe_flags(sqe.flags);
    }
    if sqe.opcode == io_uring::opcode::MsgRingData::CODE {
        return message_ring_rejected();
    }
    Ok(())
}

pub(crate) enum OperationIdentity {
    Caller(OperationId),
    Keyed(SubsystemId),
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
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
    let kind = if matches!(
        sqe.opcode,
        io_uring::opcode::SendZc::CODE | io_uring::opcode::SendMsgZc::CODE
    ) {
        OperationKind::ZeroCopy
    } else if sqe.opcode == io_uring::opcode::AsyncCancel::CODE
        || sqe.opcode == io_uring::opcode::PollRemove::CODE
    {
        OperationKind::CancelControl
    } else if (sqe.opcode == io_uring::opcode::Recv::CODE && sqe.ioprio & 2 != 0)
        || (sqe.opcode == io_uring::opcode::Accept::CODE && sqe.ioprio & 1 != 0)
        || (sqe.opcode == io_uring::opcode::PollAdd::CODE && sqe.len & 1 != 0)
    {
        OperationKind::Multishot
    } else {
        OperationKind::Single
    };
    let target = if kind == OperationKind::CancelControl && sqe.operation_flags & (2 | 4) == 0 {
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
    if kind == OperationKind::CancelControl && sqe.operation_flags & (2 | 4) == 0 {
        sqe.addr = match target {
            Some(key) => {
                let target = operations.get(key)?.original;
                OperationId::pack(target.subsystem_id(), key.payload()).raw()
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
            buffer: buffer.0.take(),
            socket: buffer.1.take(),
        }
    })?;
    if let Some(target) = target {
        operations.mark_canceling(target)?;
    }
    sqe.user_data = OperationId::pack(original.subsystem_id(), key.payload()).raw();
    if let Some(slot) = vacant_slot {
        identities.insert_at(slot, original, key);
    }
    staged.push_back(StagedSqe { sqe });
    Ok(key)
}

#[cold]
#[inline(never)]
fn opcode_not_admitted<T>(opcode: u8, mode: &'static str) -> Result<T> {
    Err(UringError::OpcodeNotAdmitted { opcode, mode })
}

#[cold]
#[inline(never)]
fn message_ring_rejected<T>() -> Result<T> {
    Err(UringError::InvalidPreparedSqe(
        "message ring bypasses generation tracking",
    ))
}

#[cold]
#[inline(never)]
pub(crate) fn internal_subsystem<T>() -> Result<T> {
    Err(UringError::InvalidSubsystemId(0))
}
