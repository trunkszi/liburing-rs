//! Internal generation tracking and caller-identity translation.

use std::{collections::VecDeque, os::fd::OwnedFd, rc::Rc};

use crate::{
    OperationId, Result, SubsystemId, UringError,
    backend::{self, RawSqe},
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
    pub(crate) key: Option<OperationKey>,
}

pub(crate) fn validate(sqe: &RawSqe) -> Result<()> {
    if u32::from(sqe.flags)
        & (backend::IOSQE_IO_DRAIN | backend::IOSQE_IO_LINK | backend::IOSQE_IO_HARDLINK)
        != 0
    {
        return Err(UringError::InvalidPreparedSqe(
            "drain and linked operations cannot span bounded submission batches",
        ));
    }
    if u32::from(sqe.flags) & backend::IOSQE_CQE_SKIP_SUCCESS != 0 {
        return Err(UringError::InvalidPreparedSqe(
            "every operation must deliver a final completion",
        ));
    }
    if sqe.opcode == io_uring::opcode::MsgRingData::CODE {
        return Err(UringError::InvalidPreparedSqe(
            "message ring bypasses generation tracking",
        ));
    }
    Ok(())
}

pub(crate) enum OperationIdentity {
    Caller(OperationId),
    Keyed(SubsystemId),
}

pub(crate) fn stage(
    staged: &mut VecDeque<StagedSqe>,
    capacity: usize,
    operations: &mut OperationSlab<TrackedOperation>,
    identities: &mut crate::identity_map::IdentityMap,
    identity: OperationIdentity,
    mut sqe: RawSqe,
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
        return Err(UringError::InvalidSubsystemId(0));
    }
    if !keyed && (original.raw() == u64::MAX || identities.contains_key(&original)) {
        return Err(UringError::InvalidPayload(original.raw()));
    }
    if staged.len() == capacity {
        return Err(UringError::SqRingFull);
    }
    validate(&sqe)?;
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
    let key = operations.insert(
        TrackedOperation {
            original,
            keyed,
            buffer: None,
            socket: None,
        },
        kind,
    )?;
    if keyed {
        original = OperationId::pack(original.subsystem_id(), key.payload());
    }
    let metadata = operations.get_mut(key)?;
    metadata.original = original;
    metadata.buffer = buffer.0.take();
    metadata.socket = buffer.1.take();
    if let Some(target) = target {
        operations.mark_canceling(target)?;
    }
    sqe.user_data = OperationId::pack(original.subsystem_id(), key.payload()).raw();
    if !keyed && let Err(error) = identities.insert(original, key) {
        // SAFETY: No SQE containing this fresh key has been published or staged.
        let metadata = unsafe { operations.discard_unsubmitted(key) }?;
        metadata.release()?;
        return Err(error);
    }
    staged.push_back(StagedSqe {
        sqe,
        key: Some(key),
    });
    Ok(key)
}
