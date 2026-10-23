//! Caller-owned static completion dispatch and bounded submission capabilities.

use std::collections::VecDeque;

use crate::{
    BufferGroupId, OperationId, Result, SubsystemId, UringError,
    backend::RawSqe,
    buffer_ring::BufferRing,
    fixed_buffers::{FixedBufferPool, InFlightWaitingBuffer},
    operation::{self, PendingBuffer, StagedSqe, TrackedOperation},
    operation_slab::{OperationKey, OperationSlab},
    proactor::resources::Resources,
};

/// A copied completion independent of the mmap completion-queue lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub operation_id: OperationId,
    pub result: i32,
    pub flags: u32,
}

/// Monomorphized dispatch over state retained by the caller, never the ring.
/// Custom dispatchers and their mutable borrows use the default kind. Closures
/// infer [`ClosureDispatch`]; generic wrappers accepting both carry a `Kind`
/// parameter with a `D: CompletionDispatcher<Kind>` bound.
pub trait CompletionDispatcher<Kind = ()> {
    /// Handles one completion and stages any follow-up work.
    /// # Errors
    /// Returns a business or submission error after this CQE has been consumed.
    /// # Panics
    /// May propagate a callback panic; the completion batch is still acknowledged.
    fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()>;
}

/// Inferred dispatch kind for closures, disjoint from borrowed dispatcher impls.
pub enum ClosureDispatch {}

impl<D: CompletionDispatcher + ?Sized> CompletionDispatcher for &mut D {
    fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        (**self).dispatch(completion, submissions)
    }
}

impl<F> CompletionDispatcher<ClosureDispatch> for F
where
    F: FnMut(Completion, &mut SubmissionContext<'_>) -> Result<()>,
{
    fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        self(completion, submissions)
    }
}

/// A callback's fixed-capacity submission capability and registered resources.
pub struct SubmissionContext<'a> {
    pub(crate) staged: &'a mut VecDeque<StagedSqe>,
    pub(crate) capacity: usize,
    pub(crate) operations: &'a mut OperationSlab<TrackedOperation>,
    pub(crate) identities: &'a mut crate::identity_map::IdentityMap,
    pub(crate) resources: &'a Resources,
    pub(crate) pending_cancels: &'a mut usize,
    pub(crate) current_completion: Option<Completion>,
}

impl SubmissionContext<'_> {
    /// Claims the current authenticated CQE once for safe DMA payload handoff.
    /// A mismatch preserves the rightful claim; successful claims cannot replay.
    /// # Errors
    /// Rejects forged metadata or a completion that has already been claimed.
    /// # Panics
    /// Does not panic.
    pub fn claim_completion(&mut self, completion: Completion) -> Result<()> {
        if self.current_completion != Some(completion) {
            return Err(UringError::InvalidConfig(
                "completion is not the unclaimed current CQE",
            ));
        }
        self.current_completion = None;
        Ok(())
    }

    /// Stages cancellation without consuming an application operation slot.
    /// # Errors
    /// Returns staging-capacity or operation-state errors.
    /// # Panics
    /// Does not panic.
    pub fn cancel(&mut self, target: OperationId) -> Result<bool> {
        let Some(&key) = self.identities.get(&target) else {
            return Ok(false);
        };
        self.cancel_key(key)
    }

    /// Stages cancellation for exactly one current ring generation.
    /// # Errors
    /// Returns staging-capacity or operation-state errors.
    /// # Panics
    /// Does not panic.
    pub fn cancel_key(&mut self, key: OperationKey) -> Result<bool> {
        let Ok(operation) = self.operations.get(key) else {
            return Ok(false);
        };
        let original = operation.original;
        if self.operations.state(key)? != crate::operation_slab::OperationState::InFlight {
            return Ok(true);
        }
        if self.staged.len() >= self.capacity {
            return Err(UringError::SqRingFull);
        }
        let sqe = RawSqe::from_entry(
            io_uring::opcode::AsyncCancel::new(
                OperationId::pack(original.subsystem_id(), key.payload()).raw(),
            )
            .build()
            .user_data(crate::proactor::INTERNAL_TARGET_CANCEL),
        );
        self.operations.mark_canceling(key)?;
        self.staged.push_back(StagedSqe { sqe, key: None });
        *self.pending_cancels += 1;
        Ok(true)
    }

    /// Stages socket DMA while retaining its descriptor and optional fixed token.
    /// # Errors
    /// Returns identity, flag, or fixed-capacity errors.
    /// # Panics
    /// Propagates preparation panics before publication.
    pub fn prepare_owned_sqe_with<F>(
        &mut self,
        id: OperationId,
        socket: std::rc::Rc<std::os::fd::OwnedFd>,
        buffer: Option<InFlightWaitingBuffer>,
        prepare: F,
    ) -> Result<()>
    where
        F: FnOnce(*mut RawSqe),
    {
        self.prepare(id, PendingBuffer(buffer, Some(socket)), prepare)
    }

    /// Stages a pointer-compatible pure Rust SQE with generation tracking.
    /// # Errors
    /// Returns invalid identity, unsafe flags, duplicate identity, or capacity errors.
    /// # Panics
    /// Propagates a preparation panic before publishing the operation.
    pub fn prepare_sqe_with<F>(&mut self, id: OperationId, prepare: F) -> Result<()>
    where
        F: FnOnce(*mut RawSqe),
    {
        self.prepare(id, PendingBuffer(None, None), prepare)
    }

    /// Retains a registered DMA token through target and notification completion.
    /// # Errors
    /// Returns identity, preparation validation, or fixed-capacity errors.
    /// # Panics
    /// Propagates a preparation panic; an unsubmitted token is safely returned.
    pub fn prepare_buffer_sqe_with<F>(
        &mut self,
        id: OperationId,
        buffer: InFlightWaitingBuffer,
        prepare: F,
    ) -> Result<()>
    where
        F: FnOnce(*mut RawSqe),
    {
        self.prepare(id, PendingBuffer(Some(buffer), None), prepare)
    }

    /// Allocates a generation identity without hashing a caller payload.
    /// Completions carry `OperationId::pack(subsystem, key.payload())`.
    /// Use `cancel_key` for direct generation cancellation.
    /// # Errors
    /// Returns reserved-subsystem, invalid-SQE, or fixed-capacity errors.
    /// # Panics
    /// Propagates preparation panics before publication.
    pub fn prepare_keyed_sqe_with<F>(
        &mut self,
        subsystem: SubsystemId,
        prepare: F,
    ) -> Result<OperationKey>
    where
        F: FnOnce(*mut RawSqe),
    {
        self.prepare_keyed(subsystem, PendingBuffer(None, None), prepare)
    }

    /// Allocates a hash-free generation and retains its DMA token until final CQE.
    /// # Errors
    /// Returns reserved-subsystem, invalid-SQE, or fixed-capacity errors.
    /// # Panics
    /// Propagates preparation panics, returning unsubmitted tokens safely.
    pub fn prepare_keyed_buffer_sqe_with<F>(
        &mut self,
        subsystem: SubsystemId,
        buffer: InFlightWaitingBuffer,
        prepare: F,
    ) -> Result<OperationKey>
    where
        F: FnOnce(*mut RawSqe),
    {
        self.prepare_keyed(subsystem, PendingBuffer(Some(buffer), None), prepare)
    }

    /// Allocates a hash-free generation retaining a descriptor and optional DMA token.
    /// # Errors
    /// Returns reserved-subsystem, invalid-SQE, or fixed-capacity errors.
    /// # Panics
    /// Propagates preparation panics before publication.
    pub fn prepare_keyed_owned_sqe_with<F>(
        &mut self,
        subsystem: SubsystemId,
        socket: std::rc::Rc<std::os::fd::OwnedFd>,
        buffer: Option<InFlightWaitingBuffer>,
        prepare: F,
    ) -> Result<OperationKey>
    where
        F: FnOnce(*mut RawSqe),
    {
        self.prepare_keyed(subsystem, PendingBuffer(buffer, Some(socket)), prepare)
    }

    fn prepare_keyed<F>(
        &mut self,
        subsystem: SubsystemId,
        buffer: PendingBuffer,
        prepare: F,
    ) -> Result<OperationKey>
    where
        F: FnOnce(*mut RawSqe),
    {
        if subsystem == SubsystemId::INTERNAL {
            return Err(UringError::InvalidSubsystemId(0));
        }
        if self.remaining_capacity() == 0 {
            return Err(UringError::SqRingFull);
        }
        let mut sqe = RawSqe::default();
        prepare(&raw mut sqe);
        operation::stage(
            self.staged,
            self.capacity,
            self.operations,
            self.identities,
            operation::OperationIdentity::Keyed(subsystem),
            sqe,
            buffer,
        )
    }

    fn prepare<F>(&mut self, id: OperationId, buffer: PendingBuffer, prepare: F) -> Result<()>
    where
        F: FnOnce(*mut RawSqe),
    {
        if id.subsystem_id() == crate::SubsystemId::INTERNAL {
            return Err(UringError::InvalidSubsystemId(0));
        }
        if id.raw() == u64::MAX || self.identities.contains_key(&id) {
            return Err(UringError::InvalidPayload(id.raw()));
        }
        if self.remaining_capacity() == 0 {
            return Err(UringError::SqRingFull);
        }
        let mut sqe = RawSqe::default();
        prepare(&raw mut sqe);
        operation::stage(
            self.staged,
            self.capacity,
            self.operations,
            self.identities,
            operation::OperationIdentity::Caller(id),
            sqe,
            buffer,
        )
        .map(|_| ())
    }

    /// Reports remaining staging and operation-slot credit.
    /// # Errors
    /// This function does not return errors.
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        self.capacity
            .saturating_sub(self.staged.len())
            .min(self.operations.available())
    }

    /// Borrows a provided-buffer group for zero-copy CQE payload handoff.
    /// # Errors
    /// Returns an error for an unregistered group.
    /// # Panics
    /// Does not panic.
    pub fn buffer_ring(&self, group: BufferGroupId) -> Result<&BufferRing> {
        self.resources.group(group)
    }

    /// Borrows the registered fixed-buffer pool.
    /// # Errors
    /// Returns an error if fixed buffers have not been configured.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// Every derived handle must be released or retained in a tracked operation
    /// before the proactor shuts down; handles must not outlive the kernel ring.
    pub unsafe fn fixed_buffers(&self) -> Result<&FixedBufferPool> {
        self.resources
            .buffers
            .as_ref()
            .ok_or(UringError::InvalidConfig(
                "fixed buffers are not registered",
            ))
    }
}
