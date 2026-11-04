//! Pure Rust ring ownership, generation tracking, and caller-owned static dispatch.

use std::{
    collections::VecDeque, marker::PhantomData, mem::ManuallyDrop, os::fd::AsRawFd, rc::Rc,
    time::Duration,
};

use io_uring::{IoUring, cqueue};

use crate::{
    OperationId, Result, SubsystemId, UringError,
    backend::RawSqe,
    config::{KernelFeatures, OpcodeSet, ProactorConfig, ProactorMode},
    fixed_buffers::InFlightWaitingBuffer,
    operation::{PendingBuffer, StagedSqe, TrackedOperation},
    operation_slab::{OperationKey, OperationSlab, OperationState, SLOT_MASK},
    subsystem::{Completion, CompletionDispatcher, SubmissionContext},
};

pub(crate) mod resources;
use resources::Resources;
mod drive;
mod setup;
mod shutdown;
mod stats;
use drive::Drive;
pub use stats::ProactorStats;
const INTERNAL_CANCEL: u64 = 2;
pub(crate) const INTERNAL_TARGET_CANCEL: u64 = 3;

/// A thread-affine ring and preallocated operation/DMA budgets; no business owner.
pub struct Proactor {
    ring: Option<Box<IoUring>>,
    registered_ring_offset: Option<u32>,
    config: ProactorConfig,
    features: KernelFeatures,
    mode: ProactorMode,
    drive: Drive,
    stats: ProactorStats,
    staged: VecDeque<StagedSqe>,
    operations: Option<OperationSlab<TrackedOperation>>,
    identities: crate::identity_map::IdentityMap,
    resources: Option<Resources>,
    dispatching: bool,
    shutting_down: bool,
    cancel_armed: bool,
    shutdown_cancel_issued: bool,
    pending_cancels: usize,
    _thread_bound: PhantomData<Rc<()>>,
}

struct CompletionBatch<'a> {
    queue: ManuallyDrop<cqueue::CompletionQueue<'a>>,
    dispatching: &'a mut bool,
    consumed: usize,
}
impl CompletionBatch<'_> {
    #[inline(always)]
    fn prefetch_next(&self, operations: &OperationSlab<TrackedOperation>) {
        // SAFETY: io-uring's queue cursor contains only counters and a shared ring reference.
        // Iterating this non-dropping snapshot copies a published CQE without releasing CQ head.
        // The sole real consumer retains the entry, so the kernel cannot reuse it during the hint.
        // Never sync or drop the snapshot: those actions would acknowledge unprocessed work.
        let mut lookahead = ManuallyDrop::new(unsafe { std::ptr::read(&*self.queue) });
        if let Some(cqe) = lookahead.next() {
            // A bounded hint needs no authentication; generation and routing still gate mutation.
            operations.prefetch_slot((cqe.user_data() & SLOT_MASK) as usize);
        }
    }
}
impl Drop for CompletionBatch<'_> {
    fn drop(&mut self) {
        // One CQ-head release store per consumed batch, including unwind paths.
        // ManuallyDrop suppresses the queue's otherwise duplicated head store.
        if self.consumed != 0 {
            self.queue.sync();
        }
        *self.dispatching = false;
    }
}

impl Proactor {
    /// Allocates a generation identity without hashing a caller payload.
    /// Completions carry `OperationId::pack(subsystem, key.payload())`.
    /// Use `cancel_key` for direct generation cancellation.
    /// # Errors
    /// Returns closed-ring, reserved-subsystem, invalid-SQE, or capacity errors.
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
        self.ensure_open()?;
        self.context()?.prepare_keyed_sqe_with(subsystem, prepare)
    }

    /// Retains a fixed DMA token under a hash-free generation until final CQE.
    /// # Errors
    /// Returns closed-ring, reserved-subsystem, invalid-SQE, or capacity errors.
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
        let mut pending = PendingBuffer(Some(buffer), None);
        self.ensure_open()?;
        let mut context = self.context()?;
        let buffer = pending
            .0
            .take()
            .ok_or(UringError::InvalidConfig("missing DMA token"))?;
        context.prepare_keyed_buffer_sqe_with(subsystem, buffer, prepare)
    }

    /// Retains a descriptor and optional DMA token under a hash-free generation.
    /// # Errors
    /// Returns closed-ring, reserved-subsystem, invalid-SQE, or capacity errors.
    /// # Panics
    /// Propagates preparation panics before publication.
    pub fn prepare_keyed_owned_sqe_with<F>(
        &mut self,
        subsystem: SubsystemId,
        socket: Rc<std::os::fd::OwnedFd>,
        buffer: Option<InFlightWaitingBuffer>,
        prepare: F,
    ) -> Result<OperationKey>
    where
        F: FnOnce(*mut RawSqe),
    {
        let mut pending = PendingBuffer(buffer, Some(socket));
        self.ensure_open()?;
        let mut context = self.context()?;
        let socket = pending
            .1
            .take()
            .ok_or(UringError::InvalidConfig("missing descriptor owner"))?;
        context.prepare_keyed_owned_sqe_with(subsystem, socket, pending.0.take(), prepare)
    }

    /// Returns the ring's current generation key for a caller operation identity.
    /// Save this key for cancellation that may race identity reuse.
    /// # Errors
    /// Returns InvalidPayload if the operation is not currently tracked.
    /// # Panics
    /// Does not panic.
    pub fn operation_key(&self, id: OperationId) -> Result<OperationKey> {
        self.identities
            .get(&id)
            .copied()
            .ok_or(UringError::InvalidPayload(id.raw()))
    }

    /// Cancels exactly one generation, rejecting stale keys without side effects.
    /// # Errors
    /// Returns mode, staging, submission, or closed-ring errors for a current target.
    /// # Panics
    /// Does not panic.
    pub fn cancel_key(&mut self, key: OperationKey) -> Result<bool> {
        if self
            .operations
            .as_ref()
            .is_none_or(|operations| operations.get(key).is_err())
        {
            return Ok(false);
        }
        if !self.mode.supports_cancellation() {
            return Err(UringError::CancellationUnavailable {
                mode: self.mode.name(),
            });
        }
        self.ensure_open()?;
        if self
            .operations
            .as_ref()
            .ok_or(UringError::InvalidConfig("operation table is closed"))?
            .state(key)?
            != OperationState::InFlight
        {
            return Ok(true);
        }
        if self.staged.len() == self.config.staged_capacity {
            self.submit()?;
        }
        self.context()?.cancel_key(key)
    }

    /// Cancels a tracked target without consuming its DMA-operation slot credit.
    /// Internal control acknowledgments never retire the target or reach business
    /// dispatch. This remains usable when every application operation is occupied.
    /// # Errors
    /// Returns mode, submission, staging-capacity, or closed-ring errors.
    /// # Panics
    /// Does not panic.
    pub fn cancel(&mut self, target: OperationId) -> Result<bool> {
        let Some(&key) = self.identities.get(&target) else {
            return Ok(false);
        };
        self.cancel_key(key)
    }

    /// Retains a descriptor and DMA token until the operation's terminal CQE.
    /// # Errors
    /// Returns closed-ring, identity, flag, or fixed-capacity errors.
    /// # Panics
    /// Propagates preparation panics before publishing an operation.
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
        let mut pending = PendingBuffer(buffer, Some(socket));
        self.ensure_open()?;
        let mut context = self.context()?;
        let socket = pending
            .1
            .take()
            .ok_or(UringError::InvalidConfig("missing descriptor owner"))?;
        context.prepare_owned_sqe_with(id, socket, pending.0.take(), prepare)
    }

    /// Starts a builder over fixed-capacity defaults.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn builder() -> crate::ProactorBuilder {
        ProactorConfig::builder()
    }

    /// Creates a pure Rust ring and probes optional task-run optimizations.
    /// Pin the owner before construction. Preserve a separate SQ-thread CPU
    /// throughout the ring lifetime; later affinity changes cannot be detected.
    /// # Errors
    /// Returns configuration, affinity, required-feature, or ring setup errors.
    /// # Panics
    /// May panic if allocating fixed initialization budgets fails.
    pub fn new(config: ProactorConfig) -> Result<Self> {
        config.validate()?;
        let (ring, features) = setup::create(config)?;
        let mut proactor = Self {
            ring: Some(Box::new(ring)),
            registered_ring_offset: None,
            config,
            features,
            mode: config.mode,
            drive: Drive::for_mode(config.mode),
            stats: ProactorStats::default(),
            staged: VecDeque::with_capacity(config.staged_capacity),
            operations: Some(OperationSlab::new(config.operation_capacity)?),
            identities: crate::identity_map::IdentityMap::new(config.operation_capacity)?,
            resources: Some(Resources::new(config.buffer_groups)),
            dispatching: false,
            shutting_down: false,
            cancel_armed: false,
            shutdown_cancel_issued: false,
            pending_cancels: 0,
            _thread_bound: PhantomData,
        };
        // Registration follows all fallible owner allocation so initialization rollback cannot leak
        // a slot.
        if let Some(ring) = proactor.ring.as_ref() {
            proactor.registered_ring_offset = setup::register_ring_fd(ring);
        }
        Ok(proactor)
    }

    pub(crate) fn unregister_ring_fd(&mut self) {
        if let Some(offset) = self.registered_ring_offset.take()
            && let Some(ring) = self.ring.as_ref()
        {
            let update = setup::RingFdUpdate {
                offset,
                reserved: 0,
                data: 0,
            };
            // SAFETY: This owner thread retains the ring and the saved task-local slot; no pointer
            // escapes the syscall.
            unsafe {
                libc::syscall(
                    libc::SYS_io_uring_register,
                    ring.as_raw_fd(),
                    setup::UNREGISTER_RING_FDS,
                    (&update as *const setup::RingFdUpdate).cast::<libc::c_void>(),
                    1u32,
                )
            };
        }
    }

    /// Reports whether kernel entry uses this thread's registered ring index.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn has_registered_ring_fd(&self) -> bool {
        self.registered_ring_offset.is_some()
    }

    /// Returns a stable pure Rust ring pointer for explicit resource registration.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn ring_mut(&mut self) -> *mut IoUring {
        if self.shutting_down {
            return std::ptr::null_mut();
        }
        self.ring
            .as_deref_mut()
            .map_or(std::ptr::null_mut(), |ring| ring as *mut IoUring)
    }
    /// Returns negotiated setup and feature bits.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn kernel_features(&self) -> KernelFeatures {
        self.features
    }
    /// Stages an operation with a generated kernel identity.
    /// # Errors
    /// Returns closed-ring, identity, flag, or fixed-capacity errors.
    /// # Panics
    /// Propagates a preparation panic before publication.
    pub fn prepare_sqe_with<F>(&mut self, id: OperationId, prepare: F) -> Result<()>
    where
        F: FnOnce(*mut RawSqe),
    {
        self.ensure_open()?;
        self.context()?.prepare_sqe_with(id, prepare)
    }
    /// Retains a fixed DMA token through the final target and notification CQEs.
    /// # Errors
    /// Returns closed-ring, identity, flag, or fixed-capacity errors.
    /// # Panics
    /// Propagates preparation panics, returning unsubmitted storage safely.
    pub fn prepare_buffer_sqe_with<F>(
        &mut self,
        id: OperationId,
        buffer: InFlightWaitingBuffer,
        prepare: F,
    ) -> Result<()>
    where
        F: FnOnce(*mut RawSqe),
    {
        let mut buffer = PendingBuffer(Some(buffer), None);
        self.ensure_open()?;
        let mut context = self.context()?;
        let token = buffer
            .0
            .take()
            .ok_or(UringError::InvalidConfig("missing DMA token"))?;
        context.prepare_buffer_sqe_with(id, token, prepare)
    }
    /// Stages a pointer-free NOP.
    /// # Errors
    /// Returns identity, capacity, or closed-ring errors.
    /// # Panics
    /// Does not panic.
    pub fn alloc_sqe(&mut self, id: OperationId) -> Result<()> {
        self.prepare_sqe_with(id, |sqe| {
            // SAFETY: The callback owns initialized, exclusive stack SQE storage.
            unsafe { crate::ops::prep_nop(sqe) };
        })
    }
    /// Dispatches a bounded mmap CQ batch through caller-owned static state.
    /// # Errors
    /// Returns operation-state or dispatcher errors after acknowledging consumed CQEs.
    /// # Panics
    /// Propagates callback panics; CQ acknowledgment and dispatch state stay valid.
    #[inline]
    pub fn poll_completions<D: CompletionDispatcher<Kind> + ?Sized, Kind>(
        &mut self,
        max_batch: usize,
        dispatcher: &mut D,
    ) -> Result<usize> {
        if self.dispatching {
            return Err(UringError::ReentrantDispatch);
        }
        self.advance_kernel(false)?;
        self.harvest(max_batch, dispatcher)
    }

    #[inline]
    fn harvest<D: CompletionDispatcher<Kind> + ?Sized, Kind>(
        &mut self,
        max_batch: usize,
        dispatcher: &mut D,
    ) -> Result<usize> {
        let Some(ring) = self.ring.as_mut() else {
            return Err(UringError::InvalidConfig("ring is closed"));
        };
        if self.operations.is_none() {
            return Err(UringError::InvalidConfig("operation table is closed"));
        }
        if self.resources.is_none() {
            return Err(UringError::InvalidConfig("resources are closed"));
        }
        if max_batch == 0 || ManuallyDrop::new(ring.completion()).is_empty() {
            if !self.staged.is_empty() {
                self.publish()?;
            }
            return Ok(0);
        }
        self.harvest_ready(max_batch, dispatcher)
    }

    #[inline(never)]
    fn harvest_ready<D: CompletionDispatcher<Kind> + ?Sized, Kind>(
        &mut self,
        max_batch: usize,
        dispatcher: &mut D,
    ) -> Result<usize> {
        let Self {
            ring,
            operations,
            identities,
            resources,
            dispatching,
            staged,
            config,
            shutting_down,
            cancel_armed,
            pending_cancels,
            mode,
            ..
        } = self;
        let Some(ring) = ring.as_mut() else {
            return Err(UringError::InvalidConfig("ring is closed"));
        };
        let Some(operations) = operations.as_mut() else {
            return Err(UringError::InvalidConfig("operation table is closed"));
        };
        let Some(resources) = resources.as_ref() else {
            return Err(UringError::InvalidConfig("resources are closed"));
        };
        *dispatching = true;
        let mut batch = CompletionBatch {
            queue: ManuallyDrop::new(ring.completion()),
            dispatching,
            consumed: 0,
        };
        let capacity = if *shutting_down {
            0
        } else {
            config.staged_capacity
        };
        let admission = OpcodeSet::for_mode(*mode);
        let cancellable = mode.supports_cancellation();
        let mode_name = mode.name();
        let mut context = SubmissionContext {
            staged,
            capacity,
            operations,
            identities,
            resources,
            pending_cancels,
            current_completion: None,
            admission,
            cancellable,
            mode_name,
        };
        let mut harvested = 0;
        while harvested < max_batch {
            let Some(cqe) = batch.queue.next() else {
                break;
            };
            harvested += 1;
            batch.consumed += 1;
            if harvested < max_batch {
                batch.prefetch_next(context.operations);
            }
            let id = OperationId::from_raw(cqe.user_data());
            if id.subsystem_id() == crate::SubsystemId::INTERNAL {
                if id.raw() == INTERNAL_CANCEL {
                    *cancel_armed = false;
                } else if id.raw() == INTERNAL_TARGET_CANCEL {
                    *context.pending_cancels = context.pending_cancels.saturating_sub(1);
                }
                continue;
            }
            let Ok(key) = OperationKey::from_payload(id.payload()) else {
                continue;
            };
            let Some((original, removed)) =
                context
                    .operations
                    .complete_checked(key, cqe.result(), cqe.flags(), |tracked| {
                        (tracked.original.subsystem_id() == id.subsystem_id())
                            .then_some(tracked.original)
                    })?
            else {
                continue;
            };
            if let Some((_, metadata)) = removed {
                if !metadata.keyed {
                    context.identities.remove(&original);
                }
                metadata.release()?;
            }
            let completion = Completion {
                operation_id: original,
                result: cqe.result(),
                flags: cqe.flags(),
            };
            context.current_completion = Some(completion);
            let dispatch_res = dispatcher.dispatch(completion, &mut context);
            context.current_completion = None;
            dispatch_res?;
        }
        drop(batch);
        if !self.staged.is_empty() {
            self.publish()?;
        }
        Ok(harvested)
    }
    /// Counts operations retained until final target or notification completion.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn operation_count(&self) -> usize {
        self.operations.as_ref().map_or(0, OperationSlab::len)
    }

    /// Reports staging and reusable operation-slot credit, excluding retired slots.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn remaining_capacity(&self) -> usize {
        if self.shutting_down || self.ring.is_none() {
            return 0;
        }
        self.config
            .staged_capacity
            .saturating_sub(self.staged.len())
            .min(self.operations.as_ref().map_or(0, OperationSlab::available))
    }

    /// Counts accepted target cancellations whose control CQE is still pending.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn pending_cancel_count(&self) -> usize {
        self.pending_cancels
    }

    /// Reports whether staging, application operations, and cancellation drained.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn is_idle(&self) -> bool {
        self.staged.is_empty()
            && self.operation_count() == 0
            && self.pending_cancels == 0
            && !self.cancel_armed
    }
    /// Looks up the generation state behind a caller identity.
    /// # Errors
    /// Returns InvalidPayload for completed or unknown identities.
    /// # Panics
    /// Does not panic.
    pub fn operation_state(&self, id: OperationId) -> Result<OperationState> {
        let key = *self
            .identities
            .get(&id)
            .ok_or(UringError::InvalidPayload(id.raw()))?;
        self.operations
            .as_ref()
            .ok_or(UringError::InvalidPayload(id.raw()))?
            .state(key)
    }
    pub(crate) fn with_submission_context<T>(
        &mut self,
        prepare: impl FnOnce(&mut SubmissionContext<'_>) -> Result<T>,
    ) -> Result<T> {
        self.ensure_open()?;
        prepare(&mut self.context()?)
    }

    fn context(&mut self) -> Result<SubmissionContext<'_>> {
        Ok(SubmissionContext {
            staged: &mut self.staged,
            capacity: self.config.staged_capacity,
            operations: self
                .operations
                .as_mut()
                .ok_or(UringError::InvalidConfig("operation table is closed"))?,
            identities: &mut self.identities,
            resources: self
                .resources
                .as_ref()
                .ok_or(UringError::InvalidConfig("resources are closed"))?,
            pending_cancels: &mut self.pending_cancels,
            current_completion: None,
            admission: OpcodeSet::for_mode(self.mode),
            cancellable: self.mode.supports_cancellation(),
            mode_name: self.mode.name(),
        })
    }
    fn ensure_open(&self) -> Result<()> {
        if self.shutting_down || self.ring.is_none() {
            Err(UringError::InvalidConfig("ring is shutting down"))
        } else {
            Ok(())
        }
    }
}
fn errno(error: &std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EIO)
}
