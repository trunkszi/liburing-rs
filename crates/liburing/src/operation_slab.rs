//! Fixed-capacity operation ownership through cancellation and final DMA CQEs.
//!
//! Completing a slot never removes its metadata. Call [`OperationSlab::remove`] only
//! after terminal completion; cancellation control operations use their own keys.
//! Dropping a slab deliberately retains metadata for live operations, because a
//! metadata destructor may otherwise recycle memory still visible to the kernel.

use crate::{
    error::{Result, UringError},
    id::OperationPayload,
};

const SLOT_BITS: u32 = 24;
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
const MAX_CAPACITY: usize = 1 << SLOT_BITS;

/// A slot and a nonzero generation encoded into the 56-bit operation payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct OperationKey(u64);

impl OperationKey {
    /// Returns the payload suitable for an operation identifier.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn payload(self) -> OperationPayload {
        OperationPayload(self.0)
    }

    /// Validates the payload width and rejects the reserved zero generation.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for an invalid encoding.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn from_payload(payload: OperationPayload) -> Result<Self> {
        if payload.0 > OperationPayload::MAX_RAW || payload.0 >> SLOT_BITS == 0 {
            return Err(UringError::InvalidPayload(payload.0));
        }
        Ok(Self(payload.0))
    }

    /// Returns the fixed-capacity table index.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn slot(self) -> usize {
        (self.0 & SLOT_MASK) as usize
    }

    /// Returns the nonzero reuse generation.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn generation(self) -> u32 {
        (self.0 >> SLOT_BITS) as u32
    }
}

/// Kernel completion lifetime associated with an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    /// An ordinary operation with one final completion.
    Single,
    /// An operation retained while completion flags contain `MORE`.
    Multishot,
    /// A send whose main completion may require a later notification.
    ZeroCopy,
    /// A cancellation request, independent from the operation being canceled.
    CancelControl,
}

/// Ownership state of an allocated operation slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    /// The kernel may still access the operation's resources.
    InFlight,
    /// Cancellation was requested; the target's final CQE is still required.
    Canceling,
    /// A zero-copy main completion requires the notification CQE.
    AwaitingZeroCopyNotification,
    /// The operation no longer permits kernel access and can be removed.
    Completed,
}

struct Operation<Meta> {
    meta: Meta,
    kind: OperationKind,
    state: OperationState,
    main_seen: bool,
    notification_seen: bool,
}

struct Slot<Meta> {
    generation: u32,
    operation: Option<Operation<Meta>>,
    next_free: Option<usize>,
}

/// Preallocated operation slots with generation checks and explicit retirement.
///
/// Insertions, completions, and removals do not allocate or resize the table.
/// Once a slot reaches generation `u32::MAX`, removal retires that slot rather
/// than allowing any previous key to become valid again.
pub struct OperationSlab<Meta = ()> {
    slots: Box<[Slot<Meta>]>,
    free_head: Option<usize>,
    len: usize,
    retired: usize,
}

impl<Meta> OperationSlab<Meta> {
    /// Allocates all slots and the intrusive free list before any I/O begins.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidConfig`] for a zero capacity, a capacity
    /// exceeding the 24-bit slot space, or an allocation failure.
    ///
    /// # Panics
    /// Does not panic.
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > MAX_CAPACITY {
            return Err(UringError::InvalidConfig("invalid operation slab capacity"));
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| UringError::InvalidConfig("operation slab allocation failed"))?;
        for index in 0..capacity {
            slots.push(Slot {
                generation: 0,
                operation: None,
                next_free: (index + 1 < capacity).then_some(index + 1),
            });
        }
        Ok(Self {
            slots: slots.into_boxed_slice(),
            free_head: Some(0),
            len: 0,
            retired: 0,
        })
    }

    /// Reserves a slot for metadata before the associated SQE is published.
    ///
    /// # Errors
    /// Returns [`UringError::SqRingFull`] when all slots are occupied or retired.
    /// Rejected metadata is returned to its normal destructor.
    ///
    /// # Panics
    /// A rejected metadata value's destructor may panic.
    pub fn insert(&mut self, meta: Meta, kind: OperationKind) -> Result<OperationKey> {
        let index = self.free_head.ok_or(UringError::SqRingFull)?;
        let slot = &mut self.slots[index];
        let generation = slot
            .generation
            .checked_add(1)
            .ok_or(UringError::SqRingFull)?;
        self.free_head = slot.next_free;
        slot.next_free = None;
        slot.generation = generation;
        slot.operation = Some(Operation {
            meta,
            kind,
            state: OperationState::InFlight,
            main_seen: false,
            notification_seen: false,
        });
        self.len += 1;
        Ok(OperationKey(
            (u64::from(generation) << SLOT_BITS) | index as u64,
        ))
    }

    /// Borrows metadata for an occupied slot of exactly the requested generation.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for stale, retired, or absent keys.
    ///
    /// # Panics
    /// Does not panic.
    pub fn get(&self, key: OperationKey) -> Result<&Meta> {
        Ok(&self.operation(key)?.meta)
    }

    /// Mutably borrows the metadata without changing its completion lifetime.
    ///
    /// Metadata that owns DMA resources must retain those resources until final
    /// completion; replacing or extracting such resources early is not safe.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for stale, retired, or absent keys.
    ///
    /// # Panics
    /// Does not panic.
    pub fn get_mut(&mut self, key: OperationKey) -> Result<&mut Meta> {
        Ok(&mut self.operation_mut(key)?.meta)
    }

    /// Reports the operation's resource ownership state.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for stale, retired, or absent keys.
    ///
    /// # Panics
    /// Does not panic.
    pub fn state(&self, key: OperationKey) -> Result<OperationState> {
        Ok(self.operation(key)?.state)
    }

    /// Marks a target as canceling without changing ownership of its metadata.
    ///
    /// Already-canceling operations are accepted. A pending zero-copy notification
    /// remains pending; a cancellation control CQE cannot replace it.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for an invalid or completed key.
    ///
    /// # Panics
    /// Does not panic.
    pub fn mark_canceling(&mut self, key: OperationKey) -> Result<()> {
        let operation = self.operation_mut(key)?;
        match operation.state {
            OperationState::Completed => Err(UringError::InvalidPayload(key.0)),
            OperationState::AwaitingZeroCopyNotification | OperationState::Canceling => Ok(()),
            OperationState::InFlight => {
                operation.state = OperationState::Canceling;
                Ok(())
            }
        }
    }

    /// Applies one target CQE and reports whether resources are now releasable.
    ///
    /// Negative results are terminal only when `MORE` is absent. Zero-copy
    /// notification results are usage reports rather than ordinary errno values.
    /// A notification arriving before its main CQE cannot complete the operation.
    /// No completion removes metadata; even a terminal slot requires `remove`.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for stale or already-completed keys,
    /// duplicate zero-copy CQEs, or notification flags on other operation kinds.
    /// Rejected completions preserve the current slot's ownership.
    ///
    /// # Panics
    /// Does not panic.
    pub fn complete(&mut self, key: OperationKey, _result: i32, flags: u32) -> Result<bool> {
        let operation = self.operation_mut(key)?;
        if operation.state == OperationState::Completed {
            return Err(UringError::InvalidPayload(key.0));
        }
        let more = io_uring::cqueue::more(flags);
        let notification = io_uring::cqueue::notif(flags);
        if operation.kind != OperationKind::ZeroCopy {
            if notification {
                return Err(UringError::InvalidPayload(key.0));
            }
            if !more {
                operation.state = OperationState::Completed;
            }
        } else if notification {
            if more || operation.notification_seen {
                return Err(UringError::InvalidPayload(key.0));
            }
            operation.notification_seen = true;
            if operation.main_seen {
                operation.state = OperationState::Completed;
            }
        } else {
            if operation.main_seen {
                return Err(UringError::InvalidPayload(key.0));
            }
            operation.main_seen = true;
            if !more || operation.notification_seen {
                operation.state = OperationState::Completed;
            } else {
                operation.state = OperationState::AwaitingZeroCopyNotification;
            }
        }
        Ok(operation.state == OperationState::Completed)
    }

    /// Removes metadata only after the operation has reached final completion.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] if the key is stale or still live.
    ///
    /// # Panics
    /// Does not panic.
    pub fn remove(&mut self, key: OperationKey) -> Result<Meta> {
        if self.operation(key)?.state != OperationState::Completed {
            return Err(UringError::InvalidPayload(key.0));
        }
        self.take(key)
    }

    /// Rolls back a reservation that was never visible to the kernel.
    ///
    /// # Safety
    /// The associated SQE must never have been published to the kernel or remain
    /// in a userspace staging queue that could publish it later. No kernel or
    /// other owner may still access DMA resources stored in the metadata.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for a stale, retired, or absent key.
    ///
    /// # Panics
    /// Does not panic.
    pub unsafe fn discard_unsubmitted(&mut self, key: OperationKey) -> Result<Meta> {
        self.take(key)
    }

    /// Releases remaining metadata after the kernel ring is definitively closed.
    ///
    /// Previously used slots advance their generations upon their next insertion;
    /// slots whose generations are exhausted remain retired.
    ///
    /// # Safety
    /// The ring that could access these operations must have been destroyed and
    /// all kernel accesses to their resources ended. No staged operation may be
    /// published afterward using the old keys or their resource pointers.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// A metadata value's destructor may panic.
    pub unsafe fn retire_after_ring_close(&mut self) {
        self.free_head = None;
        self.len = 0;
        self.retired = 0;
        for index in (0..self.slots.len()).rev() {
            let slot = &mut self.slots[index];
            if slot.generation < u32::MAX {
                slot.next_free = self.free_head;
                self.free_head = Some(index);
            } else {
                self.retired += 1;
                slot.next_free = None;
            }
            drop(slot.operation.take());
        }
    }

    /// Iterates occupied keys and metadata without allocating.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    pub fn iter(&self) -> impl Iterator<Item = (OperationKey, &Meta)> {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            slot.operation.as_ref().map(|operation| {
                let key = OperationKey((u64::from(slot.generation) << SLOT_BITS) | index as u64);
                (key, &operation.meta)
            })
        })
    }

    /// Returns occupied slots, including completed slots awaiting removal.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns the fixed slot count, including permanently retired slots.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Reports whether every live or completed slot has been removed.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Counts reusable slots, excluding occupied and permanently retired slots.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn available(&self) -> usize {
        self.slots.len() - self.len - self.retired
    }

    fn operation(&self, key: OperationKey) -> Result<&Operation<Meta>> {
        let slot = self
            .slots
            .get(key.slot())
            .filter(|slot| slot.generation == key.generation())
            .ok_or(UringError::InvalidPayload(key.0))?;
        slot.operation
            .as_ref()
            .ok_or(UringError::InvalidPayload(key.0))
    }

    fn operation_mut(&mut self, key: OperationKey) -> Result<&mut Operation<Meta>> {
        let slot = self
            .slots
            .get_mut(key.slot())
            .filter(|slot| slot.generation == key.generation())
            .ok_or(UringError::InvalidPayload(key.0))?;
        slot.operation
            .as_mut()
            .ok_or(UringError::InvalidPayload(key.0))
    }

    fn take(&mut self, key: OperationKey) -> Result<Meta> {
        self.operation(key)?;
        let slot = &mut self.slots[key.slot()];
        let operation = slot
            .operation
            .take()
            .ok_or(UringError::InvalidPayload(key.0))?;
        if slot.generation < u32::MAX {
            slot.next_free = self.free_head;
            self.free_head = Some(key.slot());
        } else {
            self.retired += 1;
        }
        self.len -= 1;
        Ok(operation.meta)
    }
}

impl<Meta> Drop for OperationSlab<Meta> {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            if slot
                .operation
                .as_ref()
                .is_some_and(|operation| operation.state != OperationState::Completed)
                && let Some(operation) = slot.operation.take()
            {
                core::mem::forget(operation.meta);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_generation_retires_without_aliasing_or_blocking_other_slots() -> Result<()> {
        let mut slab = OperationSlab::new(2)?;
        slab.slots[0].generation = u32::MAX - 1;
        let final_generation = slab.insert(1, OperationKind::Single)?;
        assert_eq!(slab.available(), 1);
        assert_eq!(final_generation.generation(), u32::MAX);
        assert!(slab.complete(final_generation, 0, 0)?);
        assert_eq!(slab.remove(final_generation)?, 1);
        assert_eq!(slab.available(), 1);
        let other = slab.insert(2, OperationKind::Single)?;
        assert_eq!(other.slot(), 1);
        assert_eq!(
            slab.insert(3, OperationKind::Single),
            Err(UringError::SqRingFull)
        );
        assert!(slab.get(final_generation).is_err());
        assert_eq!(slab.capacity(), 2);
        assert!(slab.complete(other, 0, 0)?);
        assert_eq!(slab.remove(other)?, 2);
        assert_eq!(slab.available(), 1);
        Ok(())
    }

    #[test]
    fn exhausted_rollback_and_repeated_ring_close_preserve_available_credit() -> Result<()> {
        let mut slab = OperationSlab::new(2)?;
        slab.slots[0].generation = u32::MAX - 1;
        let exhausted = slab.insert(1, OperationKind::Single)?;
        // SAFETY: No operation in this fixture was ever staged or sent to a kernel.
        assert_eq!(unsafe { slab.discard_unsubmitted(exhausted) }?, 1);
        assert_eq!(slab.available(), 1);
        let live = slab.insert(2, OperationKind::Single)?;
        assert_eq!(slab.available(), 0);
        // SAFETY: This fixture has no ring and no published operands.
        unsafe { slab.retire_after_ring_close() };
        assert_eq!(slab.available(), 1);
        assert!(slab.get(live).is_err());
        // SAFETY: No kernel can access this fixture, including after repeated retirement.
        unsafe { slab.retire_after_ring_close() };
        assert_eq!(slab.available(), 1);
        Ok(())
    }

    #[test]
    fn submission_credit_excludes_permanently_retired_generations() -> Result<()> {
        use crate::{
            OperationId, SubsystemId, identity_map::IdentityMap, operation::TrackedOperation,
            proactor::resources::Resources, subsystem::SubmissionContext,
        };
        let mut operations = OperationSlab::new(2)?;
        operations.slots[0].generation = u32::MAX - 1;
        let key = operations.insert(
            TrackedOperation {
                original: OperationId(1 << 56),
                keyed: true,
                buffer: None,
                socket: None,
            },
            OperationKind::Single,
        )?;
        assert!(operations.complete(key, 0, 0)?);
        operations.remove(key)?.release()?;
        let mut staged = std::collections::VecDeque::with_capacity(2);
        let mut identities = IdentityMap::new(2)?;
        let resources = Resources::new(1);
        let mut pending_cancels = 0;
        let mut context = SubmissionContext {
            staged: &mut staged,
            capacity: 2,
            operations: &mut operations,
            identities: &mut identities,
            resources: &resources,
            pending_cancels: &mut pending_cancels,
            current_completion: None,
        };
        assert_eq!(context.remaining_capacity(), 1);
        let key = context.prepare_keyed_sqe_with(SubsystemId(1), |sqe| {
            // SAFETY: Initialized exclusive SQE storage; NOP has no external operands.
            unsafe { crate::ops::prep_nop(sqe) };
        })?;
        assert_eq!(context.remaining_capacity(), 0);
        assert_eq!(
            context.prepare_keyed_sqe_with(SubsystemId(1), |_| {
                panic!("retired capacity must reject before preparation")
            }),
            Err(UringError::SqRingFull)
        );
        context.staged.clear();
        // SAFETY: The only staged entry was removed above without ever being published.
        unsafe { context.operations.discard_unsubmitted(key) }?.release()?;
        assert_eq!(context.remaining_capacity(), 1);
        Ok(())
    }
}
