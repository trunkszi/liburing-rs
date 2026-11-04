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
pub(crate) const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
const MAX_CAPACITY: usize = 1 << SLOT_BITS;
/// Free-list terminator. Every live index is below `1 << 24`.
const NONE_FREE: u32 = u32::MAX;

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
///
/// Discriminants occupy the low two bits of `OperationPhase`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    /// The kernel may still access the operation's resources.
    InFlight = 0,
    /// Cancellation was requested; the target's final CQE is still required.
    Canceling = 1,
    /// A zero-copy main completion requires the notification CQE.
    AwaitingZeroCopyNotification = 2,
    /// The operation no longer permits kernel access and can be removed.
    Completed = 3,
}

/// Completion phase whose low two bits are the [`OperationState`] discriminant.
///
/// `InFlightNotifSeen` and `CancelingNotifSeen` remember a zero-copy notification
/// that arrived before the main CQE. Those phases still report
/// [`OperationState::InFlight`] and [`OperationState::Canceling`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationPhase {
    /// No main CQE and no zero-copy notification yet.
    InFlight = 0,
    /// Cancellation was requested. Neither zero-copy CQE has arrived.
    Canceling = 1,
    /// The zero-copy main CQE carried `MORE` and the notification is outstanding.
    AwaitingZeroCopyNotif = 2,
    /// Required CQEs have arrived and the slot may be removed.
    Completed = 3,
    /// A zero-copy notification arrived before the main CQE.
    InFlightNotifSeen = 1 << 2,
    /// Cancellation was requested after the notification and before the main CQE.
    CancelingNotifSeen = (1 << 2) | 1,
}

const _: () = {
    assert!((OperationPhase::InFlight as u8 & 0x03) == OperationState::InFlight as u8);
    assert!((OperationPhase::Canceling as u8 & 0x03) == OperationState::Canceling as u8);
    assert!(
        (OperationPhase::AwaitingZeroCopyNotif as u8 & 0x03)
            == OperationState::AwaitingZeroCopyNotification as u8
    );
    assert!((OperationPhase::Completed as u8 & 0x03) == OperationState::Completed as u8);
    assert!((OperationPhase::InFlightNotifSeen as u8 & 0x03) == OperationState::InFlight as u8);
    assert!((OperationPhase::CancelingNotifSeen as u8 & 0x03) == OperationState::Canceling as u8);
    assert!(NONE_FREE as usize > MAX_CAPACITY);
};

impl OperationPhase {
    /// Projects this phase onto the public ownership state.
    ///
    /// The low two bits are the [`OperationState`] discriminant.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic. Every phase discriminant maps to a state.
    #[inline(always)]
    pub const fn state(self) -> OperationState {
        // SAFETY: The const asserts above lock `discriminant & 0x03` to
        // `InFlight` (0), `Canceling` (1), `AwaitingZeroCopyNotification` (2),
        // or `Completed` (3), which are the `#[repr(u8)]` values of `OperationState`.
        unsafe { core::mem::transmute::<u8, OperationState>(self as u8 & 0x03) }
    }
}

struct Operation<Meta> {
    meta: Meta,
    kind: OperationKind,
    phase: OperationPhase,
}

/// `generation` and `next_free` share one 8-byte word. `next_free` is [`NONE_FREE`]
/// when the slot is occupied or retired.
#[repr(C)]
struct Slot<Meta> {
    generation: u32,
    next_free: u32,
    operation: Option<Operation<Meta>>,
}

const _: () = assert!(core::mem::offset_of!(Slot<()>, next_free) == 4);

/// Preallocated operation slots with generation checks and explicit retirement.
///
/// Insertions, completions, and removals do not allocate or resize the table.
/// Once a slot reaches generation `u32::MAX`, removal retires that slot rather
/// than allowing any previous key to become valid again.
pub struct OperationSlab<Meta = ()> {
    slots: Box<[Slot<Meta>]>,
    free_head: u32,
    len: usize,
    retired: usize,
}

struct Reservation<'a, Meta> {
    slot: &'a mut Slot<Meta>,
    free_head: &'a mut u32,
    retired: &'a mut usize,
    index: u32,
}
impl<Meta> Drop for Reservation<'_, Meta> {
    fn drop(&mut self) {
        if self.slot.operation.is_none() {
            if self.slot.generation < u32::MAX {
                self.slot.next_free = *self.free_head;
                *self.free_head = self.index;
            } else {
                *self.retired += 1;
            }
        }
    }
}
pub(crate) type CompletionUpdate<M, R> = (R, Option<(OperationKind, M)>);

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
            let next_free = if index + 1 < capacity {
                (index + 1) as u32
            } else {
                NONE_FREE
            };
            slots.push(Slot {
                generation: 0,
                next_free,
                operation: None,
            });
        }
        Ok(Self {
            slots: slots.into_boxed_slice(),
            free_head: 0,
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
    #[inline(always)]
    pub fn insert(&mut self, meta: Meta, kind: OperationKind) -> Result<OperationKey> {
        self.insert_with(kind, |_| meta)
    }

    /// Builds metadata with its reserved generation before publication.
    ///
    /// # Errors
    /// Returns SqRingFull without invoking the builder when no slot is reusable.
    ///
    /// # Panics
    /// Propagates builder panics, returning slot credit while consuming its generation.
    #[inline(always)]
    pub fn insert_with(
        &mut self,
        kind: OperationKind,
        build: impl FnOnce(OperationKey) -> Meta,
    ) -> Result<OperationKey> {
        let index = self.free_head;
        if index == NONE_FREE {
            return Err(UringError::SqRingFull);
        }
        let slot = &mut self.slots[index as usize];
        let generation = slot
            .generation
            .checked_add(1)
            .ok_or(UringError::SqRingFull)?;
        self.free_head = slot.next_free;
        slot.next_free = NONE_FREE;
        slot.generation = generation;
        let key = OperationKey((u64::from(generation) << SLOT_BITS) | u64::from(index));
        let reservation = Reservation {
            slot,
            free_head: &mut self.free_head,
            retired: &mut self.retired,
            index,
        };
        let meta = build(key);
        reservation.slot.operation = Some(Operation {
            meta,
            kind,
            phase: OperationPhase::InFlight,
        });
        core::mem::forget(reservation);
        self.len += 1;
        Ok(key)
    }

    /// Borrows metadata for an occupied slot of exactly the requested generation.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for stale, retired, or absent keys.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
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
    #[inline]
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
    #[inline(always)]
    pub fn state(&self, key: OperationKey) -> Result<OperationState> {
        Ok(self.operation(key)?.phase.state())
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
    #[inline(always)]
    pub fn mark_canceling(&mut self, key: OperationKey) -> Result<()> {
        let operation = self.operation_mut(key)?;
        match begin_cancel(operation.phase) {
            Ok(phase) => {
                operation.phase = phase;
                Ok(())
            }
            Err(()) => Err(UringError::InvalidPayload(key.0)),
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
    #[inline(always)]
    pub fn complete(&mut self, key: OperationKey, _result: i32, flags: u32) -> Result<bool> {
        let operation = self.operation_mut(key)?;
        match apply_cqe(operation.kind, operation.phase, flags) {
            Ok(next) => {
                operation.phase = next;
                Ok(next == OperationPhase::Completed)
            }
            Err(()) => Err(UringError::InvalidPayload(key.0)),
        }
    }

    /// Removes metadata only after the operation has reached final completion.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] if the key is stale or still live.
    ///
    /// # Panics
    /// Does not panic.
    #[inline(always)]
    pub fn remove(&mut self, key: OperationKey) -> Result<Meta> {
        self.take(key, true)
    }

    /// Consumes a final main CQE with no MORE or notification flags and removes its metadata.
    ///
    /// # Errors
    /// Returns InvalidPayload for stale/completed keys or a zero-copy operation still awaiting
    /// notification.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub fn complete_and_remove(&mut self, key: OperationKey) -> Result<(OperationKind, Meta)> {
        self.complete_checked(key, 0, 0, |_| Some(()))?
            .and_then(|(_, removed)| removed)
            .ok_or(UringError::InvalidPayload(key.0))
    }

    #[inline(always)]
    pub(crate) fn prefetch_slot(&self, slot: usize) {
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        if slot < self.slots.len() {
            // SAFETY: This bounded hint addresses live slot storage without reading or writing it;
            // the owner keeps the allocation fixed through completion dispatch.
            unsafe {
                core::arch::asm!("prefetchw [{ptr}]", ptr = in(reg) self.slots.as_ptr().wrapping_add(slot), options(nostack, preserves_flags, readonly));
            }
        }
        #[cfg(any(not(target_arch = "x86_64"), miri))]
        let _ = slot;
    }

    #[inline(always)]
    pub(crate) fn complete_checked<R>(
        &mut self,
        key: OperationKey,
        _result: i32,
        flags: u32,
        validate: impl FnOnce(&Meta) -> Option<R>,
    ) -> Result<Option<CompletionUpdate<Meta, R>>> {
        let Some(slot) = self.slots.get_mut(key.slot()) else {
            return Ok(None);
        };
        if slot.generation != key.generation() {
            return Ok(None);
        }
        let Some(operation) = slot.operation.as_mut() else {
            return Ok(None);
        };
        let Some(identity) = validate(&operation.meta) else {
            return Ok(None);
        };
        let phase = apply_cqe(operation.kind, operation.phase, flags)
            .map_err(|()| UringError::InvalidPayload(key.0))?;
        operation.phase = phase;
        let removed = if phase == OperationPhase::Completed {
            self.len -= 1;
            Some(Self::recycle(
                slot,
                key,
                &mut self.free_head,
                &mut self.retired,
            )?)
        } else {
            None
        };
        Ok(Some((identity, removed)))
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
        self.take(key, false)
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
        self.free_head = NONE_FREE;
        self.len = 0;
        self.retired = 0;
        for index in (0..self.slots.len()).rev() {
            let slot = &mut self.slots[index];
            if slot.generation < u32::MAX {
                slot.next_free = self.free_head;
                self.free_head = index as u32;
            } else {
                self.retired += 1;
                slot.next_free = NONE_FREE;
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

    #[inline(always)]
    fn operation(&self, key: OperationKey) -> Result<&Operation<Meta>> {
        let Some(slot) = self.slots.get(key.slot()) else {
            return Err(UringError::InvalidPayload(key.0));
        };
        if slot.generation != key.generation() {
            return Err(UringError::InvalidPayload(key.0));
        }
        let Some(operation) = slot.operation.as_ref() else {
            return Err(UringError::InvalidPayload(key.0));
        };
        Ok(operation)
    }

    #[inline(always)]
    fn operation_mut(&mut self, key: OperationKey) -> Result<&mut Operation<Meta>> {
        let Some(slot) = self.slots.get_mut(key.slot()) else {
            return Err(UringError::InvalidPayload(key.0));
        };
        if slot.generation != key.generation() {
            return Err(UringError::InvalidPayload(key.0));
        }
        let Some(operation) = slot.operation.as_mut() else {
            return Err(UringError::InvalidPayload(key.0));
        };
        Ok(operation)
    }

    #[inline(always)]
    fn take(&mut self, key: OperationKey, completed: bool) -> Result<Meta> {
        let slot = self
            .slots
            .get_mut(key.slot())
            .ok_or(UringError::InvalidPayload(key.0))?;
        if slot.generation != key.generation()
            || slot
                .operation
                .as_ref()
                .is_none_or(|operation| completed && operation.phase != OperationPhase::Completed)
        {
            return Err(UringError::InvalidPayload(key.0));
        }
        let (_, meta) = Self::recycle(slot, key, &mut self.free_head, &mut self.retired)?;
        self.len -= 1;
        Ok(meta)
    }

    #[inline(always)]
    fn recycle(
        slot: &mut Slot<Meta>,
        key: OperationKey,
        free_head: &mut u32,
        retired: &mut usize,
    ) -> Result<(OperationKind, Meta)> {
        let operation = slot
            .operation
            .take()
            .ok_or(UringError::InvalidPayload(key.0))?;
        if slot.generation < u32::MAX {
            slot.next_free = *free_head;
            *free_head = key.slot() as u32;
        } else {
            slot.next_free = NONE_FREE;
            *retired += 1;
        }
        Ok((operation.kind, operation.meta))
    }
}

#[inline(always)]
fn begin_cancel(phase: OperationPhase) -> core::result::Result<OperationPhase, ()> {
    let raw = phase as u8;
    // Cancellation from `InFlight` is the common transition. The other phases
    // stay on the cold side of this branch so the straight line only stores
    // `Canceling`.
    if raw != OperationPhase::InFlight as u8 {
        core::hint::cold_path();
        if raw == OperationPhase::InFlightNotifSeen as u8 {
            return Ok(OperationPhase::CancelingNotifSeen);
        }
        if raw == OperationPhase::Completed as u8 {
            return Err(());
        }
        return Ok(phase);
    }
    Ok(OperationPhase::Canceling)
}

#[inline(always)]
fn apply_cqe(
    kind: OperationKind,
    phase: OperationPhase,
    flags: u32,
) -> core::result::Result<OperationPhase, ()> {
    let raw = phase as u8;
    if raw == OperationPhase::Completed as u8 {
        return Err(());
    }
    let more = io_uring::cqueue::more(flags);
    let notification = io_uring::cqueue::notif(flags);
    if kind as u8 != OperationKind::ZeroCopy as u8 {
        if notification {
            return Err(());
        }
        return Ok(if more {
            phase
        } else {
            OperationPhase::Completed
        });
    }
    if notification {
        zero_copy_notification(raw, more)
    } else {
        zero_copy_main(raw, more)
    }
}

/// Zero-copy main CQE. `MORE` on `InFlight` or `Canceling` waits for the notification
/// and drops a pending cancel; a notification already observed completes the slot.
#[inline(always)]
fn zero_copy_main(raw: u8, more: bool) -> core::result::Result<OperationPhase, ()> {
    if raw == OperationPhase::InFlight as u8 || raw == OperationPhase::Canceling as u8 {
        return Ok(if more {
            OperationPhase::AwaitingZeroCopyNotif
        } else {
            OperationPhase::Completed
        });
    }
    if raw == OperationPhase::AwaitingZeroCopyNotif as u8 {
        return Err(());
    }
    Ok(OperationPhase::Completed)
}

/// Zero-copy notification CQE. The steady state is `AwaitingZeroCopyNotif` with `MORE` clear.
#[inline(always)]
fn zero_copy_notification(raw: u8, more: bool) -> core::result::Result<OperationPhase, ()> {
    if raw == OperationPhase::AwaitingZeroCopyNotif as u8 {
        if more {
            return Err(());
        }
        return Ok(OperationPhase::Completed);
    }
    if more
        || raw == OperationPhase::InFlightNotifSeen as u8
        || raw == OperationPhase::CancelingNotifSeen as u8
    {
        return Err(());
    }
    Ok(if raw == OperationPhase::Canceling as u8 {
        OperationPhase::CancelingNotifSeen
    } else {
        OperationPhase::InFlightNotifSeen
    })
}

impl<Meta> Drop for OperationSlab<Meta> {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            if slot
                .operation
                .as_ref()
                .is_some_and(|operation| operation.phase != OperationPhase::Completed)
                && let Some(operation) = slot.operation.take()
            {
                core::mem::forget(operation.meta);
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/operation_slab/unit.rs"]
mod tests;
