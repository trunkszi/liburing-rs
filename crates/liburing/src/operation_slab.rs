//! Fixed-capacity operation ownership through cancellation and final DMA CQEs.
//!
//! Completing a slot never removes its metadata. Call [`OperationSlab::remove`] only
//! after terminal completion; cancellation control operations use their own keys.
//! Dropping a slab deliberately retains metadata for live operations, because a
//! metadata destructor may otherwise recycle memory still visible to the kernel.

use core::mem::MaybeUninit;

use uarch::prelude::{bitword, cold_path, cold_sink, hot_inline, patch, pattern};

use crate::{
    error::{Result, UringError},
    id::OperationPayload,
};

const SLOT_BITS: u32 = 24;
pub(crate) const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
const MAX_CAPACITY: usize = SLOT_MASK as usize;
/// The top 24-bit index is reserved as the free-list terminator.
const NONE_FREE: u32 = 0x00FF_FFFF;

/// A slot and a nonzero generation encoded into the 56-bit operation payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct OperationKey(u64);

// SAFETY: repr(transparent) over one unsigned scalar has no implicit padding.
unsafe impl uarch::layout::NoPadding for OperationKey {}
// SAFETY: This transparent scalar wrapper contributes exactly one native ABI leaf.
unsafe impl uarch::layout::RegisterLeaf for OperationKey {
    const LEAVES: u8 = 1;
}
const _: () = uarch::layout::assert_register_leaf::<OperationKey>();
uarch::layout::assert_layout!(OperationKey, size = 8, align = 8);

bitword! {
    struct KeyWord(u64) {
        [0..=23] SLOT: u32,
        [24..=55] GENERATION: u32,
    }
}

impl OperationKey {
    #[hot_inline]
    const fn pack(slot: u32, generation: u32) -> Self {
        Self(
            KeyWord::new(0)
                .patch(
                    uarch::bits::BitPatch::EMPTY
                        .with_field(KeyWord::SLOT, (slot as u64) & SLOT_MASK)
                        .with_field(KeyWord::GENERATION, generation as u64),
                )
                .raw(),
        )
    }

    /// Returns the payload suitable for an operation identifier.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[hot_inline]
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
    #[hot_inline]
    pub const fn from_payload(payload: OperationPayload) -> Result<Self> {
        if payload.0 > OperationPayload::MAX_RAW
            || KeyWord::new(payload.0).get(KeyWord::GENERATION) == 0
        {
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
    #[hot_inline]
    pub const fn slot(self) -> usize {
        KeyWord::new(self.0).get(KeyWord::SLOT) as usize
    }

    /// Returns the nonzero reuse generation.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn generation(self) -> u32 {
        KeyWord::new(self.0).get(KeyWord::GENERATION)
    }
}

/// Kernel completion lifetime associated with an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
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
    assert!(NONE_FREE as usize == MAX_CAPACITY);
};

impl OperationPhase {
    /// Projects the low two bits onto the public ownership state.
    #[hot_inline]
    pub const fn state(self) -> OperationState {
        // SAFETY: The const asserts above lock `discriminant & 0x03` to
        // `InFlight` (0), `Canceling` (1), `AwaitingZeroCopyNotification` (2),
        // or `Completed` (3), which are the `#[repr(u8)]` values of `OperationState`.
        unsafe { core::mem::transmute::<u8, OperationState>(self as u8 & 0x03) }
    }
}

bitword! {
    struct SlotHeader(u64) {
        [0] OCCUPIED,
        [1] RETIRED,
        [2..=4] PHASE: u8,
        [5..=6] KIND: u8,
        [8..=31] NEXT_FREE: u32,
        [32..=63] GENERATION: u32,
    }
}

impl SlotHeader {
    #[hot_inline]
    fn occupied(self) -> bool {
        self.matches(pattern!(SlotHeader { OCCUPIED & !RETIRED }))
    }

    #[hot_inline]
    fn phase(self) -> OperationPhase {
        // SAFETY: Only OperationPhase discriminants are written to the private PHASE field.
        unsafe { core::mem::transmute(self.get(Self::PHASE)) }
    }

    #[hot_inline]
    fn kind(self) -> OperationKind {
        // SAFETY: Only OperationKind discriminants are written to the private KIND field.
        unsafe { core::mem::transmute(self.get(Self::KIND)) }
    }
}

uarch::layout::assert_layout!(SlotHeader, size = 8, align = 8);

/// Preallocated operation slots with generation checks and explicit retirement.
///
/// Metadata is separate from dense eight-byte headers. No hot operation resizes
/// either allocation. Exhausted generations permanently retire their slot.
pub struct OperationSlab<Meta = ()> {
    headers: Box<[SlotHeader]>,
    metas: Box<[MaybeUninit<Meta>]>,
    free_head: u32,
    len: usize,
    retired: usize,
}

struct Reservation<'a> {
    header: &'a mut SlotHeader,
    free_head: &'a mut u32,
    retired: &'a mut usize,
    index: u32,
}

impl Drop for Reservation<'_> {
    #[cold_sink]
    fn drop(&mut self) {
        if self.header.get(SlotHeader::GENERATION) == u32::MAX {
            cold_path();
            *self.header = self.header.patch(patch!(SlotHeader { RETIRED: true }));
            *self.retired += 1;
        } else {
            *self.header = self.header.patch(uarch::bits::BitPatch::EMPTY.with_field(
                SlotHeader::NEXT_FREE,
                ((*self.free_head) as u64) & SLOT_MASK,
            ));
            *self.free_head = self.index;
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
    #[cold_sink]
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > MAX_CAPACITY {
            return Err(UringError::InvalidConfig("invalid operation slab capacity"));
        }
        let mut headers = Vec::new();
        let mut metas = Vec::new();
        headers
            .try_reserve_exact(capacity)
            .map_err(|_| UringError::InvalidConfig("operation slab allocation failed"))?;
        metas
            .try_reserve_exact(capacity)
            .map_err(|_| UringError::InvalidConfig("operation metadata allocation failed"))?;
        for index in 0..capacity {
            let next = if index + 1 < capacity {
                (index + 1) as u32
            } else {
                NONE_FREE
            };
            headers.push(
                SlotHeader::new(0).patch(
                    uarch::bits::BitPatch::EMPTY
                        .with_field(SlotHeader::NEXT_FREE, (next as u64) & SLOT_MASK),
                ),
            );
            metas.push(MaybeUninit::uninit());
        }
        Ok(Self {
            headers: headers.into_boxed_slice(),
            metas: metas.into_boxed_slice(),
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
    #[hot_inline]
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
    #[hot_inline]
    pub fn insert_with(
        &mut self,
        kind: OperationKind,
        build: impl FnOnce(OperationKey) -> Meta,
    ) -> Result<OperationKey> {
        let index = self.free_head;
        if index == NONE_FREE {
            return Err(UringError::SqRingFull);
        }
        let Some(header) = self.headers.get_mut(index as usize) else {
            cold_path();
            return Err(UringError::SqRingFull);
        };
        let generation = header
            .get(SlotHeader::GENERATION)
            .checked_add(1)
            .ok_or(UringError::SqRingFull)?;
        self.free_head = header.get(SlotHeader::NEXT_FREE);
        *header = header.patch(
            uarch::bits::BitPatch::EMPTY
                .with_field(SlotHeader::GENERATION, generation as u64)
                .with_field(SlotHeader::NEXT_FREE, NONE_FREE as u64),
        );
        let key = OperationKey::pack(index, generation);
        let reservation = Reservation {
            header,
            free_head: &mut self.free_head,
            retired: &mut self.retired,
            index,
        };
        let meta = build(key);
        // SAFETY: The reserved header index also bounds the equally sized metadata allocation.
        unsafe { self.metas.get_unchecked_mut(index as usize) }.write(meta);
        *reservation.header = reservation.header.patch(
            uarch::bits::BitPatch::EMPTY
                .with_flag(SlotHeader::OCCUPIED, true)
                .with_field(SlotHeader::KIND, kind as u64)
                .with_field(SlotHeader::PHASE, OperationPhase::InFlight as u64),
        );
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
    #[hot_inline]
    pub fn get(&self, key: OperationKey) -> Result<&Meta> {
        self.operation(key)?;
        // SAFETY: Matching occupancy proves initialization; both fixed slices have equal lengths.
        Ok(unsafe { self.metas.get_unchecked(key.slot()).assume_init_ref() })
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
    #[hot_inline]
    pub fn get_mut(&mut self, key: OperationKey) -> Result<&mut Meta> {
        self.operation(key)?;
        // SAFETY: The valid header bounds both equal-length slices; &mut self is exclusive.
        Ok(unsafe { self.metas.get_unchecked_mut(key.slot()).assume_init_mut() })
    }

    /// Reports the operation's resource ownership state.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for stale, retired, or absent keys.
    ///
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn state(&self, key: OperationKey) -> Result<OperationState> {
        Ok(self.operation(key)?.phase().state())
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
    #[hot_inline]
    pub fn mark_canceling(&mut self, key: OperationKey) -> Result<()> {
        let operation = self.operation_mut(key)?;
        match begin_cancel(operation.phase()) {
            Ok(phase) => {
                *operation = operation.patch(
                    uarch::bits::BitPatch::EMPTY.with_field(SlotHeader::PHASE, phase as u64),
                );
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
    #[hot_inline]
    pub fn complete(&mut self, key: OperationKey, _result: i32, flags: u32) -> Result<bool> {
        let operation = self.operation_mut(key)?;
        match apply_cqe(operation.kind(), operation.phase(), flags) {
            Ok(next) => {
                *operation = operation
                    .patch(uarch::bits::BitPatch::EMPTY.with_field(SlotHeader::PHASE, next as u64));
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
    #[hot_inline]
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
    #[hot_inline]
    pub fn complete_and_remove(&mut self, key: OperationKey) -> Result<(OperationKind, Meta)> {
        self.complete_checked(key, 0, 0, |_| Some(()))?
            .and_then(|(_, removed)| removed)
            .ok_or(UringError::InvalidPayload(key.0))
    }

    #[hot_inline]
    pub(crate) fn prefetch_slot(&self, slot: usize) {
        if slot < self.headers.len() {
            uarch::mem::prefetch_read::<uarch::mem::L1, _>(
                self.headers.as_ptr().wrapping_add(slot),
            );
            uarch::mem::prefetch_read::<uarch::mem::L1, _>(self.metas.as_ptr().wrapping_add(slot));
        }
    }

    #[hot_inline]
    pub(crate) fn complete_checked<R>(
        &mut self,
        key: OperationKey,
        _result: i32,
        flags: u32,
        validate: impl FnOnce(&Meta) -> Option<R>,
    ) -> Result<Option<CompletionUpdate<Meta, R>>> {
        let Some(header) = self.headers.get(key.slot()) else {
            return Ok(None);
        };
        if !header.occupied() || header.get(SlotHeader::GENERATION) != key.generation() {
            return Ok(None);
        }
        // SAFETY: Occupancy proves initialization; the valid header bounds both fixed slices.
        let Some(identity) =
            validate(unsafe { self.metas.get_unchecked(key.slot()).assume_init_ref() })
        else {
            return Ok(None);
        };
        let phase = apply_cqe(header.kind(), header.phase(), flags)
            .map_err(|()| UringError::InvalidPayload(key.0))?;
        self.headers[key.slot()] =
            header.patch(uarch::bits::BitPatch::EMPTY.with_field(SlotHeader::PHASE, phase as u64));
        let removed = if phase == OperationPhase::Completed {
            Some(self.recycle(key))
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
        for index in (0..self.headers.len()).rev() {
            if self.headers[index].occupied() {
                let key = OperationKey::pack(
                    index as u32,
                    self.headers[index].get(SlotHeader::GENERATION),
                );
                // Recycling clears occupancy before a potentially panicking destructor.
                drop(self.recycle(key).1);
            }
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
        self.headers
            .iter()
            .enumerate()
            .filter_map(|(index, header)| {
                if !header.occupied() {
                    return None;
                }
                let key = OperationKey::pack(index as u32, header.get(SlotHeader::GENERATION));
                // SAFETY: Occupied headers identify initialized entries; the slab is
                // shared-borrowed.
                Some((key, unsafe { self.metas[index].assume_init_ref() }))
            })
    }

    /// Returns occupied slots, including completed slots awaiting removal.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[hot_inline]
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
    #[hot_inline]
    pub const fn capacity(&self) -> usize {
        self.headers.len()
    }

    /// Reports whether every live or completed slot has been removed.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Counts reusable slots, excluding occupied and permanently retired slots.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn available(&self) -> usize {
        self.headers.len() - self.len - self.retired
    }

    #[hot_inline]
    fn operation(&self, key: OperationKey) -> Result<&SlotHeader> {
        let header = self
            .headers
            .get(key.slot())
            .ok_or(UringError::InvalidPayload(key.0))?;
        if !header.occupied() || header.get(SlotHeader::GENERATION) != key.generation() {
            return Err(UringError::InvalidPayload(key.0));
        }
        Ok(header)
    }

    #[hot_inline]
    fn operation_mut(&mut self, key: OperationKey) -> Result<&mut SlotHeader> {
        self.operation(key)?;
        Ok(&mut self.headers[key.slot()])
    }

    #[hot_inline]
    fn take(&mut self, key: OperationKey, completed: bool) -> Result<Meta> {
        let header = self.operation(key)?;
        if completed && header.phase() != OperationPhase::Completed {
            return Err(UringError::InvalidPayload(key.0));
        }
        Ok(self.recycle(key).1)
    }

    #[hot_inline]
    fn recycle(&mut self, key: OperationKey) -> (OperationKind, Meta) {
        // SAFETY: Every caller validated occupancy and bounds before transferring ownership.
        let header = unsafe { self.headers.get_unchecked_mut(key.slot()) };
        let kind = header.kind();
        let retired = header.get(SlotHeader::GENERATION) == u32::MAX;
        let next = if retired { NONE_FREE } else { self.free_head };
        *header = header.patch(
            uarch::bits::BitPatch::EMPTY
                .with_flag(SlotHeader::OCCUPIED, false)
                .with_flag(SlotHeader::RETIRED, retired)
                .with_field(SlotHeader::NEXT_FREE, (next as u64) & SLOT_MASK),
        );
        self.len -= 1;
        if retired {
            cold_path();
            self.retired += 1;
        } else {
            self.free_head = key.slot() as u32;
        }
        // SAFETY: Equal slice lengths preserve the checked index; clearing occupancy transfers
        // once.
        (kind, unsafe {
            self.metas.get_unchecked(key.slot()).assume_init_read()
        })
    }
}

#[hot_inline]
fn begin_cancel(phase: OperationPhase) -> core::result::Result<OperationPhase, ()> {
    let raw = phase as u8;
    // Cancellation from `InFlight` is the common transition. The other phases
    // stay on the cold side of this branch so the straight line only stores
    // `Canceling`.
    if raw != OperationPhase::InFlight as u8 {
        cold_path();
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

#[hot_inline]
fn apply_cqe(
    kind: OperationKind,
    phase: OperationPhase,
    flags: u32,
) -> core::result::Result<OperationPhase, ()> {
    let raw = phase as u8;
    if raw == OperationPhase::Completed as u8 {
        return Err(());
    }
    let more = crate::backend::cqueue::more(flags);
    let notification = crate::backend::cqueue::notif(flags);
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
#[hot_inline]
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
#[hot_inline]
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
        for (header, meta) in self.headers.iter_mut().zip(self.metas.iter_mut()) {
            if header.occupied() && header.phase() == OperationPhase::Completed {
                *header = header.patch(patch!(SlotHeader { OCCUPIED: false }));
                // SAFETY: Occupied completed slots own initialized Meta with no remaining DMA.
                unsafe { meta.assume_init_drop() };
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/operation_slab/unit.rs"]
mod tests;
