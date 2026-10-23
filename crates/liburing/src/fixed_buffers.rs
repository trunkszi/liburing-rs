//! Registered, stable-address buffers with explicit completion ownership.
//!
//! Cancellation only quarantines a buffer. Its original operation's final CQE,
//! rather than the cancellation request's CQE, authorizes reuse.

use std::{
    cell::{Cell, UnsafeCell},
    ptr::NonNull,
    rc::Rc,
};

use crate::{
    error::{Result, UringError},
    id::BufferId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Free,
    Retired,
    CheckedOut,
    InFlight,
    Quarantined,
}

struct Slot {
    bytes: UnsafeCell<Box<[u8]>>,
    state: Cell<State>,
    generation: Cell<u64>,
}

struct Inner {
    ring: NonNull<io_uring::IoUring>,
    slots: Vec<Slot>,
    free: Box<[Cell<u16>]>,
    free_len: Cell<usize>,
    registered: Cell<bool>,
    #[cfg(test)]
    mock_registration: bool,
}

fn error(errno: i32) -> UringError {
    std::io::Error::from_raw_os_error(errno).into()
}

impl Inner {
    fn release(&self, id: BufferId) {
        let len = self.free_len.get();
        self.free[len].set(id.0);
        self.free_len.set(len + 1);
        self.slots[usize::from(id.0)].state.set(State::Free);
    }

    fn unregister_kernel(&self) -> Result<()> {
        #[cfg(test)]
        if self.mock_registration {
            return Ok(());
        }
        // SAFETY: Construction requires the live ring to outlast every pool
        // lease. This registration belongs exclusively to this owner thread.
        unsafe { self.ring.as_ref() }
            .submitter()
            .unregister_buffers()
            .map_err(Into::into)
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let outstanding = self
            .slots
            .iter()
            .any(|slot| matches!(slot.state.get(), State::InFlight | State::Quarantined));
        let unregister_failed = if self.registered.get() {
            self.unregister_kernel().is_err()
        } else {
            false
        };
        if outstanding || unregister_failed {
            // Unregistering does not prove that requests already holding kernel
            // references have stopped DMA. Retain their physical allocations;
            // returning them to the allocator could corrupt unrelated objects.
            for slot in &mut self.slots {
                std::mem::forget(std::mem::take(slot.bytes.get_mut()));
            }
        }
    }
}

/// A single-threaded pool registered as one ring's fixed-buffer table.
///
/// Handles retain the registration after this owner is dropped. If final
/// completions are never reclaimed, teardown retains the allocations instead
/// of freeing memory that the kernel may still access.
pub struct FixedBufferPool {
    inner: Rc<Inner>,
}

impl FixedBufferPool {
    /// Allocate and register `buffer_count` zeroed buffers of `buffer_len` bytes.
    ///
    /// Construction allocates memory; checkout and completion transitions do not.
    ///
    /// # Errors
    /// Returns an error for a null ring, zero dimensions, lengths above `u32::MAX`,
    /// allocation failure, or a failed kernel buffer registration.
    ///
    /// # Panics
    /// This function does not intentionally panic.
    ///
    /// # Safety
    /// `ring` must identify an initialized ring owned by this thread and outlive
    /// this pool and every handle derived from it. No other owner may register,
    /// update, or unregister its fixed buffers during that lifetime. Ring access
    /// must remain serialized on this thread, including while handles are dropped.
    pub unsafe fn new(
        ring: *mut io_uring::IoUring,
        buffer_count: u16,
        buffer_len: usize,
    ) -> Result<Self> {
        let ring = NonNull::new(ring).ok_or_else(|| error(libc::EINVAL))?;
        if buffer_count == 0 || buffer_len == 0 || buffer_len > u32::MAX as usize {
            return Err(error(libc::EINVAL));
        }
        let count = usize::from(buffer_count);
        let mut slots = Vec::new();
        let mut free = Vec::new();
        let mut iovecs = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| error(libc::ENOMEM))?;
        free.try_reserve_exact(count)
            .map_err(|_| error(libc::ENOMEM))?;
        iovecs
            .try_reserve_exact(count)
            .map_err(|_| error(libc::ENOMEM))?;
        for id in 0..buffer_count {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(buffer_len)
                .map_err(|_| error(libc::ENOMEM))?;
            bytes.resize(buffer_len, 0);
            let mut bytes = bytes.into_boxed_slice();
            iovecs.push(libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            });
            slots.push(Slot {
                bytes: UnsafeCell::new(bytes),
                state: Cell::new(State::Free),
                generation: Cell::new(0),
            });
            free.push(Cell::new(buffer_count - id - 1));
        }
        // SAFETY: The ring is initialized by the caller. All iovecs refer to
        // initialized, uniquely owned stable allocations retained in `slots`.
        // Registration copies the iovec descriptors before returning.
        unsafe { ring.as_ref().submitter().register_buffers(&iovecs) }.map_err(|error| {
            UringError::syscalls(
                "register_buffers",
                error.raw_os_error().unwrap_or(libc::EIO),
            )
        })?;
        Ok(Self {
            inner: Rc::new(Inner {
                ring,
                slots,
                free: free.into_boxed_slice(),
                free_len: Cell::new(count),
                registered: Cell::new(true),
                #[cfg(test)]
                mock_registration: false,
            }),
        })
    }

    /// Lease one free buffer, removing it from the available stack in O(1).
    ///
    /// # Errors
    /// Returns an error if unregistered, exhausted, or a slot generation is spent.
    /// A spent slot is permanently retired; later calls can use remaining slots.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn checkout(&self) -> Result<FixedBufferHandle> {
        if !self.inner.registered.get() {
            return Err(error(libc::ENXIO));
        }
        let len = self
            .inner
            .free_len
            .get()
            .checked_sub(1)
            .ok_or(UringError::FixedBuffersExhausted)?;
        let id = self.inner.free[len].get();
        self.inner.free_len.set(len);
        let slot = &self.inner.slots[usize::from(id)];
        let Some(generation) = slot.generation.get().checked_add(1) else {
            slot.state.set(State::Retired);
            return Err(error(libc::EOVERFLOW));
        };
        slot.generation.set(generation);
        slot.state.set(State::CheckedOut);
        Ok(FixedBufferHandle {
            inner: Rc::clone(&self.inner),
            id: BufferId(id),
            generation,
        })
    }

    /// Return the total number of registered slots.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.slots.len()
    }

    /// Return the number of buffers immediately available for checkout.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn available(&self) -> usize {
        self.inner.free_len.get()
    }

    /// Release a submitted or quarantined buffer after its final completion.
    ///
    /// This ID-only operation cannot detect an earlier checkout's completion.
    /// Prefer [`Self::reclaim_completed_generation`] with a generation retained
    /// from [`InFlightWaitingBuffer::generation`] when completions can arrive late.
    ///
    /// # Errors
    /// Returns an error for an unknown, free, or checked-out buffer ID.
    ///
    /// # Panics
    /// This function does not panic.
    ///
    /// # Safety
    /// The caller must have received this buffer's original operation's final
    /// CQE without `IORING_CQE_F_MORE`, including `-ECANCELED`, and established
    /// that the kernel no longer accesses the memory. A cancel control CQE is
    /// insufficient. Zero-copy operations must also have delivered any required
    /// notification CQE. The ID must refer to that exact outstanding checkout,
    /// never an earlier operation that reused the same buffer ID.
    pub unsafe fn reclaim_completed(&self, id: BufferId) -> Result<()> {
        let slot = self
            .inner
            .slots
            .get(usize::from(id.0))
            .ok_or_else(|| error(libc::EINVAL))?;
        if !matches!(slot.state.get(), State::InFlight | State::Quarantined) {
            return Err(UringError::BufferNotInFlight(id.0));
        }
        self.inner.release(id);
        Ok(())
    }

    /// Release the exact submitted checkout identified by its ID and generation.
    ///
    /// Retain [`InFlightWaitingBuffer::generation`] alongside the operation's
    /// completion identity before abandoning its waiting token. A stale
    /// completion cannot release a buffer checked out for another operation.
    ///
    /// # Errors
    /// Returns an error for an unknown ID, a stale generation, or a slot that is
    /// not submitted or quarantined. Rejection leaves the current owner intact.
    ///
    /// # Panics
    /// This function does not panic.
    ///
    /// # Safety
    /// The matching operation must satisfy the final-CQE and no-further-DMA
    /// contract of [`Self::reclaim_completed`]. A generation check does not prove
    /// that a completion is final or that zero-copy notifications have arrived.
    pub unsafe fn reclaim_completed_generation(&self, id: BufferId, generation: u64) -> Result<()> {
        let slot = self
            .inner
            .slots
            .get(usize::from(id.0))
            .ok_or_else(|| error(libc::EINVAL))?;
        if slot.generation.get() != generation {
            return Err(UringError::BufferNotInFlight(id.0));
        }
        // SAFETY: The caller establishes final completion for this generation,
        // and the check above excludes reclaiming a later checkout of the slot.
        unsafe { self.reclaim_completed(id) }
    }

    /// Unregister an idle pool while reporting kernel errors to its owner.
    ///
    /// A successful call permanently disables checkout. Calling again succeeds.
    ///
    /// # Errors
    /// Returns `EBUSY` while any handle or operation owns a buffer, or the kernel
    /// registration error. Failure leaves the pool registered and usable.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn unregister(&mut self) -> Result<()> {
        if !self.inner.registered.get() {
            return Ok(());
        }
        if self
            .inner
            .slots
            .iter()
            .any(|slot| !matches!(slot.state.get(), State::Free | State::Retired))
        {
            return Err(error(libc::EBUSY));
        }
        self.inner.unregister_kernel()?;
        self.inner.registered.set(false);
        Ok(())
    }
}

/// Exclusive user-space access to a registered buffer that is not in flight.
///
/// Dropping this handle returns its slot to the pool. Submission must consume it
/// through [`Self::into_in_flight`] before the kernel can access its bytes.
pub struct FixedBufferHandle {
    inner: Rc<Inner>,
    id: BufferId,
    generation: u64,
}

impl FixedBufferHandle {
    /// Return the fixed-buffer index to write into a fixed I/O SQE.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn id(&self) -> BufferId {
        self.id
    }

    /// Borrow initialized bytes while no kernel operation owns this slot.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: A non-cloneable handle exclusively owns a CheckedOut slot;
        // no kernel operation or mutable borrow can coexist with this borrow.
        unsafe { &*self.inner.slots[usize::from(self.id.0)].bytes.get() }
    }

    /// Mutably borrow bytes before submission or after final completion.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: The non-cloneable handle has exclusive CheckedOut ownership,
        // and its mutable borrow prevents any other user-space access.
        unsafe { &mut *self.inner.slots[usize::from(self.id.0)].bytes.get() }
    }

    /// Return the stable address used when preparing a fixed write request.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }

    /// Return the stable address used when preparing a fixed read request.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_slice().as_mut_ptr()
    }

    /// Transfer byte access to an operation until its own final CQE arrives.
    ///
    /// Call this before publishing the SQE. Dropping the returned token does
    /// not recycle memory, even if the cancellation control request completed.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn into_in_flight(self) -> InFlightWaitingBuffer {
        self.inner.slots[usize::from(self.id.0)]
            .state
            .set(State::InFlight);
        InFlightWaitingBuffer {
            inner: Rc::clone(&self.inner),
            id: self.id,
            generation: self.generation,
        }
    }
}

impl Drop for FixedBufferHandle {
    fn drop(&mut self) {
        let slot = &self.inner.slots[usize::from(self.id.0)];
        if slot.generation.get() == self.generation && slot.state.get() == State::CheckedOut {
            self.inner.release(self.id);
        }
    }
}

/// A submitted buffer whose memory remains inaccessible until final completion.
///
/// Dropping this token changes `InFlight` to `Quarantined`. The pool continues
/// retaining its backing memory until `reclaim_completed` is explicitly called.
pub struct InFlightWaitingBuffer {
    inner: Rc<Inner>,
    id: BufferId,
    generation: u64,
}

impl InFlightWaitingBuffer {
    /// Return the slot whose original operation must complete before reuse.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn id(&self) -> BufferId {
        self.id
    }

    /// Return the checkout generation to retain with the operation's completion ID.
    ///
    /// Use it with [`FixedBufferPool::reclaim_completed_generation`] if this
    /// waiting token must be dropped before the target's final completion.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Mark cancellation or abandonment without authorizing memory reuse.
    ///
    /// Repeated calls on the same quarantined operation succeed.
    ///
    /// # Errors
    /// Returns an error if this token's checkout has already been reclaimed.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn quarantine(&mut self) -> Result<()> {
        let slot = &self.inner.slots[usize::from(self.id.0)];
        if slot.generation.get() != self.generation
            || !matches!(slot.state.get(), State::InFlight | State::Quarantined)
        {
            return Err(UringError::BufferNotInFlight(self.id.0));
        }
        slot.state.set(State::Quarantined);
        Ok(())
    }

    /// Recover exclusive byte access after this operation has fully completed.
    ///
    /// Dropping the returned handle then returns its slot to the free stack.
    ///
    /// # Errors
    /// Returns an error if this token's checkout has already been reclaimed.
    ///
    /// # Panics
    /// This function does not panic.
    ///
    /// # Safety
    /// The caller must establish the same final-CQE and no-further-DMA contract
    /// as [`FixedBufferPool::reclaim_completed`]. An operation never submitted
    /// may also be completed here after removing every staged SQE reference.
    pub unsafe fn complete(self) -> Result<FixedBufferHandle> {
        let slot = &self.inner.slots[usize::from(self.id.0)];
        if slot.generation.get() != self.generation
            || !matches!(slot.state.get(), State::InFlight | State::Quarantined)
        {
            return Err(UringError::BufferNotInFlight(self.id.0));
        }
        slot.state.set(State::CheckedOut);
        Ok(FixedBufferHandle {
            inner: Rc::clone(&self.inner),
            id: self.id,
            generation: self.generation,
        })
    }
}

impl Drop for InFlightWaitingBuffer {
    fn drop(&mut self) {
        let slot = &self.inner.slots[usize::from(self.id.0)];
        if slot.generation.get() == self.generation && slot.state.get() == State::InFlight {
            slot.state.set(State::Quarantined);
        }
    }
}

#[cfg(test)]
mod unit_lifecycle_scenario {
    use super::*;

    fn pool(count: u16) -> FixedBufferPool {
        let slots = (0..count)
            .map(|_| Slot {
                bytes: UnsafeCell::new(vec![0; 32].into_boxed_slice()),
                state: Cell::new(State::Free),
                generation: Cell::new(0),
            })
            .collect();
        FixedBufferPool {
            inner: Rc::new(Inner {
                ring: NonNull::dangling(),
                slots,
                free: (0..count).rev().map(Cell::new).collect(),
                free_len: Cell::new(usize::from(count)),
                // A test registration without FFI: all operations stay in user space.
                registered: Cell::new(true),
                mock_registration: true,
            }),
        }
    }

    fn detach(pool: &FixedBufferPool) {
        pool.inner.registered.set(false);
    }

    #[test]
    fn free_stack_reuses_exact_capacity_in_return_order_without_resizing() -> Result<()> {
        let pool = pool(3);
        let allocation = pool.inner.free.as_ptr();
        for _ in 0..1024 {
            let first = pool.checkout()?;
            let second = pool.checkout()?;
            let third = pool.checkout()?;
            let (first_id, second_id) = (first.id(), second.id());
            assert_ne!(first_id, second_id);
            assert_ne!(first_id, third.id());
            assert_ne!(second_id, third.id());
            assert_eq!(pool.available(), 0);
            assert!(matches!(
                pool.checkout(),
                Err(UringError::FixedBuffersExhausted)
            ));
            drop(second);
            drop(first);
            let reused_first = pool.checkout()?;
            let reused_second = pool.checkout()?;
            assert_eq!(reused_first.id(), first_id);
            assert_eq!(reused_second.id(), second_id);
            drop((reused_first, reused_second, third));
            assert_eq!(pool.available(), 3);
            assert_eq!(pool.inner.free.as_ptr(), allocation);
        }
        detach(&pool);
        Ok(())
    }

    #[test]
    fn cancelled_buffers_stay_unavailable_until_target_completion() -> Result<()> {
        let pool = pool(2);
        let mut original = pool.checkout()?;
        original.as_mut_slice()[0] = 91;
        let original_id = original.id();
        let address = original.as_ptr();
        let mut waiting = original.into_in_flight();
        waiting.quarantine()?;
        waiting.quarantine()?;
        drop(waiting);
        let other = pool.checkout()?;
        assert_ne!(other.id(), original_id);
        assert!(pool.checkout().is_err());
        assert_eq!(pool.available(), 0);
        // SAFETY: This test never submits an SQE, so no kernel access exists.
        unsafe { pool.reclaim_completed(original_id)? };
        let recovered = pool.checkout()?;
        assert_eq!(recovered.id(), original_id);
        assert_eq!(recovered.as_ptr(), address);
        assert_eq!(recovered.as_slice()[0], 91);
        detach(&pool);
        Ok(())
    }

    #[test]
    fn stale_waiting_token_cannot_quarantine_a_reused_slot() -> Result<()> {
        let pool = pool(1);
        let old = pool.checkout()?.into_in_flight();
        let id = old.id();
        // SAFETY: No request was submitted; this simulates its final completion.
        unsafe { pool.reclaim_completed(id)? };
        let current = pool.checkout()?.into_in_flight();
        drop(old);
        // SAFETY: No kernel request references this buffer in this unit test.
        let returned = unsafe { current.complete()? };
        assert!(pool.checkout().is_err());
        drop(returned);
        assert_eq!(pool.available(), 1);
        // SAFETY: There is no kernel request; the state must reject double reclaim.
        let reclaimed_twice = unsafe { pool.reclaim_completed(id) };
        assert!(matches!(
            reclaimed_twice,
            Err(UringError::BufferNotInFlight(_))
        ));
        detach(&pool);
        Ok(())
    }

    #[test]
    fn completion_returns_bytes_and_checked_out_drop_recycles_once() -> Result<()> {
        let pool = pool(1);
        let mut buffer = pool.checkout()?;
        buffer.as_mut_slice()[..4].copy_from_slice(b"data");
        let waiting = buffer.into_in_flight();
        assert_eq!(pool.available(), 0);
        // SAFETY: This test never makes the buffer accessible to the kernel.
        let completed = unsafe { waiting.complete()? };
        assert_eq!(&completed.as_slice()[..4], b"data");
        drop(completed);
        assert_eq!(pool.available(), 1);
        let checked_out = pool.checkout()?;
        // SAFETY: No kernel access exists; CheckedOut must reject reclamation.
        let prematurely_reclaimed = unsafe { pool.reclaim_completed(checked_out.id()) };
        assert!(matches!(
            prematurely_reclaimed,
            Err(UringError::BufferNotInFlight(_))
        ));
        drop(checked_out);
        assert_eq!(pool.available(), 1);
        detach(&pool);
        Ok(())
    }

    #[test]
    fn cancel_and_target_completion_orders_keep_reused_generation_isolated() -> Result<()> {
        for cancel_first in [true, false] {
            let pool = pool(1);
            let mut waiting = pool.checkout()?.into_in_flight();
            let id = waiting.id();
            waiting.quarantine()?;
            let mut replacement = None;
            for target_final in [!cancel_first, cancel_first] {
                if target_final {
                    // SAFETY: No SQE is submitted in this unit state-machine
                    // test; this event represents the target's own final CQE.
                    unsafe { pool.reclaim_completed(id)? };
                    replacement = Some(pool.checkout()?.into_in_flight());
                } else {
                    assert_eq!(pool.available(), 0);
                    assert!(matches!(
                        pool.checkout(),
                        Err(UringError::FixedBuffersExhausted)
                    ));
                    assert!(matches!(
                        pool.inner.slots[0].state.get(),
                        State::Quarantined | State::InFlight
                    ));
                }
            }
            assert!(matches!(
                waiting.quarantine(),
                Err(UringError::BufferNotInFlight(_))
            ));
            drop(waiting);
            assert_eq!(pool.inner.slots[0].state.get(), State::InFlight);
            let replacement = replacement.ok_or(UringError::BufferNotInFlight(id.0))?;
            // SAFETY: The replacement also remained in user space throughout;
            // no kernel request or zero-copy notification can still access it.
            drop(unsafe { replacement.complete()? });
            assert_eq!(pool.available(), 1);
            detach(&pool);
        }
        Ok(())
    }

    #[test]
    fn spent_generation_retires_without_blocking_other_slots_or_unregister() -> Result<()> {
        let mut pool = pool(2);
        pool.inner.slots[0].generation.set(u64::MAX);
        assert!(matches!(
            pool.checkout(),
            Err(UringError::Syscall {
                errno: libc::EOVERFLOW,
                ..
            })
        ));
        assert_eq!(pool.inner.slots[0].state.get(), State::Retired);
        assert_eq!(pool.available(), 1);
        let remaining = pool.checkout()?;
        assert_eq!(remaining.id(), BufferId(1));
        assert!(pool.unregister().is_err());
        drop(remaining);
        pool.inner.slots[1].generation.set(u64::MAX);
        assert!(matches!(
            pool.checkout(),
            Err(UringError::Syscall {
                errno: libc::EOVERFLOW,
                ..
            })
        ));
        assert_eq!(pool.inner.slots[1].state.get(), State::Retired);
        assert_eq!(pool.available(), 0);
        assert!(matches!(
            pool.checkout(),
            Err(UringError::FixedBuffersExhausted)
        ));
        pool.unregister()?;
        assert!(!pool.inner.registered.get());
        Ok(())
    }

    #[test]
    fn stale_completion_generation_cannot_reclaim_reused_in_flight_buffer() -> Result<()> {
        let pool = pool(1);
        let old = pool.checkout()?.into_in_flight();
        let id = old.id();
        let old_generation = old.generation();
        // SAFETY: No SQE was submitted, so this operation has no kernel access.
        unsafe { pool.reclaim_completed_generation(id, old_generation)? };
        let current = pool.checkout()?.into_in_flight();
        let current_generation = current.generation();
        assert_ne!(old_generation, current_generation);
        drop(old);
        // SAFETY: The old operation never reached the kernel; only its stale
        // identity is supplied, and rejection must preserve the current owner.
        let stale = unsafe { pool.reclaim_completed_generation(id, old_generation) };
        assert!(matches!(stale, Err(UringError::BufferNotInFlight(_))));
        assert_eq!(pool.available(), 0);
        assert_eq!(pool.inner.slots[0].state.get(), State::InFlight);
        // SAFETY: The current operation also remained entirely in user space.
        drop(unsafe { current.complete()? });
        assert_eq!(pool.available(), 1);
        detach(&pool);
        Ok(())
    }

    #[test]
    fn unregister_rejects_owned_and_quarantined_slots() -> Result<()> {
        let mut pool = pool(1);
        let checked_out = pool.checkout()?;
        assert!(pool.unregister().is_err());
        let mut waiting = checked_out.into_in_flight();
        assert!(pool.unregister().is_err());
        waiting.quarantine()?;
        assert!(pool.unregister().is_err());
        // SAFETY: No SQE was submitted, so no DMA or notification remains.
        unsafe { pool.reclaim_completed(waiting.id())? };
        assert!(matches!(
            waiting.quarantine(),
            Err(UringError::BufferNotInFlight(_))
        ));
        pool.unregister()?;
        pool.unregister()?;
        assert!(pool.checkout().is_err());
        Ok(())
    }
}
