//! Registered, stable-address buffers with explicit completion ownership.
//!
//! Cancellation only quarantines a buffer. Its original operation's final CQE,
//! rather than the cancellation request's CQE, authorizes reuse.

use std::{
    cell::{Cell, RefCell, UnsafeCell},
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
    ring: NonNull<liburing_sys::io_uring>,
    slots: Vec<Slot>,
    free: RefCell<Vec<u16>>,
    registered: Cell<bool>,
    #[cfg(test)]
    mock_registration: bool,
}

fn error(errno: i32) -> UringError {
    std::io::Error::from_raw_os_error(errno).into()
}

impl Inner {
    fn release(&self, id: BufferId) {
        self.slots[usize::from(id.0)].state.set(State::Free);
        self.free.borrow_mut().push(id.0);
    }

    fn unregister_kernel(&self) -> i32 {
        #[cfg(test)]
        if self.mock_registration {
            return 0;
        }
        // SAFETY: Construction requires the live ring to outlast every pool
        // lease. This registration belongs exclusively to this owner thread.
        unsafe { liburing_sys::uring_shim_unregister_buffers(self.ring.as_ptr()) }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let outstanding = self
            .slots
            .iter()
            .any(|slot| matches!(slot.state.get(), State::InFlight | State::Quarantined));
        let unregister_failed = if self.registered.get() {
            self.unregister_kernel() < 0
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
        ring: *mut liburing_sys::io_uring,
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
            iovecs.push(liburing_sys::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            });
            slots.push(Slot {
                bytes: UnsafeCell::new(bytes),
                state: Cell::new(State::Free),
                generation: Cell::new(0),
            });
            free.push(buffer_count - id - 1);
        }
        // SAFETY: The ring is initialized by the caller. All iovecs refer to
        // initialized, uniquely owned stable allocations retained in `slots`.
        // Registration copies the iovec descriptors before returning.
        let result = unsafe {
            liburing_sys::uring_shim_register_buffers(
                ring.as_ptr(),
                iovecs.as_ptr(),
                u32::from(buffer_count),
            )
        };
        if result < 0 {
            return Err(UringError::syscalls("register_buffers", -result));
        }
        Ok(Self {
            inner: Rc::new(Inner {
                ring,
                slots,
                free: RefCell::new(free),
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
    ///
    /// # Panics
    /// This function does not panic.
    pub fn checkout(&self) -> Result<FixedBufHandle> {
        if !self.inner.registered.get() {
            return Err(error(libc::ENXIO));
        }
        let mut free = self.inner.free.borrow_mut();
        let id = free
            .last()
            .copied()
            .ok_or(UringError::FixedBuffersExhausted)?;
        let slot = &self.inner.slots[usize::from(id)];
        let generation = slot
            .generation
            .get()
            .checked_add(1)
            .ok_or_else(|| error(libc::EOVERFLOW))?;
        let remaining = free.len() - 1;
        free.truncate(remaining);
        slot.generation.set(generation);
        slot.state.set(State::CheckedOut);
        Ok(FixedBufHandle {
            inner: Rc::clone(&self.inner),
            id: BufferId(id),
            generation,
        })
    }

    /// Return the total number of registered slots.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.slots.len()
    }

    /// Return the number of buffers immediately available for checkout.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn available(&self) -> usize {
        self.inner.free.borrow().len()
    }

    /// Release a submitted or quarantined buffer after its final completion.
    ///
    /// A stale waiting token cannot quarantine a later checkout of this slot.
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
        if self.available() != self.capacity() {
            return Err(error(libc::EBUSY));
        }
        let result = self.inner.unregister_kernel();
        if result < 0 {
            return Err(UringError::syscalls("unregister_buffers", -result));
        }
        self.inner.registered.set(false);
        Ok(())
    }
}

/// Exclusive user-space access to a registered buffer that is not in flight.
///
/// Dropping this handle returns its slot to the pool. Submission must consume it
/// through [`Self::into_in_flight`] before the kernel can access its bytes.
pub struct FixedBufHandle {
    inner: Rc<Inner>,
    id: BufferId,
    generation: u64,
}

impl FixedBufHandle {
    /// Return the fixed-buffer index to write into a fixed I/O SQE.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn id(&self) -> BufferId {
        self.id
    }

    /// Borrow initialized bytes while no kernel operation owns this slot.
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
    /// # Panics
    /// This function does not panic.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: The non-cloneable handle has exclusive CheckedOut ownership,
        // and its mutable borrow prevents any other user-space access.
        unsafe { &mut *self.inner.slots[usize::from(self.id.0)].bytes.get() }
    }

    /// Return the stable address used when preparing a fixed write request.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }

    /// Return the stable address used when preparing a fixed read request.
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

impl Drop for FixedBufHandle {
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
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn id(&self) -> BufferId {
        self.id
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
    pub unsafe fn complete(self) -> Result<FixedBufHandle> {
        let slot = &self.inner.slots[usize::from(self.id.0)];
        if slot.generation.get() != self.generation
            || !matches!(slot.state.get(), State::InFlight | State::Quarantined)
        {
            return Err(UringError::BufferNotInFlight(self.id.0));
        }
        slot.state.set(State::CheckedOut);
        Ok(FixedBufHandle {
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
                free: RefCell::new((0..count).rev().collect()),
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
