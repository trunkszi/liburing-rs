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

mod aligned;
pub(crate) use aligned::DEFAULT_ALIGNMENT;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Free = 0,
    Retired = 1,
    CheckedOut = 2,
    InFlight = 4,
    Quarantined = 5,
}

struct Slot {
    bytes: UnsafeCell<aligned::AlignedBytes>,
    state: Cell<State>,
    generation: Cell<u64>,
}

impl Slot {
    fn allocation(&self) -> (*mut u8, usize) {
        // SAFETY: The allocation address and length are fixed at construction.
        // Reading them does not borrow the bytes the kernel may be accessing.
        let bytes = unsafe { &*self.bytes.get() };
        (bytes.as_ptr(), bytes.len())
    }
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
    /// Each buffer is aligned to 4096 bytes. Construction allocates memory;
    /// checkout and completion transitions do not.
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
        // SAFETY: The caller upholds the ring lifetime required by `with_alignment`.
        unsafe { Self::with_alignment(ring, buffer_count, buffer_len, DEFAULT_ALIGNMENT) }
    }

    /// Allocate and register buffers aligned to a power-of-two `alignment`.
    ///
    /// Use the file's `statx` `stx_dio_mem_align` for `O_DIRECT`.
    ///
    /// # Errors
    /// Returns an error for a null ring, a non-power-of-two alignment, zero
    /// dimensions, lengths above `u32::MAX`, allocation failure, or a failed
    /// kernel buffer registration.
    ///
    /// # Panics
    /// This function does not intentionally panic.
    ///
    /// # Safety
    /// `ring` must identify an initialized ring owned by this thread and outlive
    /// this pool and every handle derived from it. No other owner may register,
    /// update, or unregister its fixed buffers during that lifetime. Ring access
    /// must remain serialized on this thread, including while handles are dropped.
    pub unsafe fn with_alignment(
        ring: *mut io_uring::IoUring,
        buffer_count: u16,
        buffer_len: usize,
        alignment: usize,
    ) -> Result<Self> {
        let ring = NonNull::new(ring).ok_or_else(|| error(libc::EINVAL))?;
        if !alignment.is_power_of_two()
            || buffer_count == 0
            || buffer_len == 0
            || buffer_len > u32::MAX as usize
        {
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
            let bytes = aligned::AlignedBytes::allocate(buffer_len, alignment)?;
            iovecs.push(libc::iovec {
                iov_base: bytes.as_ptr().cast(),
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

    /// Returns the stable base address of the registered allocation.
    ///
    /// Forming the pointer does not borrow the bytes. Do not dereference it
    /// while the kernel owns the buffer.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn as_ptr(&self) -> *mut u8 {
        self.inner.slots[usize::from(self.id.0)].allocation().0
    }

    /// Returns the registered allocation length in bytes.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.slots[usize::from(self.id.0)].allocation().1
    }

    /// Reports whether the registered allocation is empty.
    ///
    /// Pool construction rejects a zero length, so a live token is never empty.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
mod unit_lifecycle_scenario;
