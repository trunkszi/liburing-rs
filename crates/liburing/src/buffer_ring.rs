//! Kernel-selected receive buffers with exclusive payload leases.
//!
//! A completion transfers a selected buffer from the kernel to a lease. Returning
//! the lease republishes its descriptor before advancing the shared ring tail.

use std::{
    cell::{Cell, UnsafeCell},
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    os::fd::RawFd,
    ptr::NonNull,
    rc::Rc,
};

use crate::{
    error::{Result, UringError},
    id::{BufferGroupId, BufferId, OperationId},
};

struct ReceiveBuffer {
    bytes: Box<[UnsafeCell<u8>]>,
    leased: Cell<bool>,
}

mod recovery;
mod storage;

use recovery::DepletedRecvs;
use storage::BufferRingStorage;

/// A thread-confined buffer group with stable storage until unregistration.
/// Receiving and returning leases do not allocate.
pub struct BufferRing {
    ring: NonNull<io_uring::IoUring>,
    buffer_ring: ManuallyDrop<BufferRingStorage>,
    buffers: ManuallyDrop<Box<[ReceiveBuffer]>>,
    group: BufferGroupId,
    entries: u16,
    buffer_len: u32,
    registered: bool,
    returned: Cell<u64>,
    depleted: DepletedRecvs,
    _thread_bound: PhantomData<Rc<()>>,
}

impl BufferRing {
    /// Registers and initially publishes `entries` buffers of `buffer_len` bytes.
    ///
    /// `entries` must be a power of two in `1..=32768`; lengths fit a signed CQE.
    /// Recovery preallocates `entries` records and rejects overflow without allocating.
    ///
    /// # Errors
    /// Returns an error for invalid arguments or failed kernel registration.
    ///
    /// # Panics
    /// Does not panic for invalid arguments. Allocation follows the allocator's
    /// out-of-memory policy.
    ///
    /// # Safety
    /// `ring` must be an initialized ring confined to this thread and remain alive
    /// until this object is dropped. No other owner may register or unregister
    /// `group`. All operations selecting this group must finish before this
    /// object is unregistered or dropped, including requests awaiting cancellation.
    pub unsafe fn new(
        ring: *mut io_uring::IoUring,
        entries: u16,
        buffer_len: usize,
        group: BufferGroupId,
    ) -> Result<Self> {
        let ring = NonNull::new(ring).ok_or_else(|| invalid("null io_uring pointer"))?;
        if !entries.is_power_of_two() || entries > 32768 {
            return Err(invalid(
                "buffer ring entries must be a power of two up to 32768",
            ));
        }
        if buffer_len == 0 || buffer_len > i32::MAX as usize {
            return Err(invalid("buffer length must be in 1..=i32::MAX"));
        }
        let buffers: Box<[ReceiveBuffer]> = (0..entries)
            .map(|_| ReceiveBuffer {
                bytes: (0..buffer_len).map(|_| UnsafeCell::new(0)).collect(),
                leased: Cell::new(false),
            })
            .collect();
        let depleted = DepletedRecvs::new(entries);
        let buffer_ring = BufferRingStorage::new(entries)?;
        // SAFETY: The ring is live and exclusively managed on this thread;
        // page-aligned descriptors and their payloads remain alive until unregister.
        unsafe {
            ring.as_ref().submitter().register_buf_ring_with_flags(
                buffer_ring.address(),
                entries,
                group.0,
                0,
            )
        }
        .map_err(|error| UringError::BufferRingSetup(error.raw_os_error().unwrap_or(libc::EIO)))?;
        let result = Self {
            ring,
            buffer_ring: ManuallyDrop::new(buffer_ring),
            buffers: ManuallyDrop::new(buffers),
            group,
            entries,
            buffer_len: buffer_len as u32,
            registered: true,
            returned: Cell::new(0),
            depleted,
            _thread_bound: PhantomData,
        };
        for id in 0..entries {
            result.publish(id, i32::from(id));
        }
        result.buffer_ring.advance(entries);
        Ok(result)
    }

    /// Returns the registered group used by buffer-select receive SQEs.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub const fn group_id(&self) -> BufferGroupId {
        self.group
    }

    /// Returns the wrapping count of consumed buffers returned by leases.
    ///
    /// After `-ENOBUFS`, a changed value indicates replenishment.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn returned_count(&self) -> u64 {
        self.returned.get()
    }

    /// Parks a receive after its target's terminal `-ENOBUFS` completion.
    ///
    /// The caller must establish termination, not just cancellation acknowledgment.
    /// `fd`, socket message `flags`, and `operation_id` are retained for rearming. Identical
    /// duplicate records are idempotent. Keep the descriptor
    /// open until rearmed or removed with [`Self::forget_depleted_recv`].
    ///
    /// # Errors
    /// Returns an error for an inactive group, negative descriptor, conflicting
    /// duplicate parameters, or exhausted preallocated recovery capacity (`ENOSPC`).
    ///
    /// # Panics
    /// Does not panic.
    pub fn mark_depleted_recv(
        &self,
        fd: RawFd,
        flags: i32,
        operation_id: OperationId,
    ) -> Result<()> {
        if !self.registered {
            return Err(invalid("buffer ring is not registered"));
        }
        self.depleted
            .mark(fd, flags, operation_id, self.returned.get())
    }

    /// Stages depleted receives when buffers have been replenished.
    ///
    /// The callback receives the original descriptor, message flags, operation ID,
    /// and group. It must stage one multishot receive on `Ok(())`, nothing on error
    /// or panic. Successful records are removed; remaining records survive failure.
    /// Returns the number staged in this bounded, allocation-free scan. Callbacks
    /// may return leases or park receives, considered on the next call. Credits
    /// are reserved once per staged receive across calls. Each scan verifies its
    /// quota against current kernel inventory before staging any receive. Query
    /// failure stages nothing; retries cannot recount staged reservations.
    ///
    /// # Errors
    /// Returns an error for an inactive group, recursive recovery, failed kernel
    /// buffer-status query, or callback failure. Earlier successful callbacks
    /// remain staged when a later one fails. Recovery requires kernel support
    /// for querying provided-buffer status.
    ///
    /// # Panics
    /// Propagates callback panics, retaining its pending record and resetting the
    /// recovery guard so a caller that catches the panic can retry.
    pub fn rearm_depleted_recvs(
        &self,
        submitter: impl FnMut(RawFd, i32, OperationId, BufferGroupId) -> Result<()>,
    ) -> Result<usize> {
        if !self.registered {
            return Err(invalid("buffer ring is not registered"));
        }
        self.depleted.rearm(
            self.returned.get(),
            self.group,
            || {
                // SAFETY: Construction retains the live, thread-confined ring.
                self.buffer_ring
                    .available(unsafe { self.ring.as_ref() }, self.group.0)
            },
            submitter,
        )
    }

    /// Removes a parked receive before cancellation or descriptor close.
    ///
    /// Returns whether a pending record was removed. This removes only an
    /// unsubmitted recovery record; it does not cancel an already rearmed receive.
    ///
    /// # Errors
    /// Returns a reentrancy error if called from a recovery callback.
    ///
    /// # Panics
    /// Does not panic.
    pub fn forget_depleted_recv(&self, operation_id: OperationId) -> Result<bool> {
        self.depleted.forget(operation_id)
    }

    /// Extracts the selected buffer ID, when the CQE carries a buffer selection.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub const fn buffer_id_from_flags(flags: u32) -> Option<BufferId> {
        if flags & 1 == 0 {
            None
        } else {
            Some(BufferId((flags >> 16) as u16))
        }
    }

    /// Transfers the payload described by a receive CQE into an exclusive lease.
    ///
    /// Operation-level `IORING_CQE_F_MORE` is permitted for multishot receives;
    /// incremental-buffer `IORING_CQE_F_BUF_MORE` is rejected because the kernel
    /// retains access to that buffer. Pass error completions here as well: when
    /// `result` is negative and `IORING_CQE_F_BUFFER` is set, the selected buffer
    /// is validated and returned immediately without exposing any payload.
    ///
    /// # Errors
    /// Returns an error for an inactive group, absent or invalid buffer ID,
    /// oversized payload, incremental buffer, or an already leased buffer.
    /// A negative result returns its original syscall error after recycling any
    /// valid selected buffer; a negative result without a selection only returns
    /// the syscall error. Invalid selected-buffer metadata is rejected without
    /// republishing a buffer and takes precedence over the syscall error, except
    /// an oversized payload returns its valid, unleased selected buffer.
    ///
    /// # Panics
    /// Does not panic.
    ///
    /// # Safety
    /// The arguments must come from an unconsumed CQE of an operation selecting
    /// this group. The CQE must grant exclusive access to its selected buffer:
    /// no kernel write may remain in flight for that buffer. Each completion may
    /// be handed off once, including after a previous lease has been released.
    pub unsafe fn lease_from_cqe(&self, flags: u32, result: i32) -> Result<BufferLease<'_>> {
        if !self.registered {
            return Err(invalid("buffer ring is not registered"));
        }
        if result < 0 && Self::buffer_id_from_flags(flags).is_none() {
            return Err(kernel_error(result));
        }
        if flags & (1 << 4) != 0 {
            return Err(invalid("incremental buffer is still owned by the kernel"));
        }
        let id = Self::buffer_id_from_flags(flags)
            .ok_or_else(|| invalid("completion has no selected buffer"))?;
        let buffer = self
            .buffers
            .get(usize::from(id.0))
            .ok_or_else(|| invalid("completion buffer ID is outside the group"))?;
        if buffer.leased.get() {
            return Err(invalid("selected buffer is already leased"));
        }
        if result > 0 && result as u32 > self.buffer_len {
            self.return_buffer(id);
            return Err(invalid("completion payload exceeds buffer capacity"));
        }
        buffer.leased.set(true);
        let lease = BufferLease {
            owner: self,
            id,
            len: result.max(0) as usize,
        };
        if result < 0 {
            drop(lease);
            Err(kernel_error(result))
        } else {
            Ok(lease)
        }
    }

    /// Unregisters the group while retaining descriptor storage until drop.
    ///
    /// Storage survives until drop; success prevents new leases, failure leaves it active.
    ///
    /// # Errors
    /// Returns the kernel's error if the group cannot be unregistered.
    ///
    /// # Panics
    /// Does not panic.
    ///
    /// # Safety
    /// Every receive selecting this group must have delivered its final CQE.
    /// A cancellation control CQE alone does not establish that condition.
    pub unsafe fn unregister(&mut self) -> Result<()> {
        if !self.registered {
            return Ok(());
        }
        // SAFETY: Construction establishes ring/group ownership, mutable access
        // excludes live leases, and the caller guarantees all kernel I/O drained.
        unsafe { self.ring.as_ref() }
            .submitter()
            .unregister_buf_ring(self.group.0)?;
        self.registered = false;
        Ok(())
    }

    fn publish(&self, id: u16, offset: i32) {
        let buffer = &self.buffers[usize::from(id)];
        self.buffer_ring.publish(
            buffer.bytes.as_ptr().cast::<u8>().cast_mut(),
            self.buffer_len,
            id,
            offset as u16,
            self.entries - 1,
        );
    }

    fn return_buffer(&self, id: BufferId) {
        self.publish(id.0, 0);
        self.buffer_ring.advance(1);
        self.buffers[usize::from(id.0)].leased.set(false);
        self.returned.set(self.returned.get().wrapping_add(1));
    }
}

impl Drop for BufferRing {
    fn drop(&mut self) {
        // SAFETY: The constructor's contract requires all operations to finish
        // before drop. The last owner cannot have any live borrowed lease.
        let unregistered = unsafe { self.unregister() };
        if unregistered.is_ok() && !self.buffers.iter().any(|buffer| buffer.leased.get()) {
            // SAFETY: Unregistration succeeded, so descriptors cannot be selected
            // again; the caller drained pending I/O, and no forgotten lease holds
            // a selected buffer. This is the sole destruction of the allocation.
            unsafe {
                ManuallyDrop::drop(&mut self.buffers);
                ManuallyDrop::drop(&mut self.buffer_ring);
            };
        }
        // Failed unregistration retains storage rather than freeing addresses
        // that the kernel may still hold. Explicit unregister reports the error.
    }
}

/// An exclusive receive payload view that returns its buffer on drop.
///
/// Keeps its owner alive and republishes full capacity, including during unwinding.
pub struct BufferLease<'a> {
    owner: &'a BufferRing,
    id: BufferId,
    len: usize,
}

impl BufferLease<'_> {
    /// Returns the kernel-selected buffer ID.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub const fn buffer_id(&self) -> BufferId {
        self.id
    }

    /// Returns the buffer to the kernel immediately.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    pub fn release(self) {
        drop(self);
    }
}

impl Deref for BufferLease<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let buffer = &self.owner.buffers[usize::from(self.id.0)];
        // SAFETY: CQE handoff proves the kernel relinquished this buffer; the
        // leased flag rejects duplicate leases, the owner keeps storage alive,
        // and the validated CQE result bounds the initialized payload.
        unsafe { std::slice::from_raw_parts(buffer.bytes.as_ptr().cast::<u8>(), self.len) }
    }
}

impl DerefMut for BufferLease<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let buffer = &self.owner.buffers[usize::from(self.id.0)];
        // SAFETY: This lease has exclusive access to the selected buffer until
        // drop. The mutable lease borrow excludes other payload references and
        // the payload length was checked against the allocation at handoff.
        unsafe {
            std::slice::from_raw_parts_mut(buffer.bytes.as_ptr().cast::<u8>().cast_mut(), self.len)
        }
    }
}

impl Drop for BufferLease<'_> {
    fn drop(&mut self) {
        self.owner.return_buffer(self.id);
    }
}

fn invalid(message: &'static str) -> UringError {
    UringError::InvalidConfig(message)
}

fn kernel_error(result: i32) -> UringError {
    UringError::Syscall {
        operation: "buffer ring",
        errno: if result < 0 {
            result.saturating_neg()
        } else {
            libc::EIO
        },
    }
}
