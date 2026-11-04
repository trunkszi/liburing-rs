//! Kernel-selected receive buffers with exclusive payload leases.
//!
//! Completions transfer initialized payload ranges into exclusive leases. A descriptor
//! is republished only after the kernel and every segment lease have relinquished it.

use std::{
    alloc::{Layout, dealloc},
    cell::Cell,
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    os::fd::{AsRawFd, RawFd},
    ptr::NonNull,
    rc::Rc,
};

use uarch::prelude::*;

use crate::{
    backend::{
        register::{self, RegisterTarget},
        sys::register::{IOU_PBUF_RING_INC, IoUringBufReg},
    },
    error::{Result, UringError},
    id::{BufferGroupId, BufferId, OperationId},
};

mod bundle;
mod recovery;
mod storage;

use recovery::DepletedRecvs;
use storage::{BufferBytes, BufferRingStorage};

/// A thread-confined buffer group with stable storage until unregistration.
/// Receiving and returning leases do not allocate.
pub struct BufferRing {
    ring: RegisterTarget,
    buffer_ring: ManuallyDrop<BufferRingStorage>,
    storage_bytes: NonNull<u8>,
    storage_layout: Layout,
    leased_bits: ManuallyDrop<Box<[Cell<Bitmap64>]>>,
    progress: Box<[Progress]>,
    incremental: bool,
    group: BufferGroupId,
    entries: u16,
    buffer_len: u32,
    registered: bool,
    returned: Cell<u64>,
    depleted: DepletedRecvs,
    _thread_bound: PhantomData<Rc<()>>,
}

struct Progress {
    offset: Cell<u32>,
    leases: Cell<usize>,
    kernel_done: Cell<bool>,
    position: Cell<u16>,
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
        ring: *mut crate::backend::IoUring,
        entries: u16,
        buffer_len: usize,
        group: BufferGroupId,
    ) -> Result<Self> {
        let ring = NonNull::new(ring).ok_or_else(|| invalid("null io_uring pointer"))?;
        // SAFETY: The caller guarantees a live stable ring and exclusive group ownership.
        unsafe {
            Self::with_target(
                RegisterTarget::VfsFd(ring.as_ref().as_raw_fd()),
                entries,
                buffer_len,
                group,
                false,
            )
        }
    }

    /// Registers buffers for incremental consumption with disjoint CQE slice views.
    /// # Errors
    /// Rejects invalid dimensions and propagates kernel registration errors.
    /// # Panics
    /// Allocation follows the allocator policy.
    /// # Safety
    /// The ring and exclusive group must obey the lifetime and final-CQE contract of `new`.
    pub unsafe fn new_incremental(
        ring: *mut crate::backend::IoUring,
        entries: u16,
        buffer_len: usize,
        group: BufferGroupId,
    ) -> Result<Self> {
        let ring = NonNull::new(ring).ok_or_else(|| invalid("null io_uring pointer"))?;
        // SAFETY: The caller guarantees the ring and group remain exclusively owned and live.
        unsafe {
            Self::with_target(
                RegisterTarget::VfsFd(ring.as_ref().as_raw_fd()),
                entries,
                buffer_len,
                group,
                true,
            )
        }
    }

    /// Registers a group on a native VFS or task-local ring target.
    /// # Errors
    /// Rejects invalid dimensions and propagates kernel registration errors.
    /// # Panics
    /// Allocation follows the allocator policy.
    /// # Safety
    /// The target must remain live and unchanged on this thread until group drop.
    /// Own the group exclusively and drain every selecting operation before unregister/drop.
    pub unsafe fn with_target(
        ring: RegisterTarget,
        entries: u16,
        buffer_len: usize,
        group: BufferGroupId,
        incremental: bool,
    ) -> Result<Self> {
        if !entries.is_power_of_two() || entries > 32768 {
            return Err(invalid(
                "buffer ring entries must be a power of two up to 32768",
            ));
        }
        if buffer_len == 0 || buffer_len > i32::MAX as usize {
            return Err(invalid("buffer length must be in 1..=i32::MAX"));
        }
        let bytes = BufferBytes::new(entries, buffer_len)?;
        let leased_bits: Box<[Cell<Bitmap64>]> = (0..((usize::from(entries) + 63) >> 6))
            .map(|_| Cell::new(Bitmap64::EMPTY))
            .collect();
        let depleted = DepletedRecvs::new(entries);
        let buffer_ring = BufferRingStorage::new(entries)?;
        let progress = (0..entries)
            .map(|_| Progress {
                offset: Cell::new(0),
                leases: Cell::new(0),
                kernel_done: Cell::new(false),
                position: Cell::new(0),
            })
            .collect();
        let mut record = IoUringBufReg {
            ring_addr: buffer_ring.address(),
            ring_entries: u32::from(entries),
            bgid: group.0,
            flags: if incremental { IOU_PBUF_RING_INC } else { 0 },
            ..Default::default()
        };
        // SAFETY: Descriptor and payload allocations remain live through unregister and final DMA.
        unsafe {
            register::register_pbuf_ring(ring, &mut record)?;
        }
        let bytes = ManuallyDrop::new(bytes);
        let result = Self {
            ring,
            buffer_ring: ManuallyDrop::new(buffer_ring),
            storage_bytes: bytes.pointer,
            storage_layout: bytes.layout,
            leased_bits: ManuallyDrop::new(leased_bits),
            progress,
            incremental,
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
            || self.buffer_ring.available(self.ring, self.group.0),
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
    /// With incremental registration, each CQE leases a disjoint segment. BUF_MORE
    /// keeps the kernel's remaining suffix active; recycling waits for the final CQE
    /// and every outstanding segment lease. Other groups reject BUF_MORE.
    /// Pass error completions here as well: when
    /// `result` is negative and `IORING_CQE_F_BUFFER` is set, the selected buffer
    /// is validated without exposing payload. Recycling waits for earlier segment
    /// leases, if any, to end.
    ///
    /// # Errors
    /// Returns an error for an inactive group, absent or invalid buffer ID,
    /// oversized payload, unsupported incremental flag, or an already leased buffer.
    /// A negative result returns its original syscall error after recycling any
    /// valid selected buffer; a negative result without a selection only returns
    /// the syscall error. Invalid selected-buffer metadata is rejected without
    /// republishing a buffer and takes precedence over the syscall error, except
    /// an oversized payload returns its valid, unleased nonincremental buffer.
    /// Malformed incremental payloads retain ownership without republishing storage.
    ///
    /// # Panics
    /// Does not panic.
    ///
    /// # Safety
    /// The arguments must come from an unconsumed CQE of an operation selecting
    /// this group. The CQE must grant exclusive access to its selected buffer:
    /// no kernel write may remain in flight for the completed segment. Process all
    /// CQEs in order exactly once, including segments whose lease was released.
    /// The kernel may only write the disjoint suffix of an incremental buffer.
    #[inline]
    pub unsafe fn lease_from_cqe(&self, flags: u32, result: i32) -> Result<BufferLease<'_>> {
        if !self.registered {
            return Err(invalid("buffer ring is not registered"));
        }
        if result < 0 && Self::buffer_id_from_flags(flags).is_none() {
            return Err(kernel_error(result));
        }
        let more = flags & (1 << 4) != 0;
        if more && !self.incremental {
            return Err(invalid("incremental buffer is still owned by the kernel"));
        }
        let id = Self::buffer_id_from_flags(flags)
            .ok_or_else(|| invalid("completion has no selected buffer"))?;
        let index = usize::from(id.0);
        if id.0 >= self.entries {
            return Err(invalid("completion buffer ID is outside the group"));
        }
        let leased = &self.leased_bits[index >> 6];
        let bit = (index & 63) as u32;
        let bits = leased.get();
        let progress = &self.progress[index];
        if bits.test(bit) && (!self.incremental || progress.kernel_done.get()) {
            return Err(invalid("selected buffer is already leased"));
        }
        let offset = progress.offset.get();
        if result > 0 && result as u32 > self.buffer_len - offset {
            if !self.incremental {
                self.return_buffer(id);
            }
            return Err(invalid("completion payload exceeds buffer capacity"));
        }
        if more && result <= 0 {
            return Err(invalid("incremental completion must advance payload"));
        }
        leased.set(bits.set(bit));
        progress.offset.set(offset + result.max(0) as u32);
        progress.kernel_done.set(!more);
        progress.leases.set(progress.leases.get() + 1);
        let lease = BufferLease {
            owner: self,
            id,
            offset: offset as usize,
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
        unsafe {
            register::unregister_pbuf_ring(self.ring, self.group.0)?;
        }
        self.registered = false;
        Ok(())
    }

    #[inline]
    fn publish(&self, id: u16, offset: i32) {
        self.progress[usize::from(id)]
            .position
            .set(self.buffer_ring.tail().wrapping_add(offset as u16));
        self.buffer_ring.publish(
            self.buffer_pointer(id),
            self.buffer_len,
            id,
            offset as u16,
            self.entries - 1,
        );
    }

    #[inline]
    fn return_buffer(&self, id: BufferId) {
        self.publish(id.0, 0);
        self.buffer_ring.advance(1);
        let index = usize::from(id.0);
        let bits = &self.leased_bits[index >> 6];
        bits.set(bits.get().clear((index & 63) as u32));
        self.progress[index].offset.set(0);
        self.progress[index].kernel_done.set(false);
        self.returned.set(self.returned.get().wrapping_add(1));
    }

    #[inline]
    fn buffer_pointer(&self, id: u16) -> *mut u8 {
        // SAFETY: Construction and validated CQE handoffs bound id below entries; multiplication
        // fits the allocation.
        unsafe {
            self.storage_bytes
                .as_ptr()
                .add(usize::from(id) * self.buffer_len as usize)
        }
    }
}

impl Drop for BufferRing {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: The constructor's contract requires all operations to finish
        // before drop. The last owner cannot have any live borrowed lease.
        let unregistered = unsafe { self.unregister() };
        if unregistered.is_ok() && !self.leased_bits.iter().any(|word| !word.get().is_empty()) {
            // SAFETY: Unregistration succeeded, so descriptors cannot be selected
            // again; the caller drained pending I/O, and no forgotten lease holds
            // a selected buffer. This is the sole destruction of the allocation.
            unsafe {
                dealloc(self.storage_bytes.as_ptr(), self.storage_layout);
                ManuallyDrop::drop(&mut self.leased_bits);
                ManuallyDrop::drop(&mut self.buffer_ring);
            };
        }
        // Failed unregistration retains storage rather than freeing addresses
        // that the kernel may still hold. Explicit unregister reports the error.
    }
}

/// An exclusive receive payload view that releases its segment on drop.
///
/// Keeps its owner alive. Full capacity is republished after the final incremental
/// CQE and the last outstanding segment lease, including during unwinding.
pub struct BufferLease<'a> {
    owner: &'a BufferRing,
    id: BufferId,
    len: usize,
    offset: usize,
}

impl BufferLease<'_> {
    /// Returns the initialized payload length.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Reports whether the payload is empty.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrows the exclusively leased payload.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.deref()
    }

    /// Mutably borrows the exclusively leased payload.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.deref_mut()
    }

    /// Returns the kernel-selected buffer ID.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    #[inline]
    pub const fn buffer_id(&self) -> BufferId {
        self.id
    }

    /// Releases this segment immediately, recycling the buffer when no owner remains.
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

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: Ordered CQE handoff grants this disjoint initialized segment;
        // offset/length validation excludes the kernel-owned suffix and every
        // other lease. The owner retains the allocation until all views end.
        unsafe {
            std::slice::from_raw_parts(
                self.owner.buffer_pointer(self.id.0).add(self.offset),
                self.len,
            )
        }
    }
}

impl DerefMut for BufferLease<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: This lease exclusively owns its checked disjoint segment.
        // The kernel may write only the suffix, and the mutable lease borrow
        // excludes other references into this segment.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.owner.buffer_pointer(self.id.0).add(self.offset),
                self.len,
            )
        }
    }
}

impl Drop for BufferLease<'_> {
    #[inline]
    fn drop(&mut self) {
        let progress = &self.owner.progress[usize::from(self.id.0)];
        let remaining = progress.leases.get() - 1;
        progress.leases.set(remaining);
        if remaining == 0 && progress.kernel_done.get() {
            self.owner.return_buffer(self.id);
        }
    }
}

#[cold]
#[inline(never)]
fn invalid(message: &'static str) -> UringError {
    UringError::InvalidConfig(message)
}

#[cold]
#[inline(never)]
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
