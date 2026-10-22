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
    id::{BufGroupId, BufferId, OpId},
};

struct ReceiveBuffer {
    bytes: Box<[UnsafeCell<u8>]>,
    leased: Cell<bool>,
}

#[derive(Clone, Copy)]
struct DepletedRecv {
    fd: RawFd,
    flags: i32,
    op_id: OpId,
    deferred: bool,
}

struct DepletedRecvs {
    records: Box<[Cell<Option<DepletedRecv>>]>,
    rearming: Cell<bool>,
    returned: Cell<u64>,
    credits: Cell<u64>,
    started: Cell<bool>,
}

struct RearmGuard<'a>(&'a Cell<bool>);

impl Drop for RearmGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl DepletedRecvs {
    fn new(capacity: u16) -> Self {
        Self {
            records: (0..capacity).map(|_| Cell::new(None)).collect(),
            rearming: Cell::new(false),
            returned: Cell::new(0),
            credits: Cell::new(0),
            started: Cell::new(false),
        }
    }

    fn mark(&self, fd: RawFd, flags: i32, op_id: OpId, returned: u64) -> Result<()> {
        if fd < 0 {
            return Err(invalid(
                "depleted receive requires a nonnegative descriptor",
            ));
        }
        let mut vacant = None;
        for record in &self.records {
            match record.get() {
                Some(previous) if previous.op_id == op_id => {
                    return if previous.fd == fd && previous.flags == flags {
                        Ok(())
                    } else {
                        Err(invalid(
                            "depleted operation ID has conflicting receive parameters",
                        ))
                    };
                }
                None if vacant.is_none() => vacant = Some(record),
                _ => {}
            }
        }
        if !self.started.get() && !self.records.iter().any(|record| record.get().is_some()) {
            self.returned.set(returned);
            self.credits.set(0);
        }
        let record = vacant.ok_or(UringError::Syscall {
            op: "mark_depleted_recv",
            errno: libc::ENOSPC,
        })?;
        record.set(Some(DepletedRecv {
            fd,
            flags,
            op_id,
            deferred: self.rearming.get(),
        }));
        Ok(())
    }

    fn forget(&self, op_id: OpId) -> Result<bool> {
        if self.rearming.get() {
            return Err(UringError::ReentrantDispatch);
        }
        for record in &self.records {
            if record.get().is_some_and(|pending| pending.op_id == op_id) {
                record.set(None);
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn rearm(
        &self,
        returned: u64,
        group: BufGroupId,
        mut available: impl FnMut() -> Result<u64>,
        mut submitter: impl FnMut(RawFd, i32, OpId, BufGroupId) -> Result<()>,
    ) -> Result<usize> {
        if self.rearming.replace(true) {
            return Err(UringError::ReentrantDispatch);
        }
        let _guard = RearmGuard(&self.rearming);
        for record in &self.records {
            if let Some(mut pending) = record.get() {
                pending.deferred = false;
                record.set(Some(pending));
            }
        }
        let replenished = returned.wrapping_sub(self.returned.replace(returned));
        self.credits
            .set(self.credits.get().saturating_add(replenished));
        if self.records.iter().any(|record| record.get().is_some()) {
            let count = available()?;
            // Inventory can include earlier staged reservations. After the first
            // callback succeeds, queries may only reduce the remaining quota.
            self.credits.set(if self.started.get() {
                self.credits.get().min(count)
            } else {
                count
            });
        }
        let mut staged = 0;
        for record in &self.records {
            if let Some(pending) = record.get() {
                if pending.deferred || self.credits.get() == 0 {
                    continue;
                }
                submitter(pending.fd, pending.flags, pending.op_id, group)?;
                record.set(None);
                self.credits.set(self.credits.get() - 1);
                self.started.set(true);
                staged += 1;
            }
        }
        Ok(staged)
    }
}

/// A thread-confined buffer group with stable storage until unregistration.
/// Receiving and returning leases do not allocate.
pub struct ProvidedBufRing {
    ring: NonNull<liburing_sys::io_uring>,
    buffer_ring: NonNull<liburing_sys::io_uring_buf_ring>,
    buffers: ManuallyDrop<Box<[ReceiveBuffer]>>,
    group: BufGroupId,
    entries: u16,
    buffer_len: u32,
    registered: bool,
    returned: Cell<u64>,
    depleted: DepletedRecvs,
    _thread_bound: PhantomData<Rc<()>>,
}

impl ProvidedBufRing {
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
        ring: *mut liburing_sys::io_uring,
        entries: u16,
        buffer_len: usize,
        group: BufGroupId,
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
        let mut error = 0;
        // SAFETY: The caller guarantees an initialized, live, thread-confined
        // ring and exclusive ownership of this group. Entry count was validated.
        let raw = unsafe {
            liburing_sys::uring_shim_setup_buf_ring(
                ring.as_ptr(),
                u32::from(entries),
                i32::from(group.0),
                0,
                &mut error,
            )
        };
        let buffer_ring = NonNull::new(raw).ok_or_else(|| {
            UringError::ProvidedBufRingSetup(if error < 0 {
                error.saturating_neg()
            } else {
                libc::EIO
            })
        })?;
        let result = Self {
            ring,
            buffer_ring,
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
        // SAFETY: All descriptors below the new tail were initialized above and
        // the registered ring has exactly `entries` slots.
        unsafe {
            liburing_sys::uring_shim_buf_ring_advance(
                result.buffer_ring.as_ptr(),
                i32::from(entries),
            );
        }
        Ok(result)
    }

    /// Returns the registered group used by buffer-select receive SQEs.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub const fn group_id(&self) -> BufGroupId {
        self.group
    }

    /// Returns the wrapping count of consumed buffers returned by leases.
    ///
    /// After `-ENOBUFS`, a changed value indicates replenishment.
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
    /// `fd`, socket message `flags`, and `op_id` are retained for rearming. Identical
    /// duplicate records are idempotent. Keep the descriptor
    /// open until rearmed or removed with [`Self::forget_depleted_recv`].
    ///
    /// # Errors
    /// Returns an error for an inactive group, negative descriptor, conflicting
    /// duplicate parameters, or exhausted preallocated recovery capacity (`ENOSPC`).
    ///
    /// # Panics
    /// Does not panic.
    pub fn mark_depleted_recv(&self, fd: RawFd, flags: i32, op_id: OpId) -> Result<()> {
        if !self.registered {
            return Err(invalid("buffer ring is not registered"));
        }
        self.depleted.mark(fd, flags, op_id, self.returned.get())
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
        submitter: impl FnMut(RawFd, i32, OpId, BufGroupId) -> Result<()>,
    ) -> Result<usize> {
        if !self.registered {
            return Err(invalid("buffer ring is not registered"));
        }
        self.depleted.rearm(
            self.returned.get(),
            self.group,
            || {
                // SAFETY: Construction retains the live, thread-confined ring
                // and its registered buffer mapping. This query only reads its
                // producer tail and kernel group head on the owning thread.
                let count = unsafe {
                    liburing_sys::io_uring_buf_ring_available(
                        self.ring.as_ptr(),
                        self.buffer_ring.as_ptr(),
                        self.group.0,
                    )
                };
                if count < 0 {
                    Err(kernel_error(count))
                } else {
                    Ok(count as u64)
                }
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
    pub fn forget_depleted_recv(&self, op_id: OpId) -> Result<bool> {
        self.depleted.forget(op_id)
    }

    /// Extracts the selected buffer ID, when the CQE carries a buffer selection.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub const fn buffer_id_from_flags(flags: u32) -> Option<BufferId> {
        if flags & liburing_sys::IORING_CQE_F_BUFFER == 0 {
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
    pub unsafe fn lease_from_cqe(&self, flags: u32, result: i32) -> Result<PbufLease<'_>> {
        if !self.registered {
            return Err(invalid("buffer ring is not registered"));
        }
        if result < 0 && Self::buffer_id_from_flags(flags).is_none() {
            return Err(kernel_error(result));
        }
        if flags & liburing_sys::IORING_CQE_F_BUF_MORE != 0 {
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
        let lease = PbufLease {
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

    /// Unregisters the group and releases its kernel ring mapping.
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
        let result = unsafe {
            liburing_sys::uring_shim_free_buf_ring(
                self.ring.as_ptr(),
                self.buffer_ring.as_ptr(),
                u32::from(self.entries),
                i32::from(self.group.0),
            )
        };
        if result < 0 {
            return Err(kernel_error(result));
        }
        self.registered = false;
        Ok(())
    }

    fn publish(&self, id: u16, offset: i32) {
        let buffer = &self.buffers[usize::from(id)];
        // SAFETY: UnsafeCell permits kernel writes while the owner is borrowed.
        // The stable allocation remains alive through unregistration. This slot
        // is unpublished at setup or exclusively owned after CQE/lease handoff;
        // offset is within the ring's available descriptor capacity.
        unsafe {
            liburing_sys::uring_shim_buf_ring_add(
                self.buffer_ring.as_ptr(),
                buffer.bytes.as_ptr().cast::<u8>().cast_mut().cast(),
                self.buffer_len,
                id,
                i32::from(self.entries - 1),
                offset,
            );
        }
    }

    fn return_buffer(&self, id: BufferId) {
        self.publish(id.0, 0);
        // SAFETY: CQE handoff or a returning lease grants exclusive buffer ownership.
        // publish initialized the descriptor at the current producer tail.
        unsafe {
            liburing_sys::uring_shim_buf_ring_advance(self.buffer_ring.as_ptr(), 1);
        }
        self.buffers[usize::from(id.0)].leased.set(false);
        self.returned.set(self.returned.get().wrapping_add(1));
    }
}

impl Drop for ProvidedBufRing {
    fn drop(&mut self) {
        // SAFETY: The constructor's contract requires all operations to finish
        // before drop. The last owner cannot have any live borrowed lease.
        let unregistered = unsafe { self.unregister() };
        if unregistered.is_ok() && !self.buffers.iter().any(|buffer| buffer.leased.get()) {
            // SAFETY: Unregistration succeeded, so descriptors cannot be selected
            // again; the caller drained pending I/O, and no forgotten lease holds
            // a selected buffer. This is the sole destruction of the allocation.
            unsafe { ManuallyDrop::drop(&mut self.buffers) };
        }
        // Failed unregistration retains storage rather than freeing addresses
        // that the kernel may still hold. Explicit unregister reports the error.
    }
}

/// An exclusive receive payload view that returns its buffer on drop.
///
/// Keeps its owner alive and republishes full capacity, including during unwinding.
pub struct PbufLease<'a> {
    owner: &'a ProvidedBufRing,
    id: BufferId,
    len: usize,
}

impl PbufLease<'_> {
    /// Returns the kernel-selected buffer ID.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub const fn buffer_id(&self) -> BufferId {
        self.id
    }

    /// Returns the buffer to the kernel immediately.
    ///
    /// # Panics
    /// Does not panic.
    pub fn release(self) {
        drop(self);
    }
}

impl Deref for PbufLease<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let buffer = &self.owner.buffers[usize::from(self.id.0)];
        // SAFETY: CQE handoff proves the kernel relinquished this buffer; the
        // leased flag rejects duplicate leases, the owner keeps storage alive,
        // and the validated CQE result bounds the initialized payload.
        unsafe { std::slice::from_raw_parts(buffer.bytes.as_ptr().cast::<u8>(), self.len) }
    }
}

impl DerefMut for PbufLease<'_> {
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

impl Drop for PbufLease<'_> {
    fn drop(&mut self) {
        self.owner.return_buffer(self.id);
    }
}

fn invalid(message: &'static str) -> UringError {
    UringError::InvalidConfig(message)
}

fn kernel_error(result: i32) -> UringError {
    UringError::Syscall {
        op: "provided buffer ring",
        errno: if result < 0 {
            result.saturating_neg()
        } else {
            libc::EIO
        },
    }
}

#[cfg(test)]
mod unit {
    use super::{DepletedRecvs, invalid};
    use crate::{
        error::UringError,
        id::{BufGroupId, OpId},
    };
    fn unavailable() -> crate::error::Result<u64> {
        Ok(0)
    }
    fn reject(_: i32, _: i32, _: OpId, _: BufGroupId) -> crate::error::Result<()> {
        panic!("no receive may be staged");
    }
    #[test]
    fn scenario_buffers_returned_before_depletion_and_query_failure() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(2);
        let group = BufGroupId(2);
        let id = OpId::from_raw(3);
        pending.mark(10, 0, id, 4)?;
        pending.mark(11, 0, OpId::from_raw(4), 4)?;
        let status_failure = UringError::syscalls("buf_ring_head", libc::EIO);
        assert_eq!(
            pending.rearm(4, group, || Err(status_failure), reject),
            Err(status_failure)
        );
        assert_eq!(pending.rearm(4, group, unavailable, reject), Ok(0));
        let stage = |fd, _, op, _| {
            assert_eq!((fd, op), (10, id));
            Ok(())
        };
        assert_eq!(pending.rearm(4, group, || Ok(1), stage), Ok(1));
        assert_eq!(pending.rearm(4, group, || Ok(1), reject), Ok(0));
        Ok(())
    }
    #[test]
    fn scenario_mixed_epoch_query_retry_reserves_once() -> crate::error::Result<()> {
        for (reverse, inventory) in [(false, 1), (false, 2), (true, 1), (true, 2)] {
            let pending = DepletedRecvs::new(2);
            let (first, second, group) = (OpId(1), OpId(2), BufGroupId(3));
            if reverse {
                pending.mark(11, 0, second, 1)?;
            }
            pending.mark(10, 0, first, 1)?;
            if reverse {
                assert!(pending.forget(second)?);
            }
            pending.mark(11, 0, second, 2)?;
            let error = invalid("inventory query failed");
            assert_eq!(pending.rearm(2, group, || Err(error), reject), Err(error));
            assert_eq!(pending.credits.get(), 1);
            let mut seen = Vec::new();
            let submit = |_, _, op, _| {
                if seen.len() == 1 {
                    return Err(error);
                }
                seen.push(op);
                Ok(())
            };
            let result = pending.rearm(2, group, || Ok(inventory), submit);
            assert_eq!(result, if inventory == 1 { Ok(1) } else { Err(error) });
            assert_eq!(pending.credits.get(), inventory - 1);
            let epoch = if inventory == 1 { 3 } else { 2 };
            let submit = |_, _, op, _| {
                seen.push(op);
                Ok(())
            };
            assert_eq!(pending.rearm(epoch, group, || Ok(1), submit), Ok(1));
            assert_eq!(
                seen,
                if reverse {
                    [second, first]
                } else {
                    [first, second]
                }
            );
            pending.mark(12, 0, OpId(4), epoch)?;
            assert_eq!(pending.rearm(epoch, group, || Ok(2), reject), Ok(0));
        }
        Ok(())
    }
    #[test]
    fn scenario_multishot_consumption_invalidates_leftover_credit() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(2);
        let (id, group) = (OpId(1), BufGroupId(3));
        pending.mark(10, 0, id, 0)?;
        assert_eq!(
            pending.rearm(0, group, || Ok(2), |_, _, _, _| Ok(())),
            Ok(1)
        );
        assert_eq!(pending.credits.get(), 1);
        pending.mark(10, 0, id, 0)?;
        assert_eq!(pending.rearm(0, group, unavailable, reject), Ok(0));
        assert_eq!(pending.credits.get(), 0);
        assert_eq!(
            pending.rearm(2, group, || Ok(2), |_, _, _, _| Ok(())),
            Ok(1)
        );
        Ok(())
    }
    #[test]
    fn lifecycle_scenario_depleted_receive_retry() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(1);
        let op_id = OpId::from_raw(7);
        let group = BufGroupId(9);
        pending.mark(12, 3, op_id, 10)?;
        pending.mark(12, 3, op_id, 11)?;
        assert!(pending.mark(13, 3, op_id, 10).is_err());
        assert!(pending.mark(13, 0, OpId::from_raw(8), 10).is_err());
        assert_eq!(pending.rearm(10, group, unavailable, reject), Ok(0));
        assert!(
            pending
                .rearm(11, group, || Ok(1), |_, _, _, _| Err(invalid("SQ full")))
                .is_err()
        );
        let mut calls = 0;
        let submit = |fd, flags, id, actual_group| {
            calls += 1;
            assert_eq!((fd, flags, id, actual_group), (12, 3, op_id, group));
            Ok(())
        };
        assert_eq!(pending.rearm(11, group, || Ok(1), submit), Ok(1));
        assert_eq!(calls, 1);
        assert_eq!(pending.rearm(12, group, unavailable, reject), Ok(0));
        assert_eq!(pending.forget(op_id), Ok(false));
        Ok(())
    }
    #[test]
    fn scenario_callback_depletion_waits_for_new_return() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(2);
        let first = OpId::from_raw(1);
        let second = OpId::from_raw(2);
        let group = BufGroupId(3);
        pending.mark(10, 0, first, 0)?;
        assert_eq!(
            pending.rearm(
                1,
                group,
                || Ok(1),
                |_, _, id, _| {
                    assert_eq!(id, first);
                    pending.mark(11, 0, second, 2)?;
                    Ok(())
                }
            ),
            Ok(1)
        );
        assert_eq!(pending.rearm(2, group, unavailable, reject), Ok(0));
        assert_eq!(
            pending.rearm(
                3,
                group,
                || Ok(1),
                |fd, _, id, _| {
                    assert_eq!((fd, id), (11, second));
                    Ok(())
                }
            ),
            Ok(1)
        );
        Ok(())
    }
    #[test]
    fn lifecycle_scenario_reentrant_and_panicking_recovery() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(2);
        let first = OpId::from_raw(1);
        let second = OpId::from_raw(2);
        let group = BufGroupId(4);
        pending.mark(10, 0, first, 0)?;
        pending.mark(11, 0, second, 0)?;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pending.rearm(
                1,
                group,
                || Ok(1),
                |_, _, id, _| {
                    assert_eq!(
                        pending.rearm(1, group, unavailable, |_, _, _, _| Ok(())),
                        Err(UringError::ReentrantDispatch)
                    );
                    assert_eq!(pending.forget(id), Err(UringError::ReentrantDispatch));
                    pending.mark(10, 0, id, 1)?;
                    panic!("callback failed before staging");
                },
            )
        }));
        assert!(panic.is_err());
        assert_eq!(pending.forget(second), Ok(true));
        assert_eq!(pending.forget(second), Ok(false));
        assert_eq!(
            pending.rearm(
                1,
                group,
                || Ok(1),
                |fd, _, id, _| {
                    assert_eq!((fd, id), (10, first));
                    Ok(())
                }
            ),
            Ok(1)
        );
        Ok(())
    }
}
