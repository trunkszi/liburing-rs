//! Thread-confined mapped ring ownership with persistent cursors and exclusive borrowed views.
//!
//! Owners cannot move to another worker or be shared between workers:
//! ```compile_fail
//! use liburing::backend::ring::NativeRing;
//! fn send<T: Send>() {}
//! send::<NativeRing>();
//! ```
//! ```compile_fail
//! use liburing::backend::ring::NativeRing;
//! fn sync<T: Sync>() {}
//! sync::<NativeRing>();
//! ```
//! Queue views cannot outlive their mapping owner:
//! ```compile_fail
//! use liburing::backend::ring::{NativeRing, cq::CqRing, geometry::{Sqe64, Cqe16}};
//! fn escape() -> CqRing<'static, Cqe16> {
//!     let mut owner = NativeRing::<Sqe64, Cqe16>::with_params(4, Default::default()).unwrap();
//!     owner.completion()
//! }
//! ```
use core::{
    marker::PhantomData,
    sync::atomic::{AtomicU32, Ordering},
};
use std::rc::Rc;

use uarch::prelude::*;

use crate::{
    Result, UringError,
    backend::{
        mapping::{RingHandle, RingMemory, RingStorage},
        sys::{self, params::*},
    },
};
pub mod cq;
pub mod geometry;
pub mod sq;
pub mod sq_rewind;
use cq::{CqRing, CqState};
use geometry::{Cqe16, CqeGeometry, Sqe64, SqeGeometry};
use sq::{SqMeta, SqRing, SqState};
use sq_rewind::RewindSq;

#[hot_inline]
pub(crate) fn load32(pointer: *mut u32, ordering: Ordering) -> u32 {
    // SAFETY: Only validated aligned per-word addresses from this live ring reach this helper.
    // The kernel uses compatible aligned accesses and no non-atomic Rust references alias the word.
    unsafe { AtomicU32::from_ptr(pointer).load(ordering) }
}
#[hot_inline]
pub(crate) fn store32(pointer: *mut u32, value: u32, ordering: Ordering) {
    // SAFETY: The validated shared cursor is naturally aligned and exclusively user-written by
    // this owner; the kernel's compatible accesses observe the explicitly requested ordering.
    unsafe {
        AtomicU32::from_ptr(pointer).store(value, ordering);
    }
}
/// Native ring owner; queue views cannot escape or be swapped independently of mapped ownership.
/// Raw preparation retains caller DMA ownership. This layer does not cancel/drain application I/O.
pub struct NativeRing<S: SqeGeometry = Sqe64, C: CqeGeometry = Cqe16> {
    pub(crate) storage: RingStorage,
    pub(crate) params: IoUringParams,
    pub(crate) sq: SqState,
    pub(crate) cq: CqState,
    pub(crate) marker: PhantomData<(S, C, Rc<()>)>,
}
impl<S: SqeGeometry, C: CqeGeometry> NativeRing<S, C> {
    /// Creates an exact flag/geometry ring; feature negotiation is a separate setup function.
    /// # Errors
    /// Returns baseline, topology, allocation, mapping or kernel setup failures.
    /// # Panics
    /// Does not panic.
    pub fn with_params(entries: u32, params: IoUringParams) -> Result<Self> {
        crate::backend::setup::setup(entries, params)
    }
    /// Returns an exclusive monotonic producer view over persistent owner-local cursor state.
    /// # Errors
    /// Rejects rewind rings, which have a different submission protocol.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn submission(&mut self) -> Result<SqRing<'_, S>> {
        if self.params.flags & IORING_SETUP_SQ_REWIND != 0 {
            return Err(UringError::InvalidTopology(
                "rewind ring has no monotonic producer",
            ));
        }
        Ok(SqRing {
            state: &mut self.sq,
            marker: PhantomData,
        })
    }
    /// Returns an exclusive rewind prefix view, retaining the ring handle borrow.
    /// # Errors
    /// Rejects monotonic or closed rings.
    /// # Panics
    /// Does not panic.
    pub fn rewind(&mut self) -> Result<RewindSq<'_, S>> {
        if self.params.flags & IORING_SETUP_SQ_REWIND == 0 {
            return Err(UringError::InvalidTopology(
                "monotonic ring has no rewind prefix",
            ));
        }
        let (fd, namespace) = self
            .handle()
            .ok_or(UringError::InvalidTopology("closed ring"))?
            .enter_target();
        Ok(RewindSq {
            state: &mut self.sq,
            fd,
            namespace,
            marker: PhantomData,
        })
    }
    /// Returns an exclusive consumer view. refresh_tail acquires a new snapshot explicitly.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn completion(&mut self) -> CqRing<'_, C> {
        CqRing {
            state: &mut self.cq,
            marker: PhantomData,
        }
    }
    /// Returns the kernel's successful setup parameters without granting mutable access.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn params(&self) -> &IoUringParams {
        &self.params
    }
    /// Borrows the handle namespace; no ownership or mutable index state is transferred.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn handle(&self) -> Option<&RingHandle> {
        self.storage.handle.as_ref()
    }
    /// Adopts an already registered task-local index for this ordinary VFS ring.
    /// Cleanup is transferred only on success and persists across all borrowed queue views.
    /// # Errors
    /// Rejects an existing registration, registered-only ownership, or a closed ring.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// `index` must be a live registration for exactly this ring on this thread. Transfer its
    /// sole unregister obligation to this owner; do not independently unregister or reuse it.
    pub unsafe fn adopt_registered_index(&mut self, index: u32) -> Result<()> {
        match self.storage.handle.as_mut() {
            Some(RingHandle::Vfs {
                registered_index, ..
            }) if registered_index.is_none() => {
                *registered_index = Some(index);
                Ok(())
            }
            _ => Err(UringError::InvalidTopology(
                "ring already registered or closed",
            )),
        }
    }
    /// Reads the shared SQ cursor words; rewind rings leave both permanently zero.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn shared_sq_cursors(&self) -> (u32, u32) {
        (
            load32(self.sq.head, Ordering::Acquire),
            load32(self.sq.tail, Ordering::Acquire),
        )
    }
    /// Enters once with ordinary no-pointer arguments and the owned handle namespace.
    /// # Errors
    /// Rejects nonzero rewind submissions or extended-argument misuse; kernel errors are not
    /// retried. # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn enter(&mut self, to_submit: u32, min_complete: u32, flags: u32) -> Result<u32> {
        if (self.params.flags & IORING_SETUP_SQ_REWIND != 0 && to_submit != 0)
            || flags & (IORING_ENTER_EXT_ARG | IORING_ENTER_EXT_ARG_REG) != 0
        {
            return Err(UringError::InvalidTopology(
                "use the protocol-specific enter interface",
            ));
        }
        // SAFETY: A null signal mask with kernel sigset size 8 has no borrowed argument storage.
        unsafe { self.enter_with_arg(to_submit, min_complete, flags, core::ptr::null(), 8) }
    }
    /// Enters once with an explicit raw signal/extended argument ABI.
    /// # Errors
    /// Rejects nonzero rewind submissions and returns kernel errors without losing
    /// already-published ownership. # Panics
    /// Does not panic.
    /// # Safety
    /// `arg` and `argsz` must match flags-selected ABI; referenced signal masks, timeouts and
    /// registered regions must remain valid for kernel use. All published operand contracts apply.
    pub unsafe fn enter_with_arg(
        &mut self,
        to_submit: u32,
        min_complete: u32,
        flags: u32,
        arg: *const libc::c_void,
        argsz: usize,
    ) -> Result<u32> {
        if self.params.flags & IORING_SETUP_SQ_REWIND != 0 && to_submit != 0 {
            return Err(UringError::InvalidTopology(
                "rewind must submit its exact initialized prefix",
            ));
        }
        let (fd, namespace) = self
            .handle()
            .ok_or(UringError::InvalidTopology("closed ring"))?
            .enter_target();
        // SAFETY: The owner retains the live handle; callers retain all raw argument and SQE
        // operands.
        let result = unsafe {
            sys::sys_io_uring_enter(
                fd,
                to_submit,
                min_complete,
                (flags & !IORING_ENTER_REGISTERED_RING) | namespace,
                arg,
                argsz,
            )
        };
        if result < 0 {
            Err(UringError::cold_submit(result))
        } else {
            Ok(result as u32)
        }
    }
    /// Confirms all published targets and auxiliary notifications have retired before teardown.
    /// A subsequent publication invalidates the confirmation. Unconfirmed NO_MMAP storage leaks on
    /// Drop. # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// Every published request must have its final completion, including multishot termination
    /// and required zero-copy notifications. A cancellation-control completion is insufficient.
    pub unsafe fn confirm_drained(&mut self) {
        self.sq.meta |= SqMeta::DRAINED;
    }
}
impl<S: SqeGeometry, C: CqeGeometry> Drop for NativeRing<S, C> {
    fn drop(&mut self) {
        if matches!(self.storage.memory, Some(RingMemory::UserProvided(_)))
            && self
                .sq
                .meta
                .matches(pattern!(SqMeta { PUBLISHED & !DRAINED }))
        {
            self.storage.retain_memory = true;
        }
    }
}
