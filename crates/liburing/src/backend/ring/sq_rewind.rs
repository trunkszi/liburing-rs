//! Linear prefix submission: shared SQ head and tail remain zero permanently.
use core::marker::PhantomData;

use uarch::prelude::*;

use super::{
    geometry::SqeGeometry,
    sq::{SqMeta, SqState},
};
use crate::{
    Result, UringError,
    backend::sys::{self, sqe::*},
};

/// An exclusive rewind prefix; only submit's accepted count authorizes suffix compaction.
pub struct RewindSq<'a, S: SqeGeometry> {
    pub(crate) state: &'a mut SqState,
    pub(crate) fd: i32,
    pub(crate) namespace: u32,
    pub(crate) marker: PhantomData<S>,
}
impl<S: SqeGeometry> RewindSq<'_, S> {
    /// Appends an unpublished narrow instruction to the prefix.
    /// # Errors
    /// Returns SqRingFull or InvalidPreparedSqe for a wide opcode.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// All kernel operands must remain valid through final target completion, including
    /// cancellation.
    #[hot_inline]
    pub unsafe fn push(&mut self, entry: &RawSqe) -> Result<()> {
        if matches!(entry.opcode, IORING_OP_NOP128 | IORING_OP_URING_CMD128) {
            return Err(UringError::InvalidPreparedSqe(
                "wide opcode requires reserve_wide",
            ));
        }
        if self.state.local_tail >= self.state.entries {
            return Err(UringError::SqRingFull);
        }
        // SAFETY: The exclusive prefix owns this unpublished contiguous slot. No SQ thread exists
        // for rewind rings, and prior enter returned before this view was borrowed again.
        unsafe {
            let pointer = self
                .state
                .sqes
                .add(self.state.local_tail as usize * S::STRIDE);
            if S::STRIDE == 128 {
                pointer.write_bytes(0, 128);
            }
            pointer.cast::<RawSqe>().write(*entry);
        }
        self.state.local_tail += 1;
        Ok(())
    }
    /// Appends a contiguous extended instruction to the prefix.
    /// # Errors
    /// Returns topology/opcode errors or SqRingFull without partial reservation.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// Retain every referenced operand through final target completion and notification.
    #[hot_inline]
    pub unsafe fn reserve_wide(&mut self, entry: &RawSqe128) -> Result<()> {
        if S::STRIDE != 128 && !S::MIXED {
            return Err(UringError::InvalidTopology(
                "wide SQE on narrow rewind geometry",
            ));
        }
        if S::MIXED && !matches!(entry.base.opcode, IORING_OP_NOP128 | IORING_OP_URING_CMD128) {
            return Err(UringError::InvalidPreparedSqe(
                "mixed wide SQE requires a 128-byte opcode",
            ));
        }
        let units = if S::MIXED { 2 } else { 1 };
        if self.state.local_tail > self.state.entries - units {
            return Err(UringError::SqRingFull);
        }
        // SAFETY: The exclusive prefix reserves all bytes, including the second physical unit.
        unsafe {
            self.state
                .sqes
                .add(self.state.local_tail as usize * S::STRIDE)
                .cast::<RawSqe128>()
                .write(*entry);
        }
        self.state.local_tail += units;
        Ok(())
    }
    /// Returns unaccepted physical prefix units.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn pending(&self) -> u32 {
        self.state.local_tail
    }
    /// Submits precisely the initialized prefix once and retains/compacts an unaccepted suffix.
    /// Transient errors preserve the entire prefix; no hidden retry or shared-tail store occurs.
    /// # Errors
    /// Returns the enter errno or a corrupt accepted-count error.
    /// # Panics
    /// Does not panic.
    pub fn submit(&mut self) -> Result<u32> {
        let pending = self.state.local_tail;
        if pending == 0 {
            return Ok(0);
        }
        self.state.meta = self.state.meta.patch(patch!(SqMeta {
            PUBLISHED: true,
            DRAINED: false
        }));
        // SAFETY: Prefix builders initialized every submitted unit and retain operands under their
        // unsafe contracts. The live task-local/VFS handle is borrowed from the ring owner.
        let result = unsafe {
            sys::sys_io_uring_enter(self.fd, pending, 0, self.namespace, core::ptr::null(), 8)
        };
        if result < 0 {
            return Err(UringError::cold_submit(result));
        }
        let accepted = result as u32;
        if accepted > pending {
            return Err(UringError::InvalidTopology(
                "rewind accepted count exceeds prefix",
            ));
        }
        let remaining = pending - accepted;
        if accepted != 0 && remaining != 0 {
            // SAFETY: A synchronous enter consumed this prefix with SUBMIT_STABLE support. The
            // source and destination are within one exclusive mapping and may overlap, so copy
            // rather than copy_nonoverlapping compacts only the unaccepted physical suffix.
            unsafe {
                core::ptr::copy(
                    self.state.sqes.add(accepted as usize * S::STRIDE),
                    self.state.sqes,
                    remaining as usize * S::STRIDE,
                );
            }
        }
        self.state.local_tail = remaining;
        Ok(accepted)
    }
}
