//! Scoped queue access over persistent native cursor state.
use core::sync::atomic::{Ordering, fence};

use super::{
    RawCqe, RawSqe,
    flags::Flags,
    ring::{
        cq::CqRing,
        geometry::{Cqe16, Sqe64},
        load32,
        sq::SqRing,
    },
    sys::params::*,
};
/// Exclusive standard SQ view. Drop publishes only a changed tail.
pub struct SubmissionQueue<'a>(pub(crate) SqRing<'a, Sqe64>, pub(crate) Option<bool>);
impl SubmissionQueue<'_> {
    /// Returns pending initialized physical entries, including published work.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn len(&self) -> usize {
        self.0
            .state
            .local_tail
            .wrapping_sub(load32(self.0.state.head, Ordering::Acquire)) as usize
    }
    /// Tests whether the SQ is empty.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Returns the mapped SQ capacity.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn capacity(&self) -> usize {
        self.0.state.entries as usize
    }
    /// Copies one initialized entry into exclusive unpublished storage.
    /// # Errors
    /// Returns a full queue or unsupported wide-opcode error.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// Retain all referenced operands until final completion, including notifications.
    pub unsafe fn push(&mut self, entry: &RawSqe) -> crate::Result<()> {
        self.1 = None;
        // SAFETY: The caller retains the SQE operands through final kernel use.
        unsafe { self.0.push(entry) }
    }
    /// Publishes changed entries using the native release/wakeup protocol.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn sync(&mut self) {
        if self.0.state.local_tail != self.0.state.published_tail {
            self.1 = Some(self.0.publish_and_need_wakeup().1);
        }
    }
    /// Tests CQ overflow work in the acquired SQ flag snapshot.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn cq_overflow(&self) -> bool {
        self.0.flags() & IORING_SQ_CQ_OVERFLOW != 0
    }
    /// Tests deferred kernel task work.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn taskrun(&self) -> bool {
        self.0.flags() & IORING_SQ_TASKRUN != 0
    }
    /// Performs the StoreLoad handshake before testing SQ-thread sleep.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn need_wakeup(&self) -> bool {
        if let Some(wake) = self.1 {
            return wake;
        }
        fence(Ordering::SeqCst);
        self.0.flags() & IORING_SQ_NEED_WAKEUP != 0
    }
}
impl Drop for SubmissionQueue<'_> {
    #[uarch::prelude::hot_inline]
    fn drop(&mut self) {
        self.sync();
    }
}
/// Acquired CQ snapshot with batched acknowledgment on explicit sync or drop.
pub struct CompletionQueue<'a>(pub(crate) CqRing<'a, Cqe16>);
impl CompletionQueue<'_> {
    /// Returns the remaining acquired CQE count.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn len(&self) -> usize {
        self.0
            .state
            .cached_tail
            .wrapping_sub(self.0.state.local_head)
            .min(self.0.state.entries) as usize
    }
    /// Reads the kernel completion-overflow counter.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn overflow(&self) -> u32 {
        load32(self.0.state.overflow, Ordering::Acquire)
    }
    /// Tests whether the acquired snapshot is empty.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Peeks at an unacknowledged CQE without copying queue ownership.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn peek_ahead(&self, offset: u32) -> Option<&RawCqe> {
        self.0.peek_ahead(offset)
    }
    /// Acknowledges consumed entries once; repeated calls without progress do not store.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn sync(&mut self) {
        self.0.commit_head();
    }
}
impl Iterator for CompletionQueue<'_> {
    type Item = RawCqe;
    #[uarch::prelude::hot_inline]
    fn next(&mut self) -> Option<RawCqe> {
        self.0.pop()
    }
}
impl Drop for CompletionQueue<'_> {
    #[uarch::prelude::hot_inline]
    fn drop(&mut self) {
        self.sync();
    }
}
impl RawSqe {
    /// Assigns the caller's completion routing value.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub const fn user_data(mut self, value: u64) -> Self {
        self.user_data = value;
        self
    }
    /// Sets the SQE flag word.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub const fn flags(mut self, flags: Flags) -> Self {
        self.flags = flags.bits();
        self
    }
    /// Returns the raw opcode value.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub const fn get_opcode(&self) -> u32 {
        self.opcode as u32
    }
}
impl RawCqe {
    /// Returns the caller's completion routing value.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub const fn user_data(&self) -> u64 {
        self.user_data
    }
    /// Returns the signed kernel result.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub const fn result(&self) -> i32 {
        self.res
    }
    /// Returns the kernel completion flag word.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub const fn flags(&self) -> u32 {
        self.flags
    }
}
