//! Acquired CQ snapshots, non-consuming lookahead, and explicit batched acknowledgment.
use core::{marker::PhantomData, sync::atomic::Ordering};

use uarch::prelude::*;

use super::{geometry::CqeGeometry, load32, store32};
use crate::backend::sys::cqe::*;

pub(crate) struct CqState {
    pub head: *mut u32,
    pub tail: *mut u32,
    pub overflow: *mut u32,
    pub cqes: *mut u8,
    pub entries: u32,
    pub mask: u32,
    pub local_head: u32,
    pub published_head: u32,
    pub cached_tail: u32,
}
/// Exclusive snapshot view. References remain valid until this view acknowledges their storage.
pub struct CqRing<'a, C: CqeGeometry> {
    pub(crate) state: &'a mut CqState,
    pub(crate) marker: PhantomData<C>,
}
impl<C: CqeGeometry> CqRing<'_, C> {
    /// Acquires a bounded snapshot of completions published by the kernel.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn refresh_tail(&mut self) {
        self.state.cached_tail = load32(self.state.tail, Ordering::Acquire);
    }
    #[hot_inline]
    fn pointer(&self, head: u32) -> *const RawCqe {
        // SAFETY: The mask was validated against the mapped capacity, stride is sealed, and
        // all record addresses are aligned and contained in the retained completion mapping.
        unsafe {
            self.state
                .cqes
                .add((head & self.state.mask) as usize * C::STRIDE)
                .cast()
        }
    }
    #[hot_inline]
    fn width(flags: u32) -> u32 {
        if C::MIXED && flags & IORING_CQE_F_32 != 0 {
            2
        } else {
            1
        }
    }
    /// Peeks by logical completion offset, skipping mixed-ring gap records without consuming them.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn peek_ahead(&self, offset: u32) -> Option<&RawCqe> {
        let mut head = self.state.local_head;
        let mut logical = 0;
        let available = self
            .state
            .cached_tail
            .wrapping_sub(head)
            .min(self.state.entries);
        let mut scanned = 0;
        while scanned < available {
            // SAFETY: This record is in the acquired snapshot and has not been acknowledged.
            // The returned reference borrows the view, preventing mutation or head publication.
            let base = unsafe { &*self.pointer(head) };
            if C::MIXED && base.flags & IORING_CQE_F_SKIP != 0 {
                head = head.wrapping_add(1);
                scanned += 1;
                continue;
            }
            let width = Self::width(base.flags);
            if scanned + width > available
                || (width == 2 && (head & self.state.mask) == self.state.mask)
            {
                return None;
            }
            if logical == offset {
                prefetch_read::<L1, _>(self.pointer(head));
                return Some(base);
            }
            head = head.wrapping_add(width);
            scanned += width;
            logical += 1;
        }
        None
    }
    /// Copies and consumes one logical completion, filtering mixed gap records first.
    /// Empty extension words distinguish small mixed entries through their flags, not padding CQEs.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn pop(&mut self) -> Option<C::Entry> {
        let mut remaining = self
            .state
            .cached_tail
            .wrapping_sub(self.state.local_head)
            .min(self.state.entries);
        while remaining != 0 {
            let pointer = self.pointer(self.state.local_head);
            // SAFETY: The acquired snapshot contains this initialized base record; the kernel
            // cannot overwrite it before the owner publishes CQ head.
            let flags = unsafe { (*pointer).flags };
            if C::MIXED && flags & IORING_CQE_F_SKIP != 0 {
                self.state.local_head = self.state.local_head.wrapping_add(1);
                remaining -= 1;
                continue;
            }
            let width = Self::width(flags);
            if remaining < width
                || (width == 2 && (self.state.local_head & self.state.mask) == self.state.mask)
            {
                return None;
            }
            // SAFETY: Width/contiguity validation covers every extension byte. The policy copies
            // only initialized storage while this exclusive view still retains the CQ head.
            let entry = unsafe { C::copy(pointer, width == 2) };
            self.state.local_head = self.state.local_head.wrapping_add(width);
            return Some(entry);
        }
        None
    }
    /// Releases all consumed physical units exactly once, including filtered gaps.
    /// A second call without consumption makes no store.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn commit_head(&mut self) -> u32 {
        let count = self
            .state
            .local_head
            .wrapping_sub(self.state.published_head);
        if count != 0 {
            store32(self.state.head, self.state.local_head, Ordering::Release);
            self.state.published_head = self.state.local_head;
        }
        count
    }
}
