//! Persistent monotonic SQ state with explicit publication and bounded reservations.
use core::{
    marker::PhantomData,
    sync::atomic::{Ordering, fence},
};

use uarch::prelude::*;

use super::{
    geometry::{Sqe128, SqeGeometry, SqeMixed},
    load32, store32,
};
use crate::{
    Result, UringError,
    backend::sys::{params::*, sqe::*},
};

bitword! {
    /// Owner-local lifecycle flags; publication updates the whole scalar word.
    pub(crate) struct SqMeta(u64) {
        [0] pub(crate) SQPOLL,
        [1] pub(crate) PUBLISHED,
        [2] pub(crate) DRAINED,
    }
}

pub(crate) struct SqState {
    pub head: *mut u32,
    pub tail: *mut u32,
    pub flags: *mut u32,
    pub entries: u32,
    pub mask: u32,
    pub sqes: *mut u8,
    pub cached_head: u32,
    pub local_tail: u32,
    pub published_tail: u32,
    pub meta: SqMeta,
}
/// Exclusive access to persistent owner-local cursors; dropping this view never publishes.
pub struct SqRing<'a, S: SqeGeometry> {
    pub(crate) state: &'a mut SqState,
    pub(crate) marker: PhantomData<S>,
}
impl<S: SqeGeometry> SqRing<'_, S> {
    #[hot_inline]
    fn reserve(&mut self, units: u32) -> Result<()> {
        let state = &mut self.state;
        if state.local_tail.wrapping_sub(state.cached_head) > state.entries - units {
            state.cached_head = load32(state.head, Ordering::Acquire);
            if state.local_tail.wrapping_sub(state.cached_head) > state.entries - units {
                return Err(UringError::SqRingFull);
            }
        }
        Ok(())
    }
    /// Copies a narrow SQE into unpublished storage; no allocation occurs.
    /// # Errors
    /// Returns SqRingFull or InvalidPreparedSqe for a wide opcode passed through this interface.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// Retain every SQE-referenced operand through its final target completion, including
    /// SQPOLL consumption and cancellation. Satisfy opcode-specific kernel pointer contracts.
    #[hot_inline]
    pub unsafe fn push(&mut self, entry: &RawSqe) -> Result<()> {
        if matches!(entry.opcode, IORING_OP_NOP128 | IORING_OP_URING_CMD128) {
            return Err(UringError::InvalidPreparedSqe(
                "wide opcode requires reserve_wide",
            ));
        }
        self.reserve(1)?;
        let index = (self.state.local_tail & self.state.mask) as usize;
        // SAFETY: Reservation excludes kernel-owned slots; index lies within the validated SQE
        // mapping. Fixed SQE128 initializes the entire slot before copying its base record.
        unsafe {
            let target = self.state.sqes.add(index * S::STRIDE);
            if S::STRIDE == 128 {
                target.write_bytes(0, 128);
            }
            target.cast::<RawSqe>().write(*entry);
        }
        self.state.local_tail = self.state.local_tail.wrapping_add(1);
        Ok(())
    }
    #[hot_inline]
    unsafe fn copy_wide(&mut self, entry: &RawSqe128) -> Result<()> {
        if S::MIXED && !matches!(entry.base.opcode, IORING_OP_NOP128 | IORING_OP_URING_CMD128) {
            return Err(UringError::InvalidPreparedSqe(
                "mixed wide SQE requires a 128-byte opcode",
            ));
        }
        let pad =
            u32::from(S::MIXED && (self.state.local_tail & self.state.mask) == self.state.mask);
        let width = if S::MIXED { 2 } else { 1 };
        self.reserve(width + pad)?;
        // SAFETY: The reservation covers the complete pad and wide record transaction. A pad
        // moves the wide entry to slot zero; otherwise two physical units are contiguous.
        unsafe {
            if pad != 0 {
                self.state
                    .sqes
                    .add(self.state.mask as usize * S::STRIDE)
                    .cast::<RawSqe>()
                    .write(RawSqe {
                        flags: IOSQE_CQE_SKIP_SUCCESS,
                        ..RawSqe::default()
                    });
                self.state.local_tail = self.state.local_tail.wrapping_add(1);
            }
            self.state
                .sqes
                .add((self.state.local_tail & self.state.mask) as usize * S::STRIDE)
                .cast::<RawSqe128>()
                .write(*entry);
        }
        self.state.local_tail = self.state.local_tail.wrapping_add(width);
        Ok(())
    }
    /// Acquires the kernel SQ wakeup/taskwork/overflow flag snapshot without publication.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn flags(&self) -> u32 {
        load32(self.state.flags, Ordering::Acquire)
    }
    /// Returns physical units still visible to the kernel, excluding unpublished entries.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn unconsumed(&self) -> u32 {
        self.state
            .published_tail
            .wrapping_sub(load32(self.state.head, Ordering::Acquire))
    }
    /// Publishes changed tail once, then performs the SQPOLL sleep handshake when work remains.
    /// Returns newly published physical units and whether a SQ_WAKEUP enter is required.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn publish_and_need_wakeup(&mut self) -> (u32, bool) {
        let published = self
            .state
            .local_tail
            .wrapping_sub(self.state.published_tail);
        if published != 0 {
            store32(self.state.tail, self.state.local_tail, Ordering::Release);
            self.state.published_tail = self.state.local_tail;
            self.state.meta = self.state.meta.patch(patch!(SqMeta {
                PUBLISHED: true,
                DRAINED: false
            }));
        }
        let wake =
            if self.state.meta.test(SqMeta::SQPOLL) && (published != 0 || self.unconsumed() != 0) {
                fence(Ordering::SeqCst);
                load32(self.state.flags, Ordering::Acquire) & IORING_SQ_NEED_WAKEUP != 0
            } else {
                false
            };
        (published, wake)
    }
}
macro_rules! wide_interface {
    ($policy:ty) => {
        impl SqRing<'_, $policy> {
            /// Reserves and copies a complete wide SQE, including any internal wrap pad.
            /// # Errors
            /// Returns SqRingFull without modifying storage/cursors if the whole transaction cannot
            /// fit. Returns InvalidPreparedSqe for a narrow opcode on a mixed ring.
            /// # Panics
            /// Does not panic.
            /// # Safety
            /// Retain all referenced operands through final completion and obey the opcode's
            /// pointer ABI.
            #[hot_inline]
            pub unsafe fn reserve_wide(&mut self, entry: &RawSqe128) -> Result<()> {
                // SAFETY: The caller preserves the referenced operands through all kernel access.
                unsafe { self.copy_wide(entry) }
            }
        }
    };
}
wide_interface!(Sqe128);
wide_interface!(SqeMixed);
