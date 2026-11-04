//! Sealed queue geometry: the standard instantiation has no mixed-entry decoding.
use uarch::prelude::*;

use crate::backend::sys::{
    cqe::{RawCqe, RawCqe32},
    params::*,
};
mod sealed {
    pub trait Sealed {}
}

/// Submission storage policy. Implementations are fixed by the audited UAPI.
pub trait SqeGeometry: sealed::Sealed {
    const FLAGS: u32;
    const STRIDE: usize;
    const MIXED: bool;
}
/// Completion storage policy with a size-specific copied result.
pub trait CqeGeometry: sealed::Sealed {
    type Entry;
    const FLAGS: u32;
    const STRIDE: usize;
    const MIXED: bool;
    /// Copies one initialized, acquired completion.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// `base` must name the complete policy-specific record, retained until the copy ends.
    unsafe fn copy(base: *const RawCqe, wide: bool) -> Self::Entry;
}
macro_rules! sq_policy {
    ($name:ident, $flags:expr, $stride:expr, $mixed:expr) => {
        /// Sealed submission geometry.
        pub struct $name;
        impl sealed::Sealed for $name {}
        impl SqeGeometry for $name {
            const FLAGS: u32 = $flags;
            const STRIDE: usize = $stride;
            const MIXED: bool = $mixed;
        }
    };
}
sq_policy!(Sqe64, 0, 64, false);
sq_policy!(Sqe128, IORING_SETUP_SQE128, 128, false);
sq_policy!(SqeMixed, IORING_SETUP_SQE_MIXED, 64, true);
/// Standard 16-byte completions.
pub struct Cqe16;
/// Fixed 32-byte completions.
pub struct Cqe32;
/// Mixed 16/32-byte completions; small results have zero extension words.
pub struct CqeMixed;
impl sealed::Sealed for Cqe16 {}
impl sealed::Sealed for Cqe32 {}
impl sealed::Sealed for CqeMixed {}
impl CqeGeometry for Cqe16 {
    type Entry = RawCqe;
    const FLAGS: u32 = 0;
    const STRIDE: usize = 16;
    const MIXED: bool = false;
    #[hot_inline]
    unsafe fn copy(base: *const RawCqe, _: bool) -> RawCqe {
        // SAFETY: The caller retains one acquired initialized 16-byte record.
        unsafe { base.read() }
    }
}
impl CqeGeometry for Cqe32 {
    type Entry = RawCqe32;
    const FLAGS: u32 = IORING_SETUP_CQE32;
    const STRIDE: usize = 32;
    const MIXED: bool = false;
    #[hot_inline]
    unsafe fn copy(base: *const RawCqe, _: bool) -> RawCqe32 {
        // SAFETY: Fixed CQE32 always has an initialized 32-byte record at this aligned address.
        unsafe { base.cast::<RawCqe32>().read() }
    }
}
impl CqeGeometry for CqeMixed {
    type Entry = RawCqe32;
    const FLAGS: u32 = IORING_SETUP_CQE_MIXED;
    const STRIDE: usize = 16;
    const MIXED: bool = true;
    #[hot_inline]
    unsafe fn copy(base: *const RawCqe, wide: bool) -> RawCqe32 {
        if wide {
            // SAFETY: The caller proved two acquired contiguous 16-byte units for this entry.
            unsafe { base.cast::<RawCqe32>().read() }
        } else {
            // SAFETY: The caller retains the acquired initialized base record; extensions are
            // absent.
            let base = unsafe { base.read() };
            RawCqe32 {
                base,
                big_cqe: [0; 2],
            }
        }
    }
}
/// A queue geometry pair; cursor protocol selection remains separate.
pub trait RingGeometry {
    type Sq: SqeGeometry;
    type Cq: CqeGeometry;
}
impl<S: SqeGeometry, C: CqeGeometry> RingGeometry for (S, C) {
    type Sq = S;
    type Cq = C;
}
/// Default 64-byte SQE and 16-byte CQE geometry.
pub type Standard = (Sqe64, Cqe16);
