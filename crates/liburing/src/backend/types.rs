//! Borrowed extended syscall arguments and native descriptor selectors.
use core::marker::PhantomData;

use super::sys::params::{IoUringGeteventsArg, KernelTimespec};
/// Ordinary operating-system file descriptor.
#[derive(Clone, Copy)]
pub struct Fd(pub i32);
/// Direct file-table index.
#[derive(Clone, Copy)]
pub struct Fixed(pub u32);
/// An explicit descriptor namespace used by SQE builders.
pub trait Target {
    /// Returns the descriptor/index bits consumed by the SQE.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic for native Fd and Fixed selectors.
    fn raw(self) -> i32;
    /// Reports whether this selects the direct-file namespace.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic for native Fd and Fixed selectors.
    fn fixed(&self) -> bool;
}
impl Target for Fd {
    fn raw(self) -> i32 {
        self.0
    }
    fn fixed(&self) -> bool {
        false
    }
}
impl Target for Fixed {
    fn raw(self) -> i32 {
        self.0 as i32
    }
    fn fixed(&self) -> bool {
        true
    }
}
/// Kernel output direct-file slot encoding.
#[derive(Clone, Copy)]
pub struct DestinationSlot(pub(crate) u32);
impl DestinationSlot {
    /// Requests kernel allocation from the registered range.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn auto_target() -> Self {
        Self(u32::MAX)
    }
}
/// Relative kernel time operand with stable C layout.
pub type Timespec = KernelTimespec;
impl KernelTimespec {
    /// Creates a zero relative timeout.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn new() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }
    /// Sets the seconds field.
    /// # Errors
    /// Does not return errors; the kernel validates its signed range.
    /// # Panics
    /// Does not panic.
    pub const fn sec(mut self, seconds: u64) -> Self {
        self.tv_sec = seconds as i64;
        self
    }
    /// Sets the nanoseconds field.
    /// # Errors
    /// Does not return errors; the kernel validates the range.
    /// # Panics
    /// Does not panic.
    pub const fn nsec(mut self, nanos: u32) -> Self {
        self.tv_nsec = nanos as i64;
        self
    }
}
impl From<std::time::Duration> for KernelTimespec {
    fn from(d: std::time::Duration) -> Self {
        Self {
            tv_sec: d.as_secs() as i64,
            tv_nsec: d.subsec_nanos() as i64,
        }
    }
}
/// Extended enter arguments retaining every borrowed operand until syscall return.
#[derive(Default)]
pub struct SubmitArgs<'mask, 'time> {
    pub(crate) raw: IoUringGeteventsArg,
    marker: PhantomData<(&'mask libc::sigset_t, &'time Timespec)>,
}
impl<'mask, 'time> SubmitArgs<'mask, 'time> {
    /// Creates empty extended arguments.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn new() -> Self {
        Self::default()
    }
    /// Borrows a timeout through the synchronous kernel call.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn timespec<'next>(self, ts: &'next Timespec) -> SubmitArgs<'mask, 'next> {
        SubmitArgs {
            raw: IoUringGeteventsArg {
                ts: ts as *const _ as u64,
                ..self.raw
            },
            marker: PhantomData,
        }
    }
    /// Sets the optional minimum batching delay in microseconds.
    /// # Errors
    /// Does not return errors; the caller must check MIN_TIMEOUT support.
    /// # Panics
    /// Does not panic.
    pub fn min_wait_usec(mut self, usec: u32) -> Self {
        self.raw.min_wait_usec = usec;
        self
    }
}
