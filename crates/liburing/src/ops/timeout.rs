//! Stable timeout operands and safe finite completion waits.

use std::time::Duration;

use liburing_sys as sys;

use crate::{
    error::{Result, UringError},
    proactor::Proactor,
    subsystem::{Completion, SubmissionContext},
};

/// A stable kernel timespec used by a relative timeout SQE.
///
/// Moving this owner preserves its operand address. Its unsafe preparation API
/// requires retaining the owner until the timeout's final CQE or ring shutdown.
pub struct Timeout {
    timespec: Box<sys::__kernel_timespec>,
}

impl Timeout {
    /// Allocate an immutable relative timeout operand.
    ///
    /// # Errors
    /// Returns an invalid-configuration error if seconds exceed the kernel's
    /// signed 64-bit timespec range.
    ///
    /// # Panics
    /// Does not panic except if allocating operand storage fails.
    pub fn new(duration: Duration) -> Result<Self> {
        let seconds = i64::try_from(duration.as_secs())
            .map_err(|_| UringError::InvalidConfig("timeout exceeds kernel timespec range"))?;
        Ok(Self {
            timespec: Box::new(sys::__kernel_timespec {
                tv_sec: seconds,
                tv_nsec: i64::from(duration.subsec_nanos()),
            }),
        })
    }

    /// Prepare a relative timeout that expires independently of CQE counts.
    ///
    /// Expiry produces a CQE with result `-ETIME`. The proactor assigns user data
    /// after preparation through `prepare_sqe_with`.
    ///
    /// # Safety
    /// `sqe` must point to exclusive initialized SQE storage. Retain this owner
    /// until this operation's final CQE or completed ring shutdown, including
    /// while the SQE is staged and after cancellation is requested.
    ///
    /// # Panics
    /// Does not panic.
    pub unsafe fn prepare(&self, sqe: *mut sys::io_uring_sqe) {
        // SAFETY: The caller guarantees SQE exclusivity and operand retention.
        unsafe { sys::uring_shim_prep_timeout(sqe, self.timespec.as_ref(), 0, 0) };
    }
}

/// Submit pending operations and wait for one completion for at most `duration`.
///
/// The wait operand is retained internally until the synchronous kernel call
/// returns. Timeout expiry is reported as an empty batch, rather than a CQE.
///
/// # Errors
/// Returns submission, wait, or completion-handler errors from the proactor.
///
/// # Panics
/// Propagates a panic from the completion callback or registered handler.
pub fn wait_timeout<F>(proactor: &mut Proactor, duration: Duration, on_cqe: F) -> Result<usize>
where
    F: FnMut(Completion, &mut SubmissionContext<'_>) -> Result<()>,
{
    proactor.wait_completions(1, Some(duration), on_cqe)
}
