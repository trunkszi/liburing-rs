//! SQE preparation helpers and finite completion waits.
//!
//! Pointer operands must outlive final CQEs, including after cancellation.

pub mod net;
use std::time::Duration;

use io_uring::{opcode, types::Timespec};

use crate::{
    backend::RawSqe,
    error::{Result, UringError},
    proactor::Proactor,
    subsystem::{Completion, SubmissionContext},
};

/// A stable kernel timespec used by a relative timeout SQE.
///
/// Moving this owner preserves its operand address. Its unsafe preparation API
/// requires retaining the owner until the timeout's final CQE or ring shutdown.
pub struct Timeout {
    timespec: Box<Timespec>,
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
            timespec: Box::new(
                Timespec::new()
                    .sec(seconds as u64)
                    .nsec(duration.subsec_nanos()),
            ),
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
    pub unsafe fn prepare(&self, sqe: *mut RawSqe) {
        // SAFETY: The caller guarantees SQE exclusivity and operand retention.
        unsafe {
            let (identity, flags, personality) =
                ((*sqe).user_data, (*sqe).flags, (*sqe).personality);
            *sqe = RawSqe::from_entry(
                opcode::Timeout::new(self.timespec.as_ref())
                    .count(0)
                    .build()
                    .user_data(identity),
            );
            (*sqe).flags |= flags;
            (*sqe).personality = personality;
        };
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
pub fn wait_timeout<F>(proactor: &mut Proactor, duration: Duration, mut on_cqe: F) -> Result<usize>
where
    F: FnMut(Completion, &mut SubmissionContext<'_>) -> Result<()>,
{
    proactor.wait_completions(1, Some(duration), &mut on_cqe)
}

/// Prepare a no-op without changing the caller-assigned completion identity.
///
/// # Safety
/// `sqe` must point to live, initialized, exclusively writable SQE storage.
///
/// # Panics
/// Does not panic.
pub unsafe fn prep_nop(sqe: *mut RawSqe) {
    // SAFETY: The caller guarantees exclusive initialized SQE storage.
    unsafe {
        let (identity, flags, personality) = ((*sqe).user_data, (*sqe).flags, (*sqe).personality);
        *sqe = RawSqe::from_entry(io_uring::opcode::Nop::new().build().user_data(identity));
        (*sqe).flags |= flags;
        (*sqe).personality = personality;
    };
}
