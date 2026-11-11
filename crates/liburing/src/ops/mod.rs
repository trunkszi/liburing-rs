//! SQE preparation helpers and finite completion waits.
//!
//! Pointer operands must outlive final CQEs, including after cancellation.

pub mod fs;
pub mod futex;
pub mod ipc_cmd;
pub mod net;
pub mod poll_time;
pub mod storage;

use std::time::Duration;

pub use fs::{STATX_BASIC_STATS, STATX_DIOALIGN, Statx, StatxTimestamp};
pub use futex::{
    FUTEX_BITSET_MATCH_ANY, FUTEX2_PRIVATE, FUTEX2_SIZE_U32, FutexWaitV, prep_futex_wait,
    prep_futex_waitv, prep_futex_wake,
};
pub use ipc_cmd::*;
pub use net::prep_recv_multishot_buffer_select;
pub use poll_time::*;
pub use storage::*;
use uarch::prelude::hot_inline;

pub use crate::backend::sys::params::KernelTimespec;
use crate::{
    backend::{RawSqe, sys::sqe::*},
    error::{Result, UringError},
    proactor::Proactor,
    subsystem::{Completion, SubmissionContext},
};

/// A stable kernel timespec used by a relative timeout SQE.
/// Moving this owner preserves its operand address. Its unsafe preparation API
/// requires retaining the owner until the timeout's final CQE or ring shutdown.
pub struct Timeout {
    timespec: Box<KernelTimespec>,
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
            timespec: Box::new(KernelTimespec {
                tv_sec: seconds,
                tv_nsec: duration.subsec_nanos() as i64,
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
    /// # Errors
    /// Preparation is infallible; kernel results arrive in the CQE.
    #[hot_inline]
    pub unsafe fn prepare(&self, sqe: *mut RawSqe) {
        // SAFETY: The caller guarantees SQE exclusivity and operand retention.
        unsafe {
            init_sqe(sqe, IORING_OP_TIMEOUT, -1);
            (*sqe).addr = std::ptr::from_ref(self.timespec.as_ref()) as u64;
            (*sqe).len = 1;
        }
    }
}

/// Submit pending operations and wait for one completion for at most `duration`.
/// The wait operand is retained internally until the synchronous kernel call
/// returns. Timeout expiry is reported as an empty batch, rather than a CQE.
/// # Errors
/// Returns submission, wait, or completion-handler errors from the proactor.
/// # Panics
/// Propagates a panic from the completion callback or registered handler.
pub fn wait_timeout<F>(proactor: &mut Proactor, duration: Duration, mut on_cqe: F) -> Result<usize>
where
    F: FnMut(Completion, &mut SubmissionContext<'_>) -> Result<()>,
{
    proactor.wait_completions(1, Some(duration), &mut on_cqe)
}

/// Initializes operation fields while retaining the caller's routing attributes.
/// # Safety
/// `sqe` must point to initialized, exclusively writable SQE storage.
#[hot_inline]
unsafe fn init_sqe(sqe: *mut RawSqe, opcode: u8, fd: i32) {
    // SAFETY: The caller supplies one live, initialized, exclusively writable SQE.
    unsafe {
        let sqe = &mut *sqe;
        sqe.opcode = opcode;
        sqe.ioprio = 0;
        sqe.fd = fd;
        sqe.off = 0;
        sqe.addr = 0;
        sqe.len = 0;
        sqe.operation_flags = 0;
        sqe.buf_index = 0;
        sqe.splice_fd_in = 0;
        sqe.addr3 = 0;
        sqe.pad2 = 0;
    }
}

/// Selects a direct output descriptor; u32::MAX requests kernel allocation.
/// # Errors
/// Does not return errors.
/// # Panics
/// Does not panic.
/// # Safety
/// `sqe` must address initialized, exclusive, unpublished storage.
#[hot_inline]
pub(super) unsafe fn set_target_index(sqe: *mut RawSqe, index: u32) {
    // SAFETY: Caller supplies initialized, exclusive, unpublished SQE storage.
    unsafe { (*sqe).set_file_index(index.saturating_add(1)) };
}

uarch::bitword! {
    pub(super) struct IoOptions(u16) {
        [1] pub RECV_MULTISHOT,
        [3] pub REPORT_USAGE,
        [4] pub BUNDLE,
        [5] pub VECTORIZED,
    }
}
uarch::bitword! {
    pub(super) struct CancelOptions(u32) {
        [1] pub FD,
        [2] pub ANY,
        [3] pub FD_FIXED,
        [5] pub OP,
    }
}
uarch::bitword! {
    pub(super) struct TimeoutOptions(u32) {
        [1] pub UPDATE,
    }
}
