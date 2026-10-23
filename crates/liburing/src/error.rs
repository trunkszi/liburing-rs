//! Structured failures from ring setup, submission, and resource management.

use thiserror::Error;

/// Result returned by the proactor and its resource registries.
pub type Result<T> = core::result::Result<T, UringError>;

/// A rejected operation or a Linux error reported at an I/O boundary.
///
/// Numeric syscall errors are positive Linux errno values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UringError {
    /// Ring creation failed.
    #[error("ring initialization failed with errno {0}")]
    RingInit(i32),
    /// Publishing submissions to the kernel failed.
    #[error("submission failed with errno {0}")]
    Submit(i32),
    /// Waiting for completions failed.
    #[error("completion wait failed with errno {0}")]
    Wait(i32),
    /// Neither the kernel SQ nor the bounded staging queue has free capacity.
    #[error("submission queue capacity exhausted")]
    SqRingFull,
    /// A payload does not fit the 56-bit operation identifier field.
    #[error("operation payload {0:#x} exceeds 56 bits")]
    PayloadOverflow(u64),
    /// A subsystem-specific payload decoder rejected its input.
    #[error("invalid operation payload {0:#x}")]
    InvalidPayload(u64),
    /// The requested subsystem identifier is reserved or otherwise invalid.
    #[error("invalid subsystem identifier {0}")]
    InvalidSubsystemId(u8),
    /// No registered-file slot is available.
    #[error("fixed file slots exhausted")]
    FixedFileSlotsExhausted,
    /// A fixed-file index is outside the registry or no longer registered.
    #[error("invalid fixed file slot {0}")]
    InvalidFileSlot(u32),
    /// No registered buffer is available.
    #[error("fixed buffers exhausted")]
    FixedBuffersExhausted,
    /// The buffer is not leased to an outstanding operation.
    #[error("buffer {0} is not in flight")]
    BufferNotInFlight(u16),
    /// The target operation has not yet completed, so its buffer cannot be reused.
    #[error("buffer {0} is still quarantined")]
    BufferStillQuarantined(u16),
    /// Creating or registering a provided-buffer ring failed.
    #[error("buffer ring setup failed with errno {0}")]
    BufferRingSetup(i32),
    /// A configuration value would violate ring or batching constraints.
    #[error("invalid proactor configuration: {0}")]
    InvalidConfig(&'static str),
    /// Prepared SQE flags require guarantees that bounded staging cannot provide.
    #[error("invalid prepared submission: {0}")]
    InvalidPreparedSqe(&'static str),
    /// A callback attempted to harvest or submit while CQ dispatch was active.
    #[error("recursive completion dispatch or submission is forbidden")]
    ReentrantDispatch,
    /// A named Linux syscall failed.
    #[error("{operation} failed with errno {errno}")]
    Syscall {
        /// Stable operation name for diagnostics.
        operation: &'static str,
        /// Positive Linux errno value.
        errno: i32,
    },
}

impl UringError {
    /// Wraps a positive errno or negative liburing return value.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn from_errno(errno: i32) -> Self {
        Self::syscalls("io_uring", errno)
    }

    /// Associates a syscall name with its positive errno or negative return value.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn syscalls(operation: &'static str, errno: i32) -> Self {
        Self::Syscall {
            operation,
            errno: errno.saturating_abs(),
        }
    }
}

impl From<std::io::Error> for UringError {
    fn from(error: std::io::Error) -> Self {
        Self::syscalls("io", error.raw_os_error().unwrap_or(libc::EIO))
    }
}
