//! Structured failures from ring setup, submission, and resource management.

use thiserror::Error;
use uarch::prelude::cold_sink;

/// Result returned by the proactor and its resource registries.
pub type Result<T> = core::result::Result<T, UringError>;

/// A rejected operation or a Linux error reported at an I/O boundary.
///
/// Numeric syscall errors are positive Linux errno values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UringError {
    /// The running Linux kernel is older than the required baseline.
    #[error(
        "[proactor.kernel] Linux {detected_major}.{detected_minor} is unsupported; requires >= \
         {required_major}.{required_minor}"
    )]
    UnsupportedKernelVersion {
        /// Detected major kernel release number.
        detected_major: u32,
        /// Detected minor kernel release number.
        detected_minor: u32,
        /// Minimum required major kernel release number.
        required_major: u32,
        /// Minimum required minor kernel release number.
        required_minor: u32,
    },
    /// A required or requested kernel capability or opcode is unsupported by the active ring.
    #[error("[proactor.capability] unsupported kernel capability: {0}")]
    UnsupportedCapability(&'static str),
    /// A ring geometry, handle mode, or memory topology combination is invalid.
    #[error("[proactor.topology] invalid ring topology: {0}")]
    InvalidTopology(&'static str),
    /// A `futex2` operand, alignment, NUMA node, or flag combination is invalid.
    #[error("[proactor.futex] invalid futex2 operation: {0}")]
    InvalidFutex(&'static str),
    #[error("[proactor.mode] opcode {opcode} is not admitted in {mode} mode")]
    OpcodeNotAdmitted { opcode: u8, mode: &'static str },
    #[error("[proactor.mode] blocking wait is unavailable in {mode} mode")]
    BlockingWaitUnavailable { mode: &'static str },
    #[error("[proactor.mode] submitted operations cannot be cancelled in {mode} mode")]
    CancellationUnavailable { mode: &'static str },
    #[error("[proactor.completion] kernel dropped completions")]
    CompletionsDropped,
    #[error("[proactor.sq-thread] kernel SQ thread is gone")]
    SqThreadGone,
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
    /// A control operation names no currently tracked operation.
    #[error("unknown operation {0:?}")]
    UnknownOperation(crate::OperationId),
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

    /// Cold-path constructor for a named syscall failure placed in `.text.unlikely`.
    ///
    /// # Panics
    /// Does not panic.
    #[cold_sink]
    pub fn cold_syscall(operation: &'static str, errno: i32) -> Self {
        Self::syscalls(operation, errno)
    }

    /// Cold-path constructor for a ring initialization failure placed in `.text.unlikely`.
    ///
    /// # Panics
    /// Does not panic.
    #[cold_sink]
    pub fn cold_ring_init(errno: i32) -> Self {
        Self::RingInit(errno.saturating_abs())
    }

    /// Cold-path constructor for a submission failure placed in `.text.unlikely`.
    ///
    /// # Panics
    /// Does not panic.
    #[cold_sink]
    pub fn cold_submit(errno: i32) -> Self {
        Self::Submit(errno.saturating_abs())
    }

    /// Cold-path constructor for a completion wait failure placed in `.text.unlikely`.
    ///
    /// # Panics
    /// Does not panic.
    #[cold_sink]
    pub fn cold_wait(errno: i32) -> Self {
        Self::Wait(errno.saturating_abs())
    }
}

impl From<std::io::Error> for UringError {
    #[cold_sink]
    fn from(error: std::io::Error) -> Self {
        Self::syscalls("io", error.raw_os_error().unwrap_or(libc::EIO))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_and_topology_variants_format() {
        let kernel = UringError::UnsupportedKernelVersion {
            detected_major: 6,
            detected_minor: 15,
            required_major: 6,
            required_minor: 16,
        };
        assert_eq!(
            kernel.to_string(),
            "[proactor.kernel] Linux 6.15 is unsupported; requires >= 6.16"
        );
        assert_eq!(kernel, kernel);

        let cap = UringError::UnsupportedCapability("IORING_FEAT_SQE_MIXED");
        assert_eq!(
            cap.to_string(),
            "[proactor.capability] unsupported kernel capability: IORING_FEAT_SQE_MIXED"
        );

        let topo = UringError::InvalidTopology("SQ_REWIND requires NO_SQARRAY");
        assert_eq!(
            topo.to_string(),
            "[proactor.topology] invalid ring topology: SQ_REWIND requires NO_SQARRAY"
        );

        let futex = UringError::InvalidFutex("FUTEX2_NUMA requires 8-byte alignment");
        assert_eq!(
            futex.to_string(),
            "[proactor.futex] invalid futex2 operation: FUTEX2_NUMA requires 8-byte alignment"
        );
    }

    #[test]
    fn cold_constructors_normalize_errno() {
        assert_eq!(
            UringError::cold_syscall("io_uring_register", -libc::EINVAL),
            UringError::Syscall {
                operation: "io_uring_register",
                errno: libc::EINVAL,
            }
        );
        assert_eq!(
            UringError::cold_syscall("io_uring_register", libc::EINVAL),
            UringError::Syscall {
                operation: "io_uring_register",
                errno: libc::EINVAL,
            }
        );
        assert_eq!(
            UringError::cold_ring_init(-libc::ENOMEM),
            UringError::RingInit(libc::ENOMEM)
        );
        assert_eq!(
            UringError::cold_ring_init(libc::ENOMEM),
            UringError::RingInit(libc::ENOMEM)
        );
        assert_eq!(
            UringError::cold_submit(-libc::EAGAIN),
            UringError::Submit(libc::EAGAIN)
        );
        assert_eq!(
            UringError::cold_submit(libc::EAGAIN),
            UringError::Submit(libc::EAGAIN)
        );
        assert_eq!(
            UringError::cold_wait(-libc::EINTR),
            UringError::Wait(libc::EINTR)
        );
        assert_eq!(
            UringError::cold_wait(libc::EINTR),
            UringError::Wait(libc::EINTR)
        );
        let io_err = std::io::Error::from_raw_os_error(libc::EPERM);
        assert_eq!(
            UringError::from(io_err),
            UringError::Syscall {
                operation: "io",
                errno: libc::EPERM,
            }
        );
        let custom_io_err = std::io::Error::other("synthetic");
        assert_eq!(
            UringError::from(custom_io_err),
            UringError::Syscall {
                operation: "io",
                errno: libc::EIO,
            }
        );
    }
}
