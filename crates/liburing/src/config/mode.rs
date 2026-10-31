//! Mode-owned polling, waiting, and opcode capability contracts.

use core::num::NonZeroU32;
use std::time::Duration;

/// Kernel wait tuning for the lowest CPU usage in `ProactorMode::EventDriven`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventDrivenConfig {
    /// Skip iowait accounting and its cpufreq boost while waiting (Linux 6.15+, ignored
    /// otherwise).
    pub no_iowait: bool,
    /// Coalesce wakeups: wait this long for `min_complete`, then return on any CQE (Linux 6.12+).
    pub batch_wait_usec: Option<NonZeroU32>,
}

impl Default for EventDrivenConfig {
    #[inline]
    fn default() -> Self {
        Self {
            no_iowait: true,
            batch_wait_usec: None,
        }
    }
}

/// Kernel SQPOLL thread placement and idle configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqPollConfig {
    /// Target CPU core for the `iou-sqp-<pid>` thread (`IORING_SETUP_SQ_AFF`).
    /// Must differ from the owner thread's sole pinned CPU.
    pub thread_cpu: u32,
    /// Idle milliseconds before the kernel SQ thread sleeps (`NonZeroU32::MAX` is ~49.7 days at
    /// HZ=1000).
    pub idle_ms: NonZeroU32,
}

impl SqPollConfig {
    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn pinned(thread_cpu: u32) -> Self {
        Self {
            thread_cpu,
            idle_ms: NonZeroU32::MAX,
        }
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn with_idle_ms(mut self, idle_ms: NonZeroU32) -> Self {
        self.idle_ms = idle_ms;
        self
    }
}

/// Polling and waiting behavior fixed for the lifetime of one ring.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProactorMode {
    /// Event-driven mode (`SINGLE_ISSUER | COOP_TASKRUN | DEFER_TASKRUN | TASKRUN_FLAG`)
    /// with blocking kernel waits (`submit_and_wait_timeout`) for minimal CPU usage.
    EventDriven(EventDrivenConfig) = 0,
    /// General PMD busy-polling mode (`SQPOLL | SQ_AFF | SINGLE_ISSUER`);
    /// supports every socket, file, and timer operation.
    SqPoll(SqPollConfig) = 1,
    /// Polled `O_DIRECT` read/write busy-polling mode (`IOPOLL | SINGLE_ISSUER`).
    IoPoll = 2,
    /// Dual busy-polling mode (`SQPOLL | SQ_AFF | IOPOLL | SINGLE_ISSUER`);
    /// the kernel SQ thread both submits SQEs and reaps polled block I/O.
    SqPollIoPoll(SqPollConfig) = 3,
}

impl Default for ProactorMode {
    #[inline]
    fn default() -> Self {
        Self::EventDriven(EventDrivenConfig::default())
    }
}

impl ProactorMode {
    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn event_driven() -> Self {
        Self::EventDriven(EventDrivenConfig {
            no_iowait: true,
            batch_wait_usec: None,
        })
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn sq_poll(thread_cpu: u32) -> Self {
        Self::SqPoll(SqPollConfig::pinned(thread_cpu))
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn io_poll() -> Self {
        Self::IoPoll
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn sq_poll_io_poll(thread_cpu: u32) -> Self {
        Self::SqPollIoPoll(SqPollConfig::pinned(thread_cpu))
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn is_event_driven(self) -> bool {
        matches!(self, Self::EventDriven(_))
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn is_busy_poll(self) -> bool {
        !self.is_event_driven()
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn uses_sq_thread(self) -> bool {
        matches!(self, Self::SqPoll(_) | Self::SqPollIoPoll(_))
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn uses_iopoll(self) -> bool {
        matches!(self, Self::IoPoll | Self::SqPollIoPoll(_))
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn allows_blocking_wait(self) -> bool {
        matches!(self, Self::EventDriven(_))
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn supports_sockets_and_timers(self) -> bool {
        !self.uses_iopoll()
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn supports_cancellation(self) -> bool {
        !self.uses_iopoll()
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn default_shutdown_stall(self) -> Duration {
        if self.uses_iopoll() {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(320)
        }
    }

    /// Returns the configured mode value or capability.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EventDriven(_) => "event-driven",
            Self::SqPoll(_) => "sq-poll",
            Self::IoPoll => "io-poll",
            Self::SqPollIoPoll(_) => "sq-poll-io-poll",
        }
    }
}

/// Constant-time 256-bit opcode membership bitmap built at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OpcodeSet([u64; 4]);

impl OpcodeSet {
    pub(crate) const ALL: Self = Self([u64::MAX; 4]);
    pub(crate) const IOPOLL: Self = Self::of(&[
        io_uring::opcode::Nop::CODE,
        io_uring::opcode::Read::CODE,
        io_uring::opcode::Write::CODE,
        io_uring::opcode::Readv::CODE,
        io_uring::opcode::Writev::CODE,
        io_uring::opcode::ReadFixed::CODE,
        io_uring::opcode::WriteFixed::CODE,
        io_uring::opcode::ReadvFixed::CODE,
        io_uring::opcode::WritevFixed::CODE,
    ]);

    pub(crate) const fn of(codes: &[u8]) -> Self {
        let mut bits = [0u64; 4];
        let mut i = 0;
        while i < codes.len() {
            let op = codes[i];
            bits[(op >> 6) as usize] |= 1u64 << (op & 63);
            i += 1;
        }
        Self(bits)
    }

    #[inline(always)]
    pub(crate) const fn for_mode(mode: ProactorMode) -> Self {
        if mode.uses_iopoll() {
            Self::IOPOLL
        } else {
            Self::ALL
        }
    }

    #[inline(always)]
    pub(crate) const fn contains(self, op: u8) -> bool {
        (self.0[(op >> 6) as usize] & (1u64 << (op & 63))) != 0
    }
}
