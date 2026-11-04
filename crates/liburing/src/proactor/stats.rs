//! Owner-local kernel-entry counters.

/// Single-threaded hot-path counters owned by `Proactor`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProactorStats {
    /// Total `io_uring_enter` syscalls issued by the owner thread.
    pub enter_calls: u64,
    /// Blocking `io_uring_enter` wait calls in `EventDriven` mode.
    pub wait_calls: u64,
    /// `IORING_ENTER_SQ_WAKEUP` syscalls issued when the kernel SQ thread was asleep.
    pub sq_wakeups: u64,
    /// Kernel entries triggered to flush `IORING_SQ_CQ_OVERFLOW`.
    pub cq_overflow_flushes: u64,
    /// Ticks that left work in staging because the kernel SQ ring was full.
    pub sq_full_events: u64,
}
