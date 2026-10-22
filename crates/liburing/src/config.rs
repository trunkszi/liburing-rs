//! Ring construction and bounded queue configuration.

use crate::{
    error::{Result, UringError},
    proactor::Proactor,
};

/// Requested ring sizes, setup behavior, and preallocated dispatch budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProactorConfig {
    /// Requested kernel submission queue entries; must be nonzero.
    pub entries: u32,
    /// Optional completion queue size, at least as large as `entries`.
    pub cq_entries: Option<u32>,
    /// Additional Linux `IORING_SETUP_*` flags requested by the caller.
    pub setup_flags: u32,
    /// Probe single-issuer and task-run optimizations with older-kernel fallback.
    pub enable_optimizations: bool,
    /// Maximum number of SQEs retained in the preallocated staging queue.
    pub staged_capacity: usize,
    /// Maximum number of completions processed during one default tick.
    pub max_cqe_batch: usize,
    /// Create and automatically arm the internal cross-thread eventfd waker.
    pub enable_waker: bool,
}

impl Default for ProactorConfig {
    fn default() -> Self {
        Self {
            entries: 256,
            cq_entries: None,
            setup_flags: 0,
            enable_optimizations: true,
            staged_capacity: 1024,
            max_cqe_batch: 256,
            enable_waker: true,
        }
    }
}

impl ProactorConfig {
    /// Starts a builder with default ring and queue capacities.
    ///
    /// # Panics
    /// Does not panic.
    pub fn builder() -> ProactorBuilder {
        ProactorBuilder::default()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.entries == 0 {
            return Err(UringError::InvalidConfig("entries must be nonzero"));
        }
        if self
            .cq_entries
            .is_some_and(|entries| entries < self.entries)
        {
            return Err(UringError::InvalidConfig(
                "cq_entries must be at least entries",
            ));
        }
        if self.staged_capacity == 0 {
            return Err(UringError::InvalidConfig("staged_capacity must be nonzero"));
        }
        if self.max_cqe_batch == 0 {
            return Err(UringError::InvalidConfig("max_cqe_batch must be nonzero"));
        }
        Ok(())
    }
}

/// Fluent construction of an explicitly owned single-threaded proactor.
#[derive(Debug, Clone, Default)]
pub struct ProactorBuilder {
    config: ProactorConfig,
}

impl ProactorBuilder {
    /// Starts with default capacities and automatic kernel feature fallback.
    ///
    /// # Panics
    /// Does not panic.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests the kernel submission queue size.
    ///
    /// # Panics
    /// Does not panic; construction validates the value.
    pub const fn entries(mut self, entries: u32) -> Self {
        self.config.entries = entries;
        self
    }

    /// Requests an explicit completion queue size.
    ///
    /// # Panics
    /// Does not panic; construction validates the value.
    pub const fn cq_entries(mut self, entries: u32) -> Self {
        self.config.cq_entries = Some(entries);
        self
    }

    /// Adds caller-selected Linux ring setup flags.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn setup_flags(mut self, flags: u32) -> Self {
        self.config.setup_flags = flags;
        self
    }

    /// Enables or disables automatic task-run optimization probing.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn enable_optimizations(mut self, enabled: bool) -> Self {
        self.config.enable_optimizations = enabled;
        self
    }

    /// Sets the maximum number of overflow and reentrant submissions.
    ///
    /// # Panics
    /// Does not panic; construction validates the value.
    pub const fn staged_capacity(mut self, capacity: usize) -> Self {
        self.config.staged_capacity = capacity;
        self
    }

    /// Sets the completion budget used by default ticks.
    ///
    /// # Panics
    /// Does not panic; construction validates the value.
    pub const fn max_cqe_batch(mut self, max_batch: usize) -> Self {
        self.config.max_cqe_batch = max_batch;
        self
    }

    /// Enables or disables the internal eventfd waker.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn enable_waker(mut self, enabled: bool) -> Self {
        self.config.enable_waker = enabled;
        self
    }

    /// Validates construction parameters without opening a kernel ring.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidConfig`] for invalid sizes or budgets.
    pub fn build_config(self) -> Result<ProactorConfig> {
        self.config.validate()?;
        Ok(self.config)
    }

    /// Creates the kernel ring and configured proactor resources.
    ///
    /// # Errors
    /// Returns invalid configuration, ring setup, or waker setup errors.
    pub fn build(self) -> Result<Proactor> {
        Proactor::new(self.build_config()?)
    }
}

/// Actual setup flags and feature bits accepted by the current kernel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelFeatures {
    /// Linux `io_uring_params.flags` used by the successful setup attempt.
    pub setup_flags: u32,
    /// Linux `io_uring_params.features` returned by the successful setup attempt.
    pub features: u32,
}

impl KernelFeatures {
    /// Reports whether the ring accepted `IORING_SETUP_SINGLE_ISSUER`.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn single_issuer(self) -> bool {
        self.setup_flags & liburing_sys::IORING_SETUP_SINGLE_ISSUER != 0
    }

    /// Reports whether the ring accepted `IORING_SETUP_COOP_TASKRUN`.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn coop_taskrun(self) -> bool {
        self.setup_flags & liburing_sys::IORING_SETUP_COOP_TASKRUN != 0
    }

    /// Reports whether the ring accepted `IORING_SETUP_DEFER_TASKRUN`.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn defer_taskrun(self) -> bool {
        self.setup_flags & liburing_sys::IORING_SETUP_DEFER_TASKRUN != 0
    }
}

#[cfg(test)]
mod unit {
    use super::{ProactorBuilder, UringError};

    #[test]
    fn invalid_queue_shapes_are_rejected_before_ring_setup() {
        for builder in [
            ProactorBuilder::new().entries(0),
            ProactorBuilder::new().entries(32).cq_entries(16),
            ProactorBuilder::new().staged_capacity(0),
            ProactorBuilder::new().max_cqe_batch(0),
        ] {
            assert!(matches!(
                builder.build_config(),
                Err(UringError::InvalidConfig(_))
            ));
        }
    }
}
