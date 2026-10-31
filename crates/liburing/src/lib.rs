//! Single-threaded Linux io_uring completion dispatch with bounded submission staging.
//!
//! Each proactor and all its resources stay on the creating thread. Raw operation
//! buffers must remain valid until their final completions.

pub mod backend;
pub mod buffer_ring;
pub mod config;
pub mod direct_file;
pub mod error;
pub mod fixed_buffers;
pub mod fixed_files;
pub mod id;
mod identity_map;
mod operation;
pub mod operation_slab;
pub mod ops;
pub mod proactor;
pub mod socket_io;
pub mod subsystem;

pub use buffer_ring::{BufferLease, BufferRing};
pub use config::{
    EventDrivenConfig, KernelFeatures, ProactorBuilder, ProactorConfig, ProactorMode, SqPollConfig,
};
pub use direct_file::{DirectAccess, DirectFile};
pub use error::{Result, UringError};
pub use id::{
    BufferGroupId, BufferId, OperationId, OperationPayload, OperationPayloadCodec, SubsystemId,
    UringFileSlot,
};
pub use proactor::{Proactor, ProactorStats};
pub use subsystem::{Completion, CompletionDispatcher, SubmissionContext};
