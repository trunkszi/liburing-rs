//! Single-threaded Linux io_uring completion dispatch with bounded submission staging.
//!
//! Each proactor owns one ring. Only its waker and command queues cross threads;
//! raw operation buffers must remain valid until their final completions.

pub mod config;
pub mod error;
pub mod fixed_buffers;
pub mod fixed_files;
pub mod id;
pub mod ops;
pub mod pbuf_ring;
pub mod proactor;
pub mod socket_bridge;
pub mod subsystem;
pub mod waker;

pub use config::{KernelFeatures, ProactorBuilder, ProactorConfig};
pub use error::{Result, UringError};
pub use id::{BufGroupId, BufferId, OpId, OpPayload, OpPayloadCodec, SubsystemId, UringFileSlot};
pub use proactor::Proactor;
pub use subsystem::{Completion, SubmissionContext, SubsystemHandler, SubsystemRegistry};
pub use waker::{CrossThreadCommandQueue, ProactorWaker};
