//! Single-threaded Linux io_uring completion dispatch with bounded submission staging.
//!
//! Each proactor and all its resources stay on the creating thread. Raw operation
//! buffers must remain valid until their final completions.
//!
//! # Payload codecs
//!
//! ```
//! use liburing::OperationPayloadCodec;
//!
//! #[derive(OperationPayloadCodec, Debug, PartialEq, Eq)]
//! struct Header {
//!     kind: u8,
//!     flags: u16,
//!     len: u32,
//! }
//!
//! let max = Header {
//!     kind: 0xff,
//!     flags: 0xffff,
//!     len: 0xffff_ffff,
//! };
//! assert_eq!(max.encode_payload(), 0x00FF_FFFF_FFFF_FFFF);
//! assert_eq!(
//!     Header::decode_payload(max.encode_payload()).as_ref(),
//!     Ok(&max)
//! );
//! let payload = <Header as liburing::OperationPayloadCodec>::encode_payload(&max);
//! assert_eq!(
//!     <Header as liburing::OperationPayloadCodec>::decode_payload(payload),
//!     Ok(max)
//! );
//! ```
//!
//! Wider primitive aliases cannot change the declared payload widths.
//!
//! ```compile_fail
//! use liburing::OperationPayloadCodec;
//!
//! #[allow(non_camel_case_types)]
//! type u8 = u64;
//!
//! #[derive(OperationPayloadCodec)]
//! struct WiderAlias { value: u8 }
//! ```
//!
//! Unsupported primitive paths are rejected.
//!
//! ```compile_fail
//! use liburing::OperationPayloadCodec;
//!
//! #[allow(non_camel_case_types)]
//! mod protocol {
//!     pub type u8 = u64;
//! }
//!
//! #[derive(OperationPayloadCodec)]
//! struct QualifiedAlias { value: protocol::u8 }
//! ```
//!
//! Signed aliases cannot replace unsigned payload fields.
//!
//! ```compile_fail
//! use liburing::OperationPayloadCodec;
//!
//! #[allow(non_camel_case_types)]
//! type u8 = i8;
//!
//! #[derive(OperationPayloadCodec)]
//! struct SignedAlias { value: u8 }
//! ```
//!
//! # Static subsystem dispatch
//!
//! ```
//! use liburing::define_subsystems;
//!
//! define_subsystems! {
//!     pub enum DemoSubsystems {
//!         Dns = 1,
//!         Http = 2,
//!     }
//! }
//!
//! assert_eq!(DemoSubsystems::Http.id(), 2);
//! assert_eq!(DemoSubsystems::from_id(0), None);
//! ```
//!
//! ```
//! use liburing::{CompletionDispatcher, define_subsystems};
//!
//! define_subsystems! { enum Routes { Network = 1, Storage = 2 } }
//! struct Worker {
//!     network: usize,
//!     storage: usize,
//! }
//! let mut worker = Worker {
//!     network: 0,
//!     storage: 0,
//! };
//! let mut dispatcher = Routes::dispatcher(&mut worker, |route, state, _, _| {
//!     match route {
//!         Routes::Network => state.network += 1,
//!         Routes::Storage => state.storage += 1,
//!     }
//!     Ok(())
//! });
//! fn accepts_dispatcher<D: CompletionDispatcher<Kind>, Kind>(_: &mut D) {}
//! accepts_dispatcher(&mut dispatcher);
//! drop(dispatcher);
//! assert_eq!((worker.network, worker.storage), (0, 0));
//! ```
//!
//! The dispatcher retains an exclusive borrow of the worker until its last use.
//!
//! ```compile_fail
//! use liburing::define_subsystems;
//! define_subsystems! { enum Routes { Network = 1 } }
//! let mut state = 0;
//! let mut dispatcher = Routes::dispatcher(&mut state, |_, state, _, _| {
//!     *state += 1;
//!     Ok(())
//! });
//! state += 1;
//! drop(dispatcher);
//! ```

pub mod backend;
pub mod buffer_ring;
pub mod config;
pub mod direct_file;
pub mod error;
pub mod fixed_buffers;
pub mod fixed_files;
pub mod futex2;
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
pub use ops::{
    FUTEX_BITSET_MATCH_ANY, FUTEX2_PRIVATE, FUTEX2_SIZE_U32, FutexWaitV, STATX_BASIC_STATS,
    STATX_DIOALIGN, Statx, StatxTimestamp, prep_futex_wait, prep_futex_waitv, prep_futex_wake,
};
pub use proactor::{Proactor, ProactorStats};
pub use subsystem::{Completion, CompletionDispatcher, SubmissionContext};
pub use uring_macros::{OperationPayloadCodec, define_subsystems};
