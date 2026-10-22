//! Raw bindings to the statically linked upstream liburing and its C inline shim.
//!
//! `pre-release` selects upstream master, while `stable` selects liburing 2.15.
//! Set `LIBURING_DIR` to supply an existing upstream source directory.
//!
//! # Safety
//!
//! Every export is a raw upstream operation. Pointers dereferenced by an
//! operation must be non-null, correctly aligned, and valid for its complete
//! input or output range. Optional null pointers are accepted only where the
//! upstream operation permits them, such as the timeout and signal mask for
//! `uring_shim_submit_and_wait_timeout` or the CQE for `uring_shim_cqe_seen`.
//! A null return from `uring_shim_get_sqe` means the submission queue is full.
//!
//! Initialize ring storage with `uring_shim_queue_init_params`, check its result,
//! and call `uring_shim_queue_exit` exactly once after successful initialization.
//! Serialize application access to each ring. CQE pointers remain borrowed from
//! its completion queue until consumption; read their contents before calling
//! `uring_shim_cqe_seen` or `uring_shim_cq_advance`, and never advance past the
//! available completions.
//!
//! Request buffers, socket addresses, message headers, and their referenced
//! memory must remain valid and obey the operation's read/write permissions
//! until its final completion. Cancellation completion alone does not release
//! the target request's memory. Registered resources remain valid until the
//! corresponding unregister operation succeeds and outstanding users complete.
//!
//! Buffer rings require storage for every entry, a nonzero power-of-two entry
//! count, and the matching `entries - 1` mask. Add only into slots already
//! returned to the application. Initialize before publishing and advance only
//! by the number of newly initialized entries; advancement performs upstream's
//! release publication. Retain published buffers until their operation completes
//! and the application has finished consuming them.

#![cfg(target_os = "linux")]

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    missing_docs,
    dead_code,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::undocumented_unsafe_blocks
)]
// Bindgen emits ABI declarations and unsafe flexible-array accessors. Their
// contracts come from upstream headers and the caller requirements above.
mod generated {
    pub use libc::{iovec, msghdr, sigset_t, sockaddr};

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use generated::*;

/// Interpret the SQE file descriptor as a registered file-table index.
pub const IOSQE_FIXED_FILE: u32 = 1 << IOSQE_FIXED_FILE_BIT;
/// Complete earlier requests before starting this request.
pub const IOSQE_IO_DRAIN: u32 = 1 << IOSQE_IO_DRAIN_BIT;
/// Link the next SQE to this request, cancelling it on failure.
pub const IOSQE_IO_LINK: u32 = 1 << IOSQE_IO_LINK_BIT;
/// Link the next SQE without cancelling it on this request's failure.
pub const IOSQE_IO_HARDLINK: u32 = 1 << IOSQE_IO_HARDLINK_BIT;
/// Issue the request through asynchronous execution.
pub const IOSQE_ASYNC: u32 = 1 << IOSQE_ASYNC_BIT;
/// Select a receive buffer from the SQE's registered buffer group.
pub const IOSQE_BUFFER_SELECT: u32 = 1 << IOSQE_BUFFER_SELECT_BIT;
/// Suppress the completion event when this request succeeds.
pub const IOSQE_CQE_SKIP_SUCCESS: u32 = 1 << IOSQE_CQE_SKIP_SUCCESS_BIT;

/// Mark a completion timestamp as originating from hardware.
pub const IORING_CQE_F_TSTAMP_HW: u32 = 1 << IORING_TIMESTAMP_HW_SHIFT;
/// Extract the area identifier from a zero-copy receive offset.
pub const IORING_ZCRX_AREA_MASK: u64 = !((1_u64 << IORING_ZCRX_AREA_SHIFT) - 1);
