//! Raw bindings to the statically linked upstream liburing and its C inline shim.
//!
//! `pre-release` selects upstream master, while `stable` selects liburing 2.15.
//! Set `LIBURING_DIR` to supply an existing upstream source directory.
//!
//! All operations preserve the upstream pointer and lifetime requirements. A
//! prepared request may retain its buffers until the target operation's final
//! completion, including when cancellation itself has already completed.

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
mod generated {
    pub use libc::{iovec, msghdr, sigset_t, sockaddr};

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use generated::*;
