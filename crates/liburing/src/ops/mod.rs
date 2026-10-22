//! SQE preparation helpers and bounded completion waits.
//!
//! Raw preparation helpers require exclusive initialized SQE storage. Pointer
//! operands must outlive their final CQEs, even after a cancellation request.

pub mod net;
pub mod nop;
pub mod timeout;

pub use nop::prep_nop;
pub use timeout::{Timeout, wait_timeout};
