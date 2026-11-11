//! Synchronous futex2 words and the four futex2 syscalls.
//!
//! `io_uring` submission helpers live in `ops::futex` and share these words.

pub mod syscalls;
pub mod word;

pub use syscalls::{
    futex_requeue_numa_u32, futex_requeue_u32, futex_wait_numa_u32, futex_wait_u32, futex_waitv,
    futex_wake_numa_u32, futex_wake_u32, sys_futex_requeue, sys_futex_wait, sys_futex_waitv,
    sys_futex_wake,
};
pub use word::{FutexFlags, FutexNumaU32, FutexWaitV, FutexWaiter, FutexWord};
