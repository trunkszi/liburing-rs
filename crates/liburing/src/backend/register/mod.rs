//! Typed, non-owning registration calls. The caller owns every ring and resource lifetime.
mod files_buffers;
mod probe_caps;
mod sandbox_cancel_zcrx;
mod workers_napi_clock;

use std::os::fd::RawFd;

pub use files_buffers::*;
pub use probe_caps::*;
pub use sandbox_cancel_zcrx::*;
use uarch::prelude::hot_inline;
pub use workers_napi_clock::*;

use crate::{
    Result, UringError,
    backend::sys::{
        self,
        register::{IORING_REGISTER_USE_REGISTERED_RING, RegisterOpcode},
    },
};

/// Borrowed ring namespace. Registered indices are local to the calling task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterTarget {
    /// An ordinary VFS ring descriptor; this value never closes it.
    VfsFd(RawFd),
    /// A previously allocated index in this thread's registered-ring table.
    RegisteredIndex(u32),
}
impl RegisterTarget {
    /// Encodes the handle and opcode namespace without transferring ownership.
    /// # Errors
    /// Rejects an index that would encode the reserved blind-call fd of -1.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn syscall_args(self, opcode: RegisterOpcode) -> Result<(i32, u32)> {
        match self {
            Self::VfsFd(fd) => Ok((fd, opcode as u32)),
            Self::RegisteredIndex(u32::MAX) => {
                Err(UringError::InvalidConfig("reserved blind-call ring index"))
            }
            Self::RegisteredIndex(index) => Ok((
                index as i32,
                opcode as u32 | IORING_REGISTER_USE_REGISTERED_RING,
            )),
        }
    }

    /// Issues one raw registration call, preserving counts and positive errno.
    /// # Errors
    /// Returns kernel errors as `UringError::Syscall`, or rejects a reserved blind-call index.
    /// Never retries.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// Any consumed record and embedded pointers must be valid for the opcode's
    /// extent and required read/write access. State-changing calls must select
    /// the intended owned ring, with registered indices used on their owning task.
    /// Blind fd -1 calls require the opcode's distinct blind-call argument ABI.
    /// Retain registered memory through confirmed unregister or ring destruction,
    /// and keep resources alive through every operation that can still access them.
    #[hot_inline]
    pub unsafe fn register(
        self,
        opcode: RegisterOpcode,
        arg: *mut libc::c_void,
        count: u32,
    ) -> Result<u32> {
        let (fd, opcode) = self.syscall_args(opcode)?;
        // SAFETY: The caller guarantees the namespace, record layout and operand lifetimes.
        let result = unsafe { sys::sys_io_uring_register(fd, opcode, arg, count) };
        if result < 0 {
            Err(UringError::syscalls("io_uring_register", result))
        } else {
            Ok(result as u32)
        }
    }
}

fn count(len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| UringError::InvalidConfig("registration count exceeds u32"))
}
