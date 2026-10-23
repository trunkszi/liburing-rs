//! Native Linux SQE layout converted directly to the pure Rust ring entry.

pub use io_uring::{IoUring, cqueue, opcode, squeue, types};

/// The Linux 64-byte SQE ABI, without generated C bindings or foreign helpers.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RawSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub operation_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub pad2: u64,
}

impl RawSqe {
    /// Converts the exact Linux SQE bytes to the ring's native entry type.
    /// # Errors
    /// This function does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn into_entry(self) -> squeue::Entry {
        // SAFETY: Both repr(C) types implement the identical 64-byte Linux SQE
        // layout. All fields are integer bit patterns; no references are created.
        unsafe { std::mem::transmute(self) }
    }

    /// Copies a native entry into the public pointer-compatible SQE layout.
    /// # Errors
    /// This function does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn from_entry(entry: squeue::Entry) -> Self {
        // SAFETY: Both types are the same repr(C) Linux SQE ABI with valid
        // integer fields and no destructor or implicit pointer ownership.
        unsafe { std::mem::transmute(entry) }
    }
}

pub const IOSQE_FIXED_FILE: u32 = 1;
pub const IOSQE_IO_DRAIN: u32 = 2;
pub const IOSQE_IO_LINK: u32 = 4;
pub const IOSQE_IO_HARDLINK: u32 = 8;
pub const IOSQE_BUFFER_SELECT: u32 = 32;
pub const IOSQE_CQE_SKIP_SUCCESS: u32 = 64;
pub const IORING_CQE_F_BUFFER: u32 = 1;
pub const IORING_CQE_F_MORE: u32 = 2;
pub const IORING_CQE_F_NOTIF: u32 = 8;
pub const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
pub const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
pub const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;
pub const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
pub const IORING_RECV_MULTISHOT: u16 = 2;

/// Runs deferred kernel task work without waiting for an I/O completion.
pub(crate) trait SynchronousTaskrun {
    fn synchronous_taskrun(&self) -> std::io::Result<usize>;
}

impl SynchronousTaskrun for io_uring::Submitter<'_> {
    fn synchronous_taskrun(&self) -> std::io::Result<usize> {
        flush_task_work(|| {
            // SAFETY: Submit no entries, request no minimum CQEs, and pass no signal
            // mask. GETEVENTS executes deferred task work without waiting for I/O.
            unsafe {
                self.enter::<libc::sigset_t>(0, 0, io_uring::EnterFlags::GETEVENTS.bits(), None)
            }
        })
    }
}

fn flush_task_work(mut enter: impl FnMut() -> std::io::Result<usize>) -> std::io::Result<usize> {
    loop {
        match enter() {
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error) if matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EBUSY)) => {
                return Ok(0);
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_work_retries_signals_and_defers_kernel_backpressure() {
        let mut calls = 0;
        let result = flush_task_work(|| {
            calls += 1;
            if calls < 3 {
                Err(std::io::Error::from_raw_os_error(libc::EINTR))
            } else {
                Ok(7)
            }
        });
        assert_eq!(result.ok(), Some(7));
        assert_eq!(calls, 3);
        for error in [libc::EAGAIN, libc::EBUSY] {
            assert_eq!(
                flush_task_work(|| Err(std::io::Error::from_raw_os_error(error))).ok(),
                Some(0)
            );
        }
        assert_eq!(
            flush_task_work(|| Err(std::io::Error::from_raw_os_error(libc::EBADF)))
                .err()
                .and_then(|error| error.raw_os_error()),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn native_entry_layout_and_every_exposed_field_round_trip() {
        assert_eq!(std::mem::size_of::<RawSqe>(), 64);
        assert_eq!(
            std::mem::align_of::<RawSqe>(),
            std::mem::align_of::<squeue::Entry>()
        );
        let entry = opcode::RecvMulti::new(types::Fd(17), 23)
            .build()
            .user_data(0x1234);
        let raw = RawSqe::from_entry(entry);
        assert_eq!(
            (raw.fd, raw.buf_index, raw.ioprio, raw.user_data),
            (17, 23, 2, 0x1234)
        );
        assert_eq!(raw.into_entry().get_opcode(), u32::from(opcode::Recv::CODE));
    }
}
