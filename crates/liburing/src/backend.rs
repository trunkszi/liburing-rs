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

pub const IORING_SETUP_IOPOLL: u32 = 1;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
pub const IORING_SETUP_SUBMIT_ALL: u32 = 1 << 7;
pub const IORING_SETUP_NO_SQARRAY: u32 = 1 << 16;
pub const IORING_FEAT_MIN_TIMEOUT: u32 = 1 << 15;
pub const IORING_FEAT_NO_IOWAIT: u32 = 1 << 17;

pub(crate) fn enter_result(result: std::io::Result<usize>, waiting: bool) -> crate::Result<usize> {
    result.or_else(|error| {
        let errno = error.raw_os_error().unwrap_or(libc::EIO);
        match errno {
            libc::EINTR | libc::EAGAIN | libc::EBUSY => Ok(0),
            libc::ETIME if waiting => Ok(0),
            libc::EBADR => Err(crate::UringError::CompletionsDropped),
            libc::EOWNERDEAD => Err(crate::UringError::SqThreadGone),
            _ if waiting => Err(crate::UringError::Wait(errno)),
            _ => Err(crate::UringError::Submit(errno)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_result_maps_error_classes() {
        use crate::UringError;

        let cases = [
            (libc::EINTR, Ok(0), Ok(0)),
            (libc::EAGAIN, Ok(0), Ok(0)),
            (libc::EBUSY, Ok(0), Ok(0)),
            (libc::ETIME, Err(UringError::Submit(libc::ETIME)), Ok(0)),
            (
                libc::EBADR,
                Err(UringError::CompletionsDropped),
                Err(UringError::CompletionsDropped),
            ),
            (
                libc::EOWNERDEAD,
                Err(UringError::SqThreadGone),
                Err(UringError::SqThreadGone),
            ),
            (
                libc::EINVAL,
                Err(UringError::Submit(libc::EINVAL)),
                Err(UringError::Wait(libc::EINVAL)),
            ),
        ];
        for (errno, submitting, waiting) in cases {
            for (is_wait, expected) in [(false, submitting), (true, waiting)] {
                let result = enter_result(Err(std::io::Error::from_raw_os_error(errno)), is_wait);
                assert_eq!(result, expected, "errno={errno}, waiting={is_wait}");
            }
        }
        for waiting in [false, true] {
            assert_eq!(enter_result(Ok(7), waiting), Ok(7));
            let expected = if waiting {
                UringError::Wait(libc::EIO)
            } else {
                UringError::Submit(libc::EIO)
            };
            assert_eq!(
                enter_result(Err(std::io::Error::other("no numeric errno")), waiting),
                Err(expected)
            );
        }
    }

    #[test]
    fn native_fields_round_trip() {
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
