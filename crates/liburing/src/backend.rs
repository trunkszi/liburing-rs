//! Native Linux ring facade with persistent queue cursors and typed UAPI values.

pub mod mapping;
pub mod register;
pub mod ring;
pub mod setup;
pub mod sys;

mod engine;
mod flags;
pub mod opcode;
mod queues;
mod submit;
pub mod types;
pub use engine::{Builder, IoUring, Parameters};
pub use flags::EnterFlags;
pub use queues::{CompletionQueue, SubmissionQueue};
pub use register::OpcodeProbe as Probe;
pub use submit::Submitter;
pub use sys::{cqe::RawCqe, sqe::RawSqe};
pub use types::SubmitArgs;
/// Standard native submission entry and flags.
pub mod squeue {
    pub use super::{RawSqe as Entry, SubmissionQueue, flags::Flags};
}
/// Standard native completion entry and borrowed consumer.
pub mod cqueue {
    pub use super::{CompletionQueue, RawCqe as Entry};
    /// Tests multishot continuation.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn more(flags: u32) -> bool {
        flags & super::IORING_CQE_F_MORE != 0
    }
    /// Tests zero-copy release notification.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn notif(flags: u32) -> bool {
        flags & super::IORING_CQE_F_NOTIF != 0
    }
}

#[uarch::prelude::cold_sink]
pub(crate) fn io_error(error: crate::UringError) -> std::io::Error {
    use crate::UringError;
    match error {
        UringError::Syscall { errno, .. }
        | UringError::RingInit(errno)
        | UringError::Submit(errno)
        | UringError::Wait(errno) => std::io::Error::from_raw_os_error(errno),
        UringError::SqRingFull => std::io::Error::from_raw_os_error(libc::EBUSY),
        _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, error),
    }
}

pub const IOSQE_FIXED_FILE: u32 = sys::sqe::IOSQE_FIXED_FILE as u32;
pub const IOSQE_IO_DRAIN: u32 = sys::sqe::IOSQE_IO_DRAIN as u32;
pub const IOSQE_IO_LINK: u32 = sys::sqe::IOSQE_IO_LINK as u32;
pub const IOSQE_IO_HARDLINK: u32 = sys::sqe::IOSQE_IO_HARDLINK as u32;
pub const IOSQE_BUFFER_SELECT: u32 = sys::sqe::IOSQE_BUFFER_SELECT as u32;
pub const IOSQE_CQE_SKIP_SUCCESS: u32 = sys::sqe::IOSQE_CQE_SKIP_SUCCESS as u32;
pub const IORING_CQE_F_BUFFER: u32 = sys::cqe::IORING_CQE_F_BUFFER;
pub const IORING_CQE_F_MORE: u32 = sys::cqe::IORING_CQE_F_MORE;
pub const IORING_CQE_F_NOTIF: u32 = sys::cqe::IORING_CQE_F_NOTIF;
pub const IORING_SETUP_SINGLE_ISSUER: u32 = sys::params::IORING_SETUP_SINGLE_ISSUER;
pub const IORING_SETUP_COOP_TASKRUN: u32 = sys::params::IORING_SETUP_COOP_TASKRUN;
pub const IORING_SETUP_TASKRUN_FLAG: u32 = sys::params::IORING_SETUP_TASKRUN_FLAG;
pub const IORING_SETUP_DEFER_TASKRUN: u32 = sys::params::IORING_SETUP_DEFER_TASKRUN;
pub const IORING_RECV_MULTISHOT: u16 = sys::sqe::IORING_RECV_MULTISHOT;

pub const IORING_SETUP_IOPOLL: u32 = sys::params::IORING_SETUP_IOPOLL;
pub const IORING_SETUP_SQPOLL: u32 = sys::params::IORING_SETUP_SQPOLL;
pub const IORING_SETUP_SQ_AFF: u32 = sys::params::IORING_SETUP_SQ_AFF;
pub const IORING_SETUP_CLAMP: u32 = sys::params::IORING_SETUP_CLAMP;
pub const IORING_SETUP_SUBMIT_ALL: u32 = sys::params::IORING_SETUP_SUBMIT_ALL;
pub const IORING_SETUP_NO_SQARRAY: u32 = sys::params::IORING_SETUP_NO_SQARRAY;
pub const IORING_FEAT_MIN_TIMEOUT: u32 = sys::params::IORING_FEAT_MIN_TIMEOUT;
pub const IORING_FEAT_NO_IOWAIT: u32 = sys::params::IORING_FEAT_NO_IOWAIT;

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
    fn native_builder_fields_match_uapi() {
        assert_eq!(std::mem::size_of::<RawSqe>(), 64);
        assert_eq!(std::mem::align_of::<RawSqe>(), 8);
        let entry = opcode::RecvMulti::new(types::Fd(17), 23)
            .build()
            .user_data(0x1234);
        let raw = entry;
        assert_eq!(
            (raw.fd, raw.buf_index, raw.ioprio, raw.user_data),
            (17, 23, 2, 0x1234)
        );
        assert_eq!(raw.get_opcode(), u32::from(opcode::Recv::CODE));
    }
    #[test]
    fn sqe_union_aliases_preserve_bytes() {
        let mut sqe: sys::sqe::RawSqe = RawSqe::default();
        sqe.set_off_or_addr2(0x1122_3344_5566_7788);
        assert_eq!(sqe.off, sqe.off_or_addr2());
        sqe.set_cmd_op(0xaabb_ccdd);
        assert_eq!(sqe.off_or_addr2(), 0x1122_3344_aabb_ccdd);
        sqe.set_addr_or_splice_off_in(0x1122_3344_5566_7788);
        assert_eq!(sqe.addr, sqe.addr_or_splice_off_in());
        sqe.set_level(0xaabb_ccdd);
        assert_eq!(sqe.addr_or_splice_off_in(), 0x1122_3344_aabb_ccdd);
        sqe.set_optname(0x9876_5432);
        assert_eq!(sqe.addr_or_splice_off_in(), 0x9876_5432_aabb_ccdd);
        sqe.set_op_flags(u32::MAX);
        assert_eq!((sqe.operation_flags, sqe.op_flags()), (u32::MAX, u32::MAX));
        sqe.set_buf_index_or_group(u16::MAX);
        assert_eq!(
            (sqe.buf_index, sqe.buf_index_or_group()),
            (u16::MAX, u16::MAX)
        );
        sqe.set_splice_fd_in_or_file_index(u32::MAX);
        assert_eq!(sqe.splice_fd_in, -1);
        assert_eq!(sqe.splice_fd_in_or_file_index(), u32::MAX);
        sqe.set_file_index(0x8000_1234);
        assert_eq!(sqe.file_index(), 0x8000_1234);
        sqe.set_addr_len(0xabcd);
        assert_eq!(sqe.file_index(), 0x8000_abcd);
        sqe.set_write_stream(0x12);
        assert_eq!(sqe.file_index(), 0x8000_ab12);
        sqe.set_addr3_or_cmd([0x1234, 0x5678]);
        assert_eq!((sqe.addr3, sqe.pad2), (0x1234, 0x5678));
        assert_eq!(sqe.addr3_or_cmd(), [0x1234, 0x5678]);
        sqe.set_attr_ptr(0xabcd);
        sqe.set_attr_type_mask(0xef01);
        assert_eq!(sqe.addr3_or_cmd(), [0xabcd, 0xef01]);
        sqe.set_optval(0x2345);
        assert_eq!(sqe.addr3_or_cmd(), [0x2345, 0xef01]);
        let _: RawSqe = sqe;
    }
}
