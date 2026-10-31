//! `O_DIRECT` files whose alignment was checked when the descriptor was adopted.
//!
//! Polling support is reported from sysfs and is not a construction failure.
//! Callers decide whether an `IORING_SETUP_IOPOLL` ring is appropriate.

use std::{
    fs::OpenOptions,
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    rc::Rc,
};

use crate::{
    Proactor, Result, SubsystemId, UringError,
    fixed_buffers::InFlightWaitingBuffer,
    operation_slab::OperationKey,
    ops::{prep_read_fixed, prep_write_fixed},
    subsystem::SubmissionContext,
};

const FALLBACK_ALIGNMENT: u32 = 4096;

/// Access mode requested when opening a direct file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectAccess {
    /// `O_RDONLY | O_DIRECT`.
    ReadOnly,
    /// `O_RDWR | O_DIRECT`.
    ReadWrite,
}

/// An `O_DIRECT` file with memory and offset alignment fixed at construction.
#[derive(Debug)]
pub struct DirectFile {
    file: Rc<OwnedFd>,
    mem_align: u32,
    offset_align: u32,
}

struct Transfer {
    file: Rc<OwnedFd>,
    buffer: InFlightWaitingBuffer,
    ptr: *mut u8,
    len: u32,
    offset: u64,
    index: crate::BufferId,
    fd: RawFd,
}

impl DirectFile {
    /// Opens `path` with `O_DIRECT` and reads its direct I/O alignment.
    ///
    /// The path must already exist. This function does not create or allocate
    /// file blocks.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidConfig`] when the descriptor is not
    /// `O_DIRECT`, when `statx` does not report direct I/O alignment, or when
    /// that alignment is not a power of two. Returns a syscall error when
    /// `open` or `fcntl` fails.
    ///
    /// # Panics
    /// Does not panic.
    pub fn open(path: &Path, access: DirectAccess) -> Result<Self> {
        let mut options = OpenOptions::new();
        match access {
            DirectAccess::ReadOnly => {
                options.read(true);
            }
            DirectAccess::ReadWrite => {
                options.read(true).write(true);
            }
        }
        let file = options
            .custom_flags(libc::O_DIRECT)
            .open(path)
            .map_err(|error| {
                UringError::syscalls("open", error.raw_os_error().unwrap_or(libc::EIO))
            })?;
        Self::from_owned_fd(OwnedFd::from(file))
    }

    /// Adopts an existing descriptor after checking `O_DIRECT` and `statx`.
    ///
    /// A reported `stx_dio_mem_align` or `stx_dio_offset_align` of zero falls
    /// back to 4096 bytes. The descriptor is closed if construction fails.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidConfig`] without `O_DIRECT`, when `statx`
    /// reports no direct I/O support, or when the alignment is not a power of
    /// two. Returns a syscall error when `fcntl` fails.
    ///
    /// # Panics
    /// Does not panic.
    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self> {
        let raw = fd.as_raw_fd();
        // SAFETY: `raw` is an open descriptor owned by `fd` for this call.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 {
            return Err(last_error("fcntl"));
        }
        if flags & libc::O_DIRECT == 0 {
            return Err(UringError::InvalidConfig(
                "file is not opened with O_DIRECT",
            ));
        }
        let (mem_align, offset_align) = dio_alignment(raw)?;
        Ok(Self {
            file: Rc::new(fd),
            mem_align,
            offset_align,
        })
    }

    /// Returns the required user-buffer alignment in bytes.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn mem_align(&self) -> usize {
        self.mem_align as usize
    }

    /// Returns the required file-offset and I/O-length alignment in bytes.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn offset_align(&self) -> u64 {
        u64::from(self.offset_align)
    }

    /// Reports whether the backing block queue advertises `io_poll`.
    ///
    /// Reads `/sys/dev/block/<major>:<minor>/queue/io_poll`, then
    /// `../queue/io_poll` for partitions. Block devices use `st_rdev`; regular
    /// files use the filesystem device `st_dev`. A missing entry is `Ok(false)`.
    ///
    /// # Errors
    /// Returns a syscall error when `fstat` fails or the sysfs node cannot be
    /// read, and [`UringError::InvalidConfig`] when the node is not an integer.
    ///
    /// # Panics
    /// Does not panic.
    pub fn supports_polled_io(&self) -> Result<bool> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: `stat` is writable storage of the correct size, and `fd` is
        // the live descriptor owned by `self`.
        let rc = unsafe { libc::fstat(self.as_raw_fd(), stat.as_mut_ptr()) };
        if rc != 0 {
            return Err(last_error("fstat"));
        }
        // SAFETY: `fstat` succeeded and wrote a plain integer `stat`. The
        // buffer was zeroed, so any padding the call leaves untouched is zero.
        let stat = unsafe { stat.assume_init() };
        let device = block_device_id(&stat);
        let major = libc::major(device);
        let minor = libc::minor(device);
        let node = format!("/sys/dev/block/{major}:{minor}");
        if let Some(enabled) = read_poll_flag(&format!("{node}/queue/io_poll"))? {
            return Ok(enabled);
        }
        // Partitions publish the queue on the parent disk.
        if let Some(enabled) = read_poll_flag(&format!("{node}/../queue/io_poll"))? {
            return Ok(enabled);
        }
        Ok(false)
    }

    /// Checks alignment in constant time and stages `ReadFixed`.
    ///
    /// `len` bytes are taken from the start of `buffer`. On rejection the
    /// buffer returns to the pool instead of staying quarantined.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidConfig`] when the address, length, or
    /// offset is misaligned or `len` exceeds the buffer. Returns staging errors
    /// from the proactor without publishing the SQE.
    ///
    /// # Panics
    /// Does not panic.
    pub fn read_fixed(
        &self,
        proactor: &mut Proactor,
        subsystem: SubsystemId,
        buffer: InFlightWaitingBuffer,
        len: usize,
        offset: u64,
    ) -> Result<OperationKey> {
        let transfer = self.transfer(buffer, len, offset)?;
        stage_proactor(proactor, subsystem, transfer, false)
    }

    /// Checks alignment in constant time and stages `WriteFixed`.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidConfig`] when the address, length, or
    /// offset is misaligned or `len` exceeds the buffer. Returns staging errors
    /// from the proactor without publishing the SQE.
    ///
    /// # Panics
    /// Does not panic.
    pub fn write_fixed(
        &self,
        proactor: &mut Proactor,
        subsystem: SubsystemId,
        buffer: InFlightWaitingBuffer,
        len: usize,
        offset: u64,
    ) -> Result<OperationKey> {
        let transfer = self.transfer(buffer, len, offset)?;
        stage_proactor(proactor, subsystem, transfer, true)
    }

    /// Stages `ReadFixed` from a completion callback's submission context.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::read_fixed`].
    ///
    /// # Panics
    /// Does not panic.
    pub fn read_fixed_with_context(
        &self,
        context: &mut SubmissionContext<'_>,
        subsystem: SubsystemId,
        buffer: InFlightWaitingBuffer,
        len: usize,
        offset: u64,
    ) -> Result<OperationKey> {
        let transfer = self.transfer(buffer, len, offset)?;
        stage_context(context, subsystem, transfer, false)
    }

    /// Stages `WriteFixed` from a completion callback's submission context.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::write_fixed`].
    ///
    /// # Panics
    /// Does not panic.
    pub fn write_fixed_with_context(
        &self,
        context: &mut SubmissionContext<'_>,
        subsystem: SubsystemId,
        buffer: InFlightWaitingBuffer,
        len: usize,
        offset: u64,
    ) -> Result<OperationKey> {
        let transfer = self.transfer(buffer, len, offset)?;
        stage_context(context, subsystem, transfer, true)
    }

    fn transfer(&self, buffer: InFlightWaitingBuffer, len: usize, offset: u64) -> Result<Transfer> {
        let ptr = buffer.as_ptr();
        let buffer_len = buffer.len();
        let len = match validate_transfer(
            self.mem_align,
            self.offset_align,
            ptr as usize,
            len,
            buffer_len,
            offset,
        ) {
            Ok(len) => len,
            Err(error) => {
                release_unsubmitted(buffer)?;
                return Err(error);
            }
        };
        Ok(Transfer {
            file: Rc::clone(&self.file),
            fd: self.as_raw_fd(),
            index: buffer.id(),
            buffer,
            ptr,
            len,
            offset,
        })
    }
}

impl AsRawFd for DirectFile {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

fn stage_proactor(
    proactor: &mut Proactor,
    subsystem: SubsystemId,
    transfer: Transfer,
    write: bool,
) -> Result<OperationKey> {
    let Transfer {
        file,
        buffer,
        ptr,
        len,
        offset,
        index,
        fd,
    } = transfer;
    proactor.prepare_keyed_owned_sqe_with(subsystem, file, Some(buffer), move |sqe| {
        // SAFETY: Alignment was checked. `file` and the in-flight buffer stay
        // owned by the operation until its final CQE. SQPOLL may consume the
        // descriptor and pointer after `submit` returns.
        unsafe { prepare_fixed(sqe, fd, ptr, len, offset, index, write) }
    })
}

fn stage_context(
    context: &mut SubmissionContext<'_>,
    subsystem: SubsystemId,
    transfer: Transfer,
    write: bool,
) -> Result<OperationKey> {
    let Transfer {
        file,
        buffer,
        ptr,
        len,
        offset,
        index,
        fd,
    } = transfer;
    context.prepare_keyed_owned_sqe_with(subsystem, file, Some(buffer), move |sqe| {
        // SAFETY: Alignment was checked. `file` and the in-flight buffer stay
        // owned by the operation until its final CQE. SQPOLL may consume the
        // descriptor and pointer after `submit` returns.
        unsafe { prepare_fixed(sqe, fd, ptr, len, offset, index, write) }
    })
}

unsafe fn prepare_fixed(
    sqe: *mut crate::backend::RawSqe,
    fd: RawFd,
    ptr: *mut u8,
    len: u32,
    offset: u64,
    index: crate::BufferId,
    write: bool,
) {
    if write {
        // SAFETY: The caller guarantees exclusive SQE storage and operand lifetime.
        unsafe { prep_write_fixed(sqe, fd, ptr, len, offset, index) }
    } else {
        // SAFETY: The caller guarantees exclusive SQE storage and operand lifetime.
        unsafe { prep_read_fixed(sqe, fd, ptr, len, offset, index) }
    }
}

fn release_unsubmitted(buffer: InFlightWaitingBuffer) -> Result<()> {
    // SAFETY: No staged or published SQE refers to this buffer. Completing it
    // returns the slot to the pool instead of quarantining a request that was
    // never submitted.
    drop(unsafe { buffer.complete() }?);
    Ok(())
}

fn validate_transfer(
    mem_align: u32,
    offset_align: u32,
    address: usize,
    len: usize,
    buffer_len: usize,
    offset: u64,
) -> Result<u32> {
    if !mem_align.is_power_of_two() || !offset_align.is_power_of_two() {
        return Err(UringError::InvalidConfig(
            "direct I/O alignment is not a power of two",
        ));
    }
    let mem_mask = (mem_align as usize) - 1;
    let off_mask = u64::from(offset_align) - 1;
    if address & mem_mask != 0 {
        return Err(UringError::InvalidConfig("direct I/O buffer is misaligned"));
    }
    if len == 0 || len > buffer_len || (len as u64) & off_mask != 0 {
        return Err(UringError::InvalidConfig("direct I/O length is misaligned"));
    }
    if offset & off_mask != 0 {
        return Err(UringError::InvalidConfig("direct I/O offset is misaligned"));
    }
    u32::try_from(len).map_err(|_| UringError::InvalidConfig("direct I/O length exceeds u32"))
}

fn dio_alignment(fd: RawFd) -> Result<(u32, u32)> {
    let mut statx = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: `statx` is writable zeroed storage. `fd` is open. The empty path
    // is a valid C string paired with `AT_EMPTY_PATH`, so the call queries `fd`.
    let rc = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_DIOALIGN,
            statx.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(UringError::InvalidConfig(
            "statx reports no direct I/O support",
        ));
    }
    // SAFETY: `statx` succeeded. The buffer is a plain integer struct that was
    // zeroed before the call, and the kernel wrote the requested mask.
    let statx = unsafe { statx.assume_init() };
    if statx.stx_mask & libc::STATX_DIOALIGN == 0 {
        return Err(UringError::InvalidConfig(
            "statx reports no direct I/O support",
        ));
    }
    let mem_align = if statx.stx_dio_mem_align == 0 {
        FALLBACK_ALIGNMENT
    } else {
        statx.stx_dio_mem_align
    };
    let offset_align = if statx.stx_dio_offset_align == 0 {
        FALLBACK_ALIGNMENT
    } else {
        statx.stx_dio_offset_align
    };
    if !mem_align.is_power_of_two() || !offset_align.is_power_of_two() {
        return Err(UringError::InvalidConfig(
            "direct I/O alignment is not a power of two",
        ));
    }
    Ok((mem_align, offset_align))
}

fn read_poll_flag(path: &str) -> Result<Option<bool>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let value = text
                .trim()
                .parse::<u32>()
                .map_err(|_| UringError::InvalidConfig("unreadable io_poll sysfs value"))?;
            Ok(Some(value > 0))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(UringError::syscalls(
            "io_poll",
            error.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
}

fn last_error(operation: &'static str) -> UringError {
    UringError::syscalls(
        operation,
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

fn block_device_id(stat: &libc::stat) -> libc::dev_t {
    if stat.st_mode & libc::S_IFMT == libc::S_IFBLK {
        stat.st_rdev
    } else {
        stat.st_dev
    }
}

#[cfg(test)]
#[path = "../tests/direct_file/unit.rs"]
mod unit_alignment;
