//! Synchronous syscall control over a retained native ring owner.
use core::sync::atomic::{Ordering, fence};
use std::{io, os::fd::AsRawFd};

use super::{
    IoUring,
    register::{self, RegisterTarget},
    ring::load32,
    sys::{self, params::*, register::IoUringRsrcUpdate},
    types::SubmitArgs,
};
/// Borrowed native syscall interface. Registration state is local to this value.
pub struct Submitter<'a> {
    pub(crate) ring: &'a IoUring,
    pub(crate) registered: Option<u32>,
}
impl Submitter<'_> {
    /// Enters with pending SQEs and an optional blocking CQ minimum.
    /// # Errors
    /// Returns kernel syscall errors without retrying or losing queue ownership.
    /// # Panics
    /// Does not panic.
    pub fn submit_and_wait(&self, want: usize) -> io::Result<usize> {
        self.submit(None, want)
    }
    /// Enters with borrowed extended arguments, retaining operands through syscall return.
    /// # Errors
    /// Returns kernel syscall errors without retrying.
    /// # Panics
    /// Does not panic.
    pub fn submit_with_args(&self, want: usize, args: &SubmitArgs<'_, '_>) -> io::Result<usize> {
        self.submit(Some(args), want)
    }
    fn submit(&self, args: Option<&SubmitArgs<'_, '_>>, want: usize) -> io::Result<usize> {
        let want = u32::try_from(want).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let state = &self.ring.inner.sq;
        let mut submit = state
            .published_tail
            .wrapping_sub(load32(state.head, Ordering::Acquire));
        let mut flags = 0;
        let sqpoll = self.ring.params().raw().flags & IORING_SETUP_SQPOLL != 0;
        if sqpoll {
            if submit != 0 {
                fence(Ordering::SeqCst);
                if load32(state.flags, Ordering::Acquire) & IORING_SQ_NEED_WAKEUP != 0 {
                    flags |= IORING_ENTER_SQ_WAKEUP;
                }
            }
            submit = 0;
        }
        if want != 0 || self.ring.params().raw().flags & IORING_SETUP_IOPOLL != 0 {
            flags |= IORING_ENTER_GETEVENTS;
        }
        let (arg, len) = if let Some(args) = args {
            flags |= IORING_ENTER_EXT_ARG;
            (
                (&raw const args.raw).cast(),
                size_of::<IoUringGeteventsArg>(),
            )
        } else {
            (core::ptr::null(), 8)
        };
        if sqpoll && flags == 0 {
            return Ok(0);
        }
        // SAFETY: The ring retains its handle; borrowed arguments remain live until this call
        // returns.
        unsafe { self.enter_raw(submit, want, flags, arg, len) }
    }
    /// Executes an exact native enter with explicit arguments.
    /// # Errors
    /// Returns the kernel errno on failure.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// The pointer and size must match the flags-selected ABI. Retain all pointed-to
    /// arguments through syscall return and all SQE operands through final completion.
    #[uarch::prelude::hot_inline]
    pub unsafe fn enter_raw(
        &self,
        submit: u32,
        want: u32,
        flags: u32,
        arg: *const libc::c_void,
        len: usize,
    ) -> io::Result<usize> {
        let (fd, namespace) = match self.registered {
            Some(index) => (index as i32, IORING_ENTER_REGISTERED_RING),
            None => self
                .ring
                .inner
                .handle()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?
                .enter_target(),
        };
        // SAFETY: Caller establishes argument validity; the borrowed owner retains the live handle.
        let rc = unsafe {
            sys::sys_io_uring_enter(
                fd,
                submit,
                want,
                (flags & !IORING_ENTER_REGISTERED_RING) | namespace,
                arg,
                len,
            )
        };
        if rc < 0 {
            Err(io::Error::from_raw_os_error(-rc))
        } else {
            Ok(rc as usize)
        }
    }
    /// Registers a task-local index owned until explicit unregistration or submitter drop.
    /// # Errors
    /// Returns the kernel error or EBUSY for an existing registration.
    /// # Panics
    /// Does not panic.
    pub fn register_ring_fd(&mut self) -> io::Result<()> {
        if self.registered.is_some() {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        let mut records = [IoUringRsrcUpdate {
            offset: u32::MAX,
            data: self.ring.as_raw_fd() as u64,
            ..Default::default()
        }];
        // SAFETY: The live ring and initialized output remain borrowed through registration.
        unsafe {
            register::register_ring_fds(RegisterTarget::VfsFd(self.ring.as_raw_fd()), &mut records)
        }
        .map_err(super::io_error)?;
        self.registered = Some(records[0].offset);
        Ok(())
    }
    /// Releases this submitter's task-local ring index.
    /// # Errors
    /// Returns the kernel error, preserving the index for retry.
    /// # Panics
    /// Does not panic.
    pub fn unregister_ring_fd(&mut self) -> io::Result<()> {
        if let Some(offset) = self.registered {
            let records = [IoUringRsrcUpdate {
                offset,
                ..Default::default()
            }];
            // SAFETY: This submitter owns the exact registered index on the calling thread.
            unsafe {
                register::unregister_ring_fds(
                    RegisterTarget::VfsFd(self.ring.as_raw_fd()),
                    &records,
                )
            }
            .map_err(super::io_error)?;
            self.registered = None;
        }
        Ok(())
    }
}

impl Drop for Submitter<'_> {
    fn drop(&mut self) {
        let _result = self.unregister_ring_fd();
    }
}
