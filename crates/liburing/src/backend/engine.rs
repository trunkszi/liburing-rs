//! Standard native ring facade and cold parameter construction.
use std::{
    io,
    os::fd::{AsRawFd, RawFd},
};

use super::{
    Submitter,
    queues::{CompletionQueue, SubmissionQueue},
    ring::{NativeRing, cq::CqRing, sq::SqRing},
    sys::params::*,
};
/// Native standard 64-byte SQE / 16-byte CQE ring with persistent cursors.
pub struct IoUring {
    pub(crate) inner: NativeRing,
    params: Parameters,
}
impl IoUring {
    /// Creates a native ring with default setup parameters.
    /// # Errors
    /// Returns setup, baseline or mapping errors.
    /// # Panics
    /// Does not intentionally panic.
    pub fn new(entries: u32) -> io::Result<Self> {
        Self::builder().build(entries)
    }
    /// Creates an exact setup builder.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn builder() -> Builder {
        Builder::default()
    }
    pub(crate) fn from_native(inner: NativeRing) -> Self {
        let params = Parameters(*inner.params());
        Self { inner, params }
    }
    pub(crate) fn register_owned_index(&mut self) -> Option<u32> {
        use super::{
            register::{self, RegisterTarget},
            sys::register::IoUringRsrcUpdate,
        };
        let mut records = [IoUringRsrcUpdate {
            offset: u32::MAX,
            data: self.as_raw_fd() as u64,
            ..Default::default()
        }];
        // SAFETY: The owned ring is live; records are initialized outputs on this thread.
        if unsafe {
            register::register_ring_fds(RegisterTarget::VfsFd(self.as_raw_fd()), &mut records)
        }
        .ok()
            != Some(1)
        {
            return None;
        }
        let index = records[0].offset;
        // SAFETY: The index was just registered for this exact ring on this thread;
        // its sole cleanup obligation moves to the handle only on successful adoption.
        if unsafe { self.inner.adopt_registered_index(index) }.is_err() {
            let rollback = [IoUringRsrcUpdate {
                offset: index,
                ..Default::default()
            }];
            // SAFETY: The live VFS ring owns this newly registered index. Releasing
            // only that index preserves any registration already held by the handle.
            let _cleanup = unsafe {
                register::unregister_ring_fds(RegisterTarget::VfsFd(self.as_raw_fd()), &rollback)
            };
            return None;
        }
        Some(index)
    }
    pub(crate) fn unregister_owned_index(&mut self) {
        use super::{
            mapping::RingHandle,
            register::{self, RegisterTarget},
            sys::register::IoUringRsrcUpdate,
        };
        let Some(RingHandle::Vfs {
            fd,
            registered_index: Some(index),
        }) = self.inner.storage.handle.as_ref()
        else {
            return;
        };
        let records = [IoUringRsrcUpdate {
            offset: *index,
            ..Default::default()
        }];
        // SAFETY: The live owned handle retains this exact task-local index until successful
        // release.
        if unsafe { register::unregister_ring_fds(RegisterTarget::VfsFd(fd.as_raw_fd()), &records) }
            .is_ok()
            && let Some(RingHandle::Vfs {
                registered_index, ..
            }) = self.inner.storage.handle.as_mut()
        {
            *registered_index = None;
        }
    }
    /// Borrows an exclusive SQ view. Drop publishes only changed entries.
    ///
    /// Dropping the view synchronizes the SQ tail when entries were pushed.
    /// In SQPOLL mode, call [`Self::submit`] or [`Submitter::submit_and_wait`]
    /// with zero minimum to wake a sleeping kernel SQ thread. Alternatively,
    /// check [`SubmissionQueue::need_wakeup`] and perform a wakeup enter explicitly.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn submission(&mut self) -> SubmissionQueue<'_> {
        SubmissionQueue(
            SqRing {
                state: &mut self.inner.sq,
                marker: core::marker::PhantomData,
            },
            None,
        )
    }
    /// Acquires an exclusive CQ snapshot with batched head acknowledgment.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn completion(&mut self) -> CompletionQueue<'_> {
        let mut view = CqRing {
            state: &mut self.inner.cq,
            marker: core::marker::PhantomData,
        };
        view.refresh_tail();
        CompletionQueue(view)
    }
    /// Borrows the syscall control interface; queues retain their persistent cursors.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub fn submitter(&self) -> Submitter<'_> {
        Submitter {
            ring: self,
            registered: None,
        }
    }
    /// Enters with pending published SQEs without waiting.
    /// # Errors
    /// Propagates kernel entry errors.
    /// # Panics
    /// Does not panic.
    pub fn submit(&self) -> io::Result<usize> {
        self.submitter().submit_and_wait(0)
    }
    /// Submits pending entries and waits for the requested CQ count.
    /// # Errors
    /// Propagates kernel entry errors.
    /// # Panics
    /// Does not panic.
    pub fn submit_and_wait(&self, want: usize) -> io::Result<usize> {
        self.submitter().submit_and_wait(want)
    }
    /// Returns the negotiated native parameters.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[uarch::prelude::hot_inline]
    pub const fn params(&self) -> &Parameters {
        &self.params
    }
}
impl AsRawFd for IoUring {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.handle().map_or(-1, |h| match h {
            super::mapping::RingHandle::Vfs { fd, .. } => fd.as_raw_fd(),
            super::mapping::RingHandle::RegisteredOnly { .. } => -1,
        })
    }
}
/// Successful native setup parameters, with named feature queries.
#[derive(Debug, Clone, Copy)]
pub struct Parameters(pub(crate) IoUringParams);
macro_rules! query {
    ($name:ident,$value:expr) => {
        /// Tests the named kernel feature bit.
        /// # Errors
        /// Does not return errors.
        /// # Panics
        /// Does not panic.
        pub const fn $name(&self) -> bool {
            self.0.features & $value != 0
        }
    };
}
impl Parameters {
    /// Returns the native parameter record.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn raw(&self) -> &IoUringParams {
        &self.0
    }
    /// Returns completion capacity.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn cq_entries(&self) -> u32 {
        self.0.cq_entries
    }
    query!(is_feature_single_mmap, IORING_FEAT_SINGLE_MMAP);
    query!(is_feature_nodrop, IORING_FEAT_NODROP);
    query!(is_feature_submit_stable, IORING_FEAT_SUBMIT_STABLE);
    query!(is_feature_sqpoll_nonfixed, IORING_FEAT_SQPOLL_NONFIXED);
    query!(is_feature_ext_arg, IORING_FEAT_EXT_ARG);
    query!(is_feature_min_timeout, IORING_FEAT_MIN_TIMEOUT);
    query!(is_feature_no_iowait, IORING_FEAT_NO_IOWAIT);
}
/// Cold exact native setup builder; never silently drops caller flags.
#[derive(Default)]
pub struct Builder {
    params: IoUringParams,
}
macro_rules! setup_flag {
    ($name:ident,$flag:expr) => {
        /// Enables the named native setup flag.
        /// # Errors
        /// Validation occurs at build.
        /// # Panics
        /// Does not panic.
        pub fn $name(&mut self) -> &mut Self {
            self.params.flags |= $flag;
            self
        }
    };
}
impl Builder {
    setup_flag!(setup_iopoll, IORING_SETUP_IOPOLL);
    setup_flag!(setup_single_issuer, IORING_SETUP_SINGLE_ISSUER);
    setup_flag!(setup_coop_taskrun, IORING_SETUP_COOP_TASKRUN);
    setup_flag!(setup_taskrun_flag, IORING_SETUP_TASKRUN_FLAG);
    setup_flag!(setup_defer_taskrun, IORING_SETUP_DEFER_TASKRUN);
    setup_flag!(setup_submit_all, IORING_SETUP_SUBMIT_ALL);
    setup_flag!(setup_no_sqarray, IORING_SETUP_NO_SQARRAY);
    setup_flag!(setup_clamp, IORING_SETUP_CLAMP);
    setup_flag!(setup_r_disabled, IORING_SETUP_R_DISABLED);
    /// Selects SQ-thread polling and its idle delay.
    /// # Errors
    /// Validation occurs at build.
    /// # Panics
    /// Does not panic.
    pub fn setup_sqpoll(&mut self, idle: u32) -> &mut Self {
        self.params.flags |= IORING_SETUP_SQPOLL;
        self.params.sq_thread_idle = idle;
        self
    }
    /// Selects the SQ-thread CPU.
    /// # Errors
    /// Validation occurs at build.
    /// # Panics
    /// Does not panic.
    pub fn setup_sqpoll_cpu(&mut self, cpu: u32) -> &mut Self {
        self.params.flags |= IORING_SETUP_SQ_AFF;
        self.params.sq_thread_cpu = cpu;
        self
    }
    /// Selects completion capacity.
    /// # Errors
    /// Validation occurs at build.
    /// # Panics
    /// Does not panic.
    pub fn setup_cqsize(&mut self, count: u32) -> &mut Self {
        self.params.flags |= IORING_SETUP_CQSIZE;
        self.params.cq_entries = count;
        self
    }
    /// Allocates, maps and validates the native ring.
    /// # Errors
    /// Returns setup, baseline or mapping errors.
    /// # Panics
    /// Does not intentionally panic.
    pub fn build(&self, entries: u32) -> io::Result<IoUring> {
        NativeRing::with_params(entries, self.params)
            .map(IoUring::from_native)
            .map_err(super::io_error)
    }
}

#[cfg(test)]
mod tests;
