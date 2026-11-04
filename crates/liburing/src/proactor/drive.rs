//! Bounded SQ publication, kernel progress, and synchronous waits.

use std::time::Duration;

use super::{Proactor, ProactorStats};
use crate::{
    CompletionDispatcher, Result, UringError, backend,
    backend::{EnterFlags, types},
    config::ProactorMode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Drive {
    Interrupt,
    SqThread,
    SyscallPoll,
}

impl Drive {
    pub(super) const fn for_mode(mode: ProactorMode) -> Self {
        match mode {
            ProactorMode::EventDriven(_) => Self::Interrupt,
            ProactorMode::SqPoll(_) | ProactorMode::SqPollIoPoll(_) => Self::SqThread,
            ProactorMode::IoPoll => Self::SyscallPoll,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct SqState {
    pending: u32,
    overflow: bool,
    taskrun: bool,
    wake: bool,
}
impl SqState {
    #[inline]
    fn read(sq: &crate::backend::squeue::SubmissionQueue<'_>, drive: Drive) -> Self {
        let pending = sq.len() as u32;
        Self {
            pending,
            overflow: sq.cq_overflow(),
            taskrun: sq.taskrun(),
            wake: drive == Drive::SqThread && pending != 0 && sq.need_wakeup(),
        }
    }
}

impl Proactor {
    /// Returns the immutable ring mode.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn mode(&self) -> ProactorMode {
        self.mode
    }

    /// Returns owner-local counts of actual kernel entries and backpressure.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn stats(&self) -> ProactorStats {
        self.stats
    }

    #[inline]
    pub(super) fn publish(&mut self) -> Result<(usize, SqState)> {
        if self.staged.is_empty() {
            return Ok((0, self.sq_state()?));
        }
        let Some(ring) = self.ring.as_mut() else {
            return Err(UringError::InvalidConfig("ring is closed"));
        };
        // Persistent native cursors suppress unchanged tail stores.
        let mut sq = ring.submission();
        let mut pushed = 0;
        while let Some(entry) = self.staged.front() {
            // SAFETY: The initialized SQE is copied into exclusive SQ storage. Slab
            // metadata retains owned DMA and descriptors through their final CQEs;
            // callers retain raw operands until completion as required by preparation.
            match unsafe { sq.push(&entry.sqe) } {
                Ok(()) => {}
                Err(UringError::SqRingFull) => {
                    self.stats.sq_full_events += 1;
                    break;
                }
                Err(error) => return Err(error),
            }
            self.staged.pop_front();
            pushed += 1;
        }
        if pushed != 0 {
            sq.sync();
        }
        // Snapshot after tail publication; need_wakeup supplies the kernel sleep handshake barrier.
        let mut state = SqState::read(&sq, self.drive);
        drop(sq);
        if state.wake {
            self.enter(0, 0, EnterFlags::SQ_WAKEUP, None, false, false)?;
            state.wake = false;
        }
        Ok((pushed, state))
    }

    #[inline]
    fn sq_state(&mut self) -> Result<SqState> {
        let Some(ring) = self.ring.as_mut() else {
            return Err(UringError::InvalidConfig("ring is closed"));
        };
        let sq = ring.submission();
        Ok(SqState::read(&sq, self.drive))
    }

    #[inline]
    fn cq_ready(&mut self) -> Result<usize> {
        let Some(ring) = self.ring.as_mut() else {
            return Err(UringError::InvalidConfig("ring is closed"));
        };
        Ok(ring.completion().len())
    }

    #[inline]
    pub(super) fn advance_kernel(&mut self, submit_pending: bool) -> Result<()> {
        let state = self.sq_state()?;
        self.advance_state(state, submit_pending).map(|_| ())
    }

    #[inline]
    fn advance_state(&mut self, state: SqState, submit_pending: bool) -> Result<usize> {
        let SqState {
            pending,
            overflow,
            taskrun,
            wake,
        } = state;
        let to_submit = if submit_pending { pending } else { 0 };
        let mut flags = EnterFlags::empty();
        let required = match self.drive {
            Drive::Interrupt => {
                if overflow || taskrun {
                    flags |= EnterFlags::GETEVENTS;
                }
                to_submit != 0 || overflow || taskrun
            }
            Drive::SqThread => {
                if overflow || taskrun {
                    flags |= EnterFlags::GETEVENTS;
                }
                // A sleeping SQ thread must consume published work even when no owner submission is
                // requested.
                if wake {
                    flags |= EnterFlags::SQ_WAKEUP;
                }
                !flags.is_empty()
            }
            Drive::SyscallPoll => {
                flags |= EnterFlags::GETEVENTS;
                to_submit != 0
                    || overflow
                    || taskrun
                    || (self.operation_count() != 0 && self.cq_ready()? == 0)
            }
        };
        if required {
            let submit = if self.drive == Drive::SqThread {
                0
            } else {
                to_submit
            };
            return self.enter(submit, 0, flags, None, false, overflow);
        }
        Ok(0)
    }

    #[inline]
    fn enter(
        &mut self,
        to_submit: u32,
        minimum: u32,
        flags: EnterFlags,
        args: Option<&types::SubmitArgs<'_, '_>>,
        waiting: bool,
        overflow: bool,
    ) -> Result<usize> {
        let Some(ring) = self.ring.as_mut() else {
            return Err(UringError::InvalidConfig("ring is closed"));
        };
        self.stats.enter_calls += 1;
        if waiting {
            self.stats.wait_calls += 1;
        }
        if flags.contains(EnterFlags::SQ_WAKEUP) {
            self.stats.sq_wakeups += 1;
        }
        if overflow {
            self.stats.cq_overflow_flushes += 1;
        }
        let (arg, size) = match args {
            Some(args) => (
                (&raw const args.raw).cast::<libc::c_void>(),
                size_of::<backend::sys::params::IoUringGeteventsArg>(),
            ),
            None => (std::ptr::null(), 8),
        };
        // SAFETY: Borrowed extended arguments outlive the synchronous enter; slab ownership
        // retains all published operands through final target completion and notifications.
        let result = unsafe {
            ring.submitter()
                .enter_raw(to_submit, minimum, flags.bits(), arg, size)
        };
        backend::enter_result(result, waiting)
    }

    /// Publishes accepted SQEs without waiting for completion.
    /// Returns the number of entries newly moved from staging into the shared SQ
    /// during this call, including internal control entries. This does not count
    /// kernel consumption or entries published by earlier calls. SQPOLL performs
    /// one bounded pass; other modes submit batches until blocked.
    /// # Errors
    /// Returns kernel-entry, closed-ring, or recursive-dispatch errors.
    /// Published operands remain retained after any kernel-entry failure.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub fn submit(&mut self) -> Result<usize> {
        self.check_drive()?;
        if self.staged.is_empty() {
            let state = self.sq_state()?;
            self.advance_state(state, self.drive != Drive::SqThread)?;
            return Ok(0);
        }
        if self.drive == Drive::SqThread {
            let had_staged = !self.staged.is_empty();
            let (published, state) = self.publish()?;
            self.advance_state(state, !had_staged)?;
            return Ok(published);
        }
        let mut total = 0;
        let bound = self.staged.len().saturating_add(1).max(2);
        for _ in 0..bound {
            let (published, state) = self.publish()?;
            total += published;
            // The syscall's accepted count proves SQ-head progress without re-opening the queue.
            let consumed = self.advance_state(state, true)?;
            if self.staged.is_empty() || (published == 0 && consumed == 0) {
                break;
            }
        }
        Ok(total)
    }

    /// Submits pending work and harvests one bounded nonblocking CQ batch.
    /// # Errors
    /// Returns publication, kernel-entry, ownership, or dispatcher errors.
    /// # Panics
    /// Propagates dispatcher panics with CQ acknowledgment preserved.
    #[inline]
    pub fn tick<D: CompletionDispatcher<Kind> + ?Sized, Kind>(
        &mut self,
        dispatcher: &mut D,
    ) -> Result<usize> {
        self.submit()?;
        self.harvest(self.config.max_cqe_batch, dispatcher)
    }

    /// Combines publication and a kernel wait in event-driven mode.
    /// Zero minimum without a timeout performs a nonblocking tick in every mode.
    /// Interrupted or timed-out waits can return fewer than the requested CQEs.
    /// # Errors
    /// Rejects blocking polling-mode waits before publication or dispatch. Returns
    /// configuration, kernel-entry, ownership, or dispatcher errors otherwise.
    /// # Panics
    /// Propagates dispatcher panics with CQ acknowledgment preserved.
    #[inline]
    pub fn wait_completions<D: CompletionDispatcher<Kind> + ?Sized, Kind>(
        &mut self,
        min_complete: u32,
        timeout: Option<Duration>,
        dispatcher: &mut D,
    ) -> Result<usize> {
        self.check_drive()?;
        if min_complete == 0 && timeout.is_none() {
            return self.tick(dispatcher);
        }
        if !self.mode.allows_blocking_wait() {
            return Err(UringError::BlockingWaitUnavailable {
                mode: self.mode.name(),
            });
        }
        let cq_capacity = self
            .ring
            .as_ref()
            .ok_or(UringError::InvalidConfig("ring is closed"))?
            .params()
            .cq_entries();
        if min_complete as usize > self.config.max_cqe_batch || min_complete > cq_capacity {
            return Err(UringError::InvalidConfig(
                "wait count exceeds completion capacity",
            ));
        }
        let (_, state) = self.publish()?;
        if self.cq_ready()? >= min_complete as usize {
            self.advance_state(state, true)?;
        } else {
            self.enter_wait_state(min_complete, timeout, state)?;
        }
        self.harvest(self.config.max_cqe_batch, dispatcher)
    }

    pub(crate) fn kernel_wait_private(&mut self, timeout: Duration) -> Result<()> {
        self.check_drive()?;
        self.enter_wait(1, Some(timeout))
    }

    fn enter_wait(&mut self, min_complete: u32, timeout: Option<Duration>) -> Result<()> {
        let state = self.sq_state()?;
        self.enter_wait_state(min_complete, timeout, state)
    }

    #[inline]
    fn enter_wait_state(
        &mut self,
        min_complete: u32,
        timeout: Option<Duration>,
        state: SqState,
    ) -> Result<()> {
        let SqState {
            pending,
            overflow,
            wake,
            ..
        } = state;
        let mut flags = EnterFlags::GETEVENTS | EnterFlags::EXT_ARG;
        let mut args = types::SubmitArgs::new();
        let config = match self.mode {
            ProactorMode::EventDriven(config) => Some(config),
            ProactorMode::SqPoll(_) | ProactorMode::IoPoll | ProactorMode::SqPollIoPoll(_) => None,
        };
        if self.features.no_iowait() && config.is_none_or(|config| config.no_iowait) {
            flags |= EnterFlags::NO_IOWAIT;
        }
        if self.features.min_timeout()
            && let Some(usec) = config.and_then(|config| config.batch_wait_usec)
        {
            args = args.min_wait_usec(usec.get());
        }
        if wake {
            flags |= EnterFlags::SQ_WAKEUP;
        }
        let timespec = timeout.map(types::Timespec::from);
        if let Some(timespec) = timespec.as_ref() {
            args = args.timespec(timespec);
        }
        let submit = if self.drive == Drive::SqThread {
            0
        } else {
            pending
        };
        self.enter(submit, min_complete, flags, Some(&args), true, overflow)?;
        Ok(())
    }

    fn check_drive(&self) -> Result<()> {
        if self.dispatching {
            return Err(UringError::ReentrantDispatch);
        }
        if self.ring.is_none() {
            return Err(UringError::InvalidConfig("ring is closed"));
        }
        Ok(())
    }
}
