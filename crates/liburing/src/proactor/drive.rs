//! Bounded SQ publication, kernel progress, and synchronous waits.

use std::{mem::ManuallyDrop, time::Duration};

use io_uring::{EnterFlags, types};

use super::{Proactor, ProactorStats};
use crate::{CompletionDispatcher, Result, UringError, backend, config::ProactorMode};

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

    pub(super) fn publish(&mut self) -> Result<u32> {
        if self.staged.is_empty() {
            return Ok(0);
        }
        let ring = self
            .ring
            .as_mut()
            .ok_or(UringError::InvalidConfig("ring is closed"))?;
        // Suppress the queue's unconditional tail store when nothing can be pushed.
        let mut sq = ManuallyDrop::new(ring.submission());
        let mut pushed = 0;
        while let Some(entry) = self.staged.front() {
            // SAFETY: The initialized SQE is copied into exclusive SQ storage. Slab
            // metadata retains owned DMA and descriptors through their final CQEs;
            // callers retain raw operands until completion as required by preparation.
            if unsafe { sq.push(&entry.sqe.into_entry()) }.is_err() {
                self.stats.sq_full_events += 1;
                break;
            }
            self.staged.pop_front();
            pushed += 1;
        }
        if pushed != 0 {
            sq.sync();
        }
        // need_wakeup supplies the full store/load barrier paired with the kernel's
        // sleep protocol. No fence is needed for interrupt or owner-polled rings.
        let wake =
            self.drive == Drive::SqThread && (pushed != 0 || !sq.is_empty()) && sq.need_wakeup();
        if wake {
            self.enter(0, 0, EnterFlags::SQ_WAKEUP, None, false, false)?;
        }
        Ok(pushed)
    }

    fn sq_state(&mut self) -> Result<(u32, bool, bool)> {
        let ring = self
            .ring
            .as_mut()
            .ok_or(UringError::InvalidConfig("ring is closed"))?;
        let sq = ManuallyDrop::new(ring.submission());
        Ok((sq.len() as u32, sq.cq_overflow(), sq.taskrun()))
    }

    fn cq_ready(&mut self) -> Result<usize> {
        let ring = self
            .ring
            .as_mut()
            .ok_or(UringError::InvalidConfig("ring is closed"))?;
        Ok(ManuallyDrop::new(ring.completion()).len())
    }

    pub(super) fn advance_kernel(&mut self, submit_pending: bool) -> Result<()> {
        let (pending, overflow, taskrun) = self.sq_state()?;
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
                if submit_pending && pending != 0 {
                    let ring = self
                        .ring
                        .as_mut()
                        .ok_or(UringError::InvalidConfig("ring is closed"))?;
                    let sq = ManuallyDrop::new(ring.submission());
                    if sq.need_wakeup() {
                        flags |= EnterFlags::SQ_WAKEUP;
                    }
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
            self.enter(submit, 0, flags, None, false, overflow)?;
        }
        Ok(())
    }

    fn enter(
        &mut self,
        to_submit: u32,
        minimum: u32,
        flags: EnterFlags,
        args: Option<&types::SubmitArgs<'_, '_>>,
        waiting: bool,
        overflow: bool,
    ) -> Result<usize> {
        let ring = self
            .ring
            .as_mut()
            .ok_or(UringError::InvalidConfig("ring is closed"))?;
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
        let submitter = ring.submitter();
        // SAFETY: Published SQEs and their operand owners remain live. The counts
        // describe this ring's SQ, and the optional EXT_ARG value (including its
        // borrowed timespec) remains valid through this synchronous call. A null
        // signal mask has no borrowed storage. submitter preserves ring-fd identity.
        let result = unsafe {
            match args {
                Some(args) => submitter.enter(to_submit, minimum, flags.bits(), Some(args)),
                None => submitter.enter::<libc::sigset_t>(to_submit, minimum, flags.bits(), None),
            }
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
    pub fn submit(&mut self) -> Result<usize> {
        self.check_drive()?;
        if self.drive == Drive::SqThread {
            let had_staged = !self.staged.is_empty();
            let published = self.publish()?;
            self.advance_kernel(!had_staged)?;
            return Ok(published as usize);
        }
        let mut total = 0;
        let bound = self.staged.len().saturating_add(1);
        for _ in 0..bound {
            total += self.publish()? as usize;
            let (before, _, _) = self.sq_state()?;
            self.advance_kernel(true)?;
            let (after, _, _) = self.sq_state()?;
            if self.staged.is_empty() || after >= before {
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
        self.publish()?;
        if self.cq_ready()? >= min_complete as usize {
            self.advance_kernel(true)?;
        } else if let (1, Some(timeout)) = (min_complete, timeout) {
            self.kernel_wait_private(timeout)?;
        } else {
            self.enter_wait(min_complete, timeout)?;
        }
        self.harvest(self.config.max_cqe_batch, dispatcher)
    }

    pub(crate) fn kernel_wait_private(&mut self, timeout: Duration) -> Result<()> {
        self.check_drive()?;
        self.enter_wait(1, Some(timeout))
    }

    fn enter_wait(&mut self, min_complete: u32, timeout: Option<Duration>) -> Result<()> {
        let (pending, overflow, _) = self.sq_state()?;
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
        if self.drive == Drive::SqThread && pending != 0 {
            let ring = self
                .ring
                .as_mut()
                .ok_or(UringError::InvalidConfig("ring is closed"))?;
            if ManuallyDrop::new(ring.submission()).need_wakeup() {
                flags |= EnterFlags::SQ_WAKEUP;
            }
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
