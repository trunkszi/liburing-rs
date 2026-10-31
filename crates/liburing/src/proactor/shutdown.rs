//! Bounded cancellation and final-CQE draining without business-state ownership.

use std::time::Instant;

use io_uring::opcode;

use super::*;

impl Proactor {
    /// Cancels and drains operations, then unregisters owned resources and closes.
    /// Business completions are discarded; use shutdown_with to receive them.
    /// # Errors
    /// Returns submission or drain errors without freeing pending DMA storage.
    /// # Panics
    /// Does not intentionally panic.
    pub fn shutdown(&mut self) -> Result<()> {
        let mut discard = |_: Completion, _: &mut SubmissionContext<'_>| Ok(());
        self.shutdown_with(&mut discard)
    }

    /// Drains teardown completions through a caller-owned static dispatcher.
    /// Callbacks receive zero submission credit. The ring remains usable for
    /// retrying teardown after an error; application preparation stays closed.
    /// # Errors
    /// Returns submission, cancellation, bounded-drain, or dispatcher errors.
    /// # Panics
    /// Propagates dispatcher panics after acknowledging the current CQ batch.
    pub fn shutdown_with<D: CompletionDispatcher<Kind> + ?Sized, Kind>(
        &mut self,
        dispatcher: &mut D,
    ) -> Result<()> {
        if self.ring.is_none() {
            return Ok(());
        }
        if self.dispatching {
            return Err(UringError::ReentrantDispatch);
        }
        self.shutting_down = true;
        while let Some(staged) = self.staged.pop_front() {
            let Some(key) = staged.key else {
                self.pending_cancels = self.pending_cancels.saturating_sub(1);
                continue;
            };
            let operations = self
                .operations
                .as_mut()
                .ok_or(UringError::InvalidConfig("operation table is closed"))?;
            // SAFETY: This SQE never left the user-space staging queue.
            let metadata = unsafe { operations.discard_unsubmitted(key) }?;
            let original = metadata.original;
            if !metadata.keyed {
                self.identities.remove(&original);
            }
            metadata.release()?;
            let mut context = self.context()?;
            context.capacity = 0;
            let completion = Completion {
                operation_id: original,
                result: -libc::ECANCELED,
                flags: 0,
            };
            context.current_completion = Some(completion);
            dispatcher.dispatch(completion, &mut context)?;
        }
        self.submit()?;
        let mut cancel_issued = self.shutdown_cancel_issued || self.cancel_armed;
        let limit = self
            .config
            .shutdown_stall_timeout
            .unwrap_or_else(|| self.mode.default_shutdown_stall());
        let mut stalled_since: Option<Instant> = None;
        loop {
            // A transient enter failure can leave published SQEs unconsumed;
            // owner-polled progress must retry submission as well as reap CQEs.
            if self.mode == ProactorMode::IoPoll
                && self
                    .ring
                    .as_mut()
                    .is_some_and(|ring| !ManuallyDrop::new(ring.submission()).is_empty())
            {
                self.submit()?;
            }
            let harvested = self.poll_completions(usize::MAX, dispatcher)?;
            if self.operation_count() == 0 && !self.cancel_armed && self.pending_cancels == 0 {
                // All target DMA and control requests retired before unregistering.
                drop(self.resources.take());
                drop(self.operations.take());
                drop(self.ring.take());
                return Ok(());
            }
            if harvested != 0 {
                stalled_since = None;
            }
            if self.mode.supports_cancellation() && !cancel_issued {
                let mut raw = RawSqe::from_entry(
                    opcode::AsyncCancel::new(0)
                        .build()
                        .user_data(INTERNAL_CANCEL),
                );
                raw.operation_flags = 1 | 4;
                let entry = raw.into_entry();
                let ring = self
                    .ring
                    .as_mut()
                    .ok_or(UringError::InvalidConfig("ring is closed"))?;
                let mut sq = ring.submission();
                // SAFETY: This control entry holds no raw DMA operands; target
                // metadata remains retained until its own final completion.
                if unsafe { sq.push(&entry) }.is_ok() {
                    self.cancel_armed = true;
                    self.shutdown_cancel_issued = true;
                    cancel_issued = true;
                }
                drop(sq);
                self.submit()?;
                if cancel_issued {
                    continue;
                }
            }
            if harvested != 0 {
                continue;
            }
            let since = stalled_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= limit {
                return Err(UringError::Wait(libc::ETIMEDOUT));
            }
            if self.mode.uses_iopoll() && !self.mode.uses_sq_thread() {
                core::hint::spin_loop();
            } else {
                self.kernel_wait_private(Duration::from_millis(10))?;
            }
        }
    }
}

impl Drop for Proactor {
    fn drop(&mut self) {
        if self.shutdown().is_err() {
            // Failure is not proof of target retirement. Retain DMA owners rather
            // than allowing their allocators or raw ring pointers to be reused.
            if let Some(resources) = self.resources.take() {
                std::mem::forget(resources);
            }
            if let Some(operations) = self.operations.take() {
                std::mem::forget(operations);
            }
            drop(self.ring.take());
        }
    }
}

#[cfg(test)]
#[path = "../../tests/proactor/shutdown.rs"]
mod tests;
