//! Bounded cancellation and final-CQE draining without business-state ownership.

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
        let mut idle_waits = 0;
        loop {
            let harvested = self.poll_completions(usize::MAX, dispatcher)?;
            if self.operation_count() == 0 && !self.cancel_armed && self.pending_cancels == 0 {
                // All target DMA and control requests retired before unregistering.
                drop(self.resources.take());
                drop(self.operations.take());
                drop(self.ring.take());
                return Ok(());
            }
            if !cancel_issued {
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
                continue;
            }
            if harvested != 0 {
                continue;
            }
            if idle_waits == 32 {
                return Err(UringError::Wait(libc::ETIMEDOUT));
            }
            idle_waits += 1;
            self.wait_completions(1, Some(Duration::from_millis(10)), dispatcher)?;
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
mod tests {
    use super::*;

    #[test]
    fn global_cancel_survives_dispatch_failure_without_reissuing_on_retry() -> Result<()> {
        let timeout = crate::ops::Timeout::new(Duration::from_secs(60))?;
        let mut proactor = Proactor::new(ProactorConfig {
            entries: 64,
            operation_capacity: 64,
            staged_capacity: 64,
            max_cqe_batch: 1,
            ..ProactorConfig::default()
        })?;
        for payload in 0..48 {
            proactor.prepare_sqe_with(
                OperationId::pack(SubsystemId(1), crate::OperationPayload(payload)),
                |sqe| {
                    // SAFETY: The immutable timeout owner precedes the ring and outlives all CQEs.
                    unsafe { timeout.prepare(sqe) };
                },
            )?;
        }
        proactor.submit()?;
        let mut completed = 0;
        let error =
            proactor.shutdown_with(&mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
                assert_eq!(cqe.result, -libc::ECANCELED);
                completed += 1;
                Err(UringError::InvalidConfig("dispatcher interrupted teardown"))
            });
        assert_eq!(
            error,
            Err(UringError::InvalidConfig("dispatcher interrupted teardown"))
        );
        assert!(proactor.shutdown_cancel_issued);
        proactor.shutdown_with(&mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.result, -libc::ECANCELED);
            completed += 1;
            Ok(())
        })?;
        assert_eq!(completed, 48);
        assert!(proactor.shutdown_cancel_issued);
        assert!(!proactor.cancel_armed);
        assert!(proactor.is_idle());
        Ok(())
    }
}
