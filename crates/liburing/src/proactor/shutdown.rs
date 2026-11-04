//! Bounded cancellation and final-CQE draining without business-state ownership.

use std::time::Instant;

use io_uring::opcode;

use super::*;

struct DispatchGuard<'a>(&'a mut bool);
impl<'a> DispatchGuard<'a> {
    fn new(dispatching: &'a mut bool) -> Self {
        *dispatching = true;
        Self(dispatching)
    }
}
impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        *self.0 = false;
    }
}

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
            let id = OperationId::from_raw(staged.sqe.user_data);
            if id.subsystem_id() == SubsystemId::INTERNAL {
                self.pending_cancels = self.pending_cancels.saturating_sub(1);
                continue;
            }
            let key = OperationKey::from_payload(id.payload())?;
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
            let mut context = SubmissionContext {
                staged: &mut self.staged,
                capacity: 0,
                operations: self
                    .operations
                    .as_mut()
                    .ok_or(UringError::InvalidConfig("operation table is closed"))?,
                identities: &mut self.identities,
                resources: self
                    .resources
                    .as_ref()
                    .ok_or(UringError::InvalidConfig("resources are closed"))?,
                pending_cancels: &mut self.pending_cancels,
                current_completion: None,
                admission: OpcodeSet::for_mode(self.mode),
                cancellable: self.mode.supports_cancellation(),
                mode_name: self.mode.name(),
            };
            let completion = Completion {
                operation_id: original,
                result: -libc::ECANCELED,
                flags: 0,
            };
            context.current_completion = Some(completion);
            let _guard = DispatchGuard::new(&mut self.dispatching);
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
                self.unregister_ring_fd();
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
        let shutdown_failed = self.shutdown().is_err();
        self.unregister_ring_fd();
        if shutdown_failed {
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

#[cfg(test)]
mod regressions {
    use super::*;

    #[test]
    fn guard_resets_after_errors_and_unwind() {
        let mut dispatching = false;
        let error = UringError::InvalidConfig("callback failed");
        let mut fail = || -> Result<()> {
            let guard = DispatchGuard::new(&mut dispatching);
            assert!(*guard.0);
            Err(error)
        };
        let attempt = fail();
        assert_eq!(attempt, Err(error));
        assert!(!dispatching);
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = DispatchGuard::new(&mut dispatching);
            assert!(*guard.0);
            panic!("callback unwound");
        }));
        assert!(attempt.is_err());
        assert!(!dispatching);
    }

    #[test]
    fn dispatch_flag_blocks_nested_drive_calls() -> Result<()> {
        let mut proactor = Proactor::new(ProactorConfig::default())?;
        let mut discard = |_: Completion, _: &mut SubmissionContext<'_>| Ok(());
        proactor.dispatching = true;
        assert_eq!(proactor.submit(), Err(UringError::ReentrantDispatch));
        assert_eq!(
            proactor.tick(&mut discard),
            Err(UringError::ReentrantDispatch)
        );
        assert_eq!(
            proactor.poll_completions(1, &mut discard),
            Err(UringError::ReentrantDispatch)
        );
        assert_eq!(
            proactor.wait_completions(0, None, &mut discard),
            Err(UringError::ReentrantDispatch)
        );
        assert_eq!(
            proactor.shutdown_with(&mut discard),
            Err(UringError::ReentrantDispatch)
        );
        proactor.dispatching = false;
        proactor.shutdown()
    }

    #[test]
    fn shutdown_retry_retains_registered_ring() -> Result<()> {
        let mut proactor = Proactor::new(ProactorConfig {
            mode: ProactorMode::io_poll(),
            shutdown_stall_timeout: Some(Duration::ZERO),
            ..Default::default()
        })?;
        assert!(proactor.has_registered_ring_fd());
        let registered = proactor.registered_ring_offset;
        let key = proactor
            .operations
            .as_mut()
            .ok_or(UringError::InvalidConfig("missing operation table"))?
            .insert(
                TrackedOperation {
                    original: OperationId::pack(SubsystemId(1), crate::OperationPayload(1)),
                    keyed: true,
                    buffer: None,
                    socket: None,
                },
                crate::operation_slab::OperationKind::Single,
            )?;
        for _ in 0..2 {
            assert_eq!(proactor.shutdown(), Err(UringError::Wait(libc::ETIMEDOUT)));
            assert_eq!(proactor.registered_ring_offset, registered);
            assert!(proactor.ring.is_some());
            assert!(!proactor.dispatching);
            assert_eq!(proactor.operation_count(), 1);
        }
        let operations = proactor
            .operations
            .as_mut()
            .ok_or(UringError::InvalidConfig("missing operation table"))?;
        assert!(operations.complete(key, 0, 0)?);
        operations.remove(key)?.release()?;
        proactor.shutdown()?;
        assert!(!proactor.has_registered_ring_fd());
        assert!(proactor.ring.is_none());
        Ok(())
    }
}
