//! Constant-time completion routing and bounded callback submissions.

use std::collections::VecDeque;

use liburing_sys::io_uring_sqe;

use crate::{
    error::{Result, UringError},
    id::{OpId, SubsystemId},
};

/// A copied completion whose lifetime is independent of the kernel CQ ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    /// Submission identity including its subsystem and local payload.
    pub op_id: OpId,
    /// Kernel result, with negative values containing a negated errno.
    pub result: i32,
    /// Kernel completion flags, including buffer selection and continuation bits.
    pub flags: u32,
}

pub(crate) struct StagedSqe {
    pub(crate) sqe: io_uring_sqe,
}

pub(crate) fn validate_prepared_sqe(sqe: &io_uring_sqe) -> Result<()> {
    if u32::from(sqe.flags) & liburing_sys::IOSQE_IO_DRAIN != 0 {
        return Err(UringError::InvalidPreparedSqe(
            "drain operations can wait forever on the internal wakeup poll",
        ));
    }
    if u32::from(sqe.flags) & (liburing_sys::IOSQE_IO_LINK | liburing_sys::IOSQE_IO_HARDLINK) != 0 {
        return Err(UringError::InvalidPreparedSqe(
            "linked operations cannot preserve chains across staged submissions",
        ));
    }
    if u32::from(sqe.flags) & liburing_sys::IOSQE_CQE_SKIP_SUCCESS != 0 {
        return Err(UringError::InvalidConfig(
            "operations must produce their final completion",
        ));
    }
    if u32::from(sqe.opcode) == liburing_sys::IORING_OP_MSG_RING {
        return Err(UringError::InvalidConfig(
            "message-ring completions bypass operation accounting",
        ));
    }
    Ok(())
}

/// A callback's bounded submission capability, without access to the ring.
///
/// SQEs enter an already allocated queue and cannot be submitted to the kernel
/// until the proactor has acknowledged the completion being dispatched.
pub struct SubmissionContext<'a> {
    staged: &'a mut VecDeque<StagedSqe>,
    capacity: usize,
}

impl<'a> SubmissionContext<'a> {
    pub(crate) fn new(staged: &'a mut VecDeque<StagedSqe>, capacity: usize) -> Self {
        Self { staged, capacity }
    }

    /// Stage one operation after running its preparation callback.
    ///
    /// The callback receives a valid zeroed SQE only for the duration of the
    /// call. Any buffers referenced by its fields must remain alive until the
    /// operation's final CQE, including after cancellation is requested.
    ///
    /// # Errors
    /// Returns [`UringError::SqRingFull`] without invoking `prepare` if the queue
    /// has reached its fixed capacity. Rejects the internal subsystem with
    /// `InvalidSubsystemId` and the all-ones fallback timeout sentinel with
    /// `InvalidPayload`.
    /// Rejects operations that skip final CQEs or inject message-ring CQEs, and
    /// returns `InvalidPreparedSqe` for linked operations because staged
    /// submissions cannot preserve chains across kernel submission batches.
    /// `IOSQE_IO_DRAIN` also returns `InvalidPreparedSqe`: the internal wakeup
    /// poll can remain outstanding indefinitely.
    ///
    /// # Panics
    /// Propagates a panic from `prepare`; the operation is not staged.
    pub fn prepare_sqe_with<F>(&mut self, op_id: OpId, prepare: F) -> Result<()>
    where
        F: FnOnce(*mut io_uring_sqe),
    {
        if op_id.subsystem_id() == SubsystemId::INTERNAL {
            return Err(UringError::InvalidSubsystemId(0));
        }
        if op_id.raw() == u64::MAX {
            return Err(UringError::InvalidPayload(op_id.raw()));
        }
        if self.staged.len() >= self.capacity {
            return Err(UringError::SqRingFull);
        }
        // SAFETY: An SQE consists solely of integers and C unions whose zero
        // representations are valid; preparation fills opcode-specific fields.
        let mut sqe = unsafe { core::mem::zeroed::<io_uring_sqe>() };
        prepare(&raw mut sqe);
        validate_prepared_sqe(&sqe)?;
        sqe.user_data = op_id.raw();
        self.staged.push_back(StagedSqe { sqe });
        Ok(())
    }

    /// Return how many additional operations can be staged in this context.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        self.capacity.saturating_sub(self.staged.len())
    }
}

/// A subsystem receiving its own completions on the ring's owner thread.
pub trait SubsystemHandler {
    /// Consume one completion and optionally stage follow-up operations.
    ///
    /// # Errors
    /// Returns a subsystem failure to stop the current dispatch turn. The
    /// completion has already been consumed and is never delivered twice.
    ///
    /// # Panics
    /// Implementations should not panic; a panic unwinds the dispatch turn.
    fn on_completion(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()>;
}

/// A fixed 256-slot table indexed directly by the subsystem byte.
///
/// Slot zero belongs to the proactor's internal wakeup operations. User handlers
/// occupy slots 1 through 255 and are never visited by a linear dispatch scan.
pub struct SubsystemRegistry {
    handlers: [Option<Box<dyn SubsystemHandler>>; 256],
    len: usize,
}

impl SubsystemRegistry {
    /// Construct an empty table without allocating handler storage.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: std::array::from_fn(|_| None),
            len: 0,
        }
    }

    /// Install a handler in a user subsystem slot.
    ///
    /// Handler boxing occurs at registration, outside completion dispatch.
    ///
    /// # Errors
    /// Rejects the internal identifier, an occupied slot, or exhausted capacity.
    ///
    /// # Panics
    /// This function does not panic except on allocation failure.
    pub fn register<H>(&mut self, id: SubsystemId, handler: H) -> Result<()>
    where
        H: SubsystemHandler + 'static,
    {
        if id == SubsystemId::INTERNAL {
            return Err(UringError::InvalidSubsystemId(id.raw()));
        }
        let slot = &mut self.handlers[usize::from(id.raw())];
        if slot.is_some() {
            return Err(UringError::SubsystemAlreadyRegistered(id.raw()));
        }
        if self.len == 255 {
            return Err(UringError::SubsystemCapacityExceeded);
        }
        *slot = Some(Box::new(handler));
        self.len += 1;
        Ok(())
    }

    /// Remove a handler after its caller has retired all associated operations.
    ///
    /// This table owns handlers, not kernel buffer lifetimes. The caller must
    /// keep submitted buffers alive even when their handler is removed.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidSubsystemId`] for a vacant or internal slot.
    ///
    /// # Panics
    /// Propagates a panic from the removed handler's destructor.
    pub fn unregister(&mut self, id: SubsystemId) -> Result<()> {
        if id == SubsystemId::INTERNAL {
            return Err(UringError::InvalidSubsystemId(id.raw()));
        }
        let slot = &mut self.handlers[usize::from(id.raw())];
        if slot.is_none() {
            return Err(UringError::InvalidSubsystemId(id.raw()));
        }
        let handler = slot.take();
        self.len -= 1;
        drop(handler);
        Ok(())
    }

    /// Return whether a user slot currently has a handler.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn contains(&self, id: SubsystemId) -> bool {
        self.handlers[usize::from(id.raw())].is_some()
    }

    /// Return the number of registered user handlers.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return whether there are no user handlers.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        let id = completion.op_id.subsystem_id();
        let handler = self.handlers[usize::from(id.raw())]
            .as_mut()
            .ok_or(UringError::InvalidSubsystemId(id.raw()))?;
        handler.on_completion(completion, submissions)
    }
}

impl Default for SubsystemRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod unit_scenario_tests {
    use std::{cell::Cell, rc::Rc};

    use super::*;
    use crate::id::OpPayload;

    fn completion(id: u8, payload: u64) -> Completion {
        Completion {
            op_id: OpId::pack(
                SubsystemId::new_unchecked(id),
                OpPayload::new_unchecked(payload),
            ),
            result: 0,
            flags: 0,
        }
    }

    #[test]
    fn staging_rejects_link_flags_without_consuming_capacity() -> Result<()> {
        let mut staged = VecDeque::with_capacity(1);
        let mut context = SubmissionContext::new(&mut staged, 1);
        let op_id = completion(1, 1).op_id;
        for flags in [
            liburing_sys::IOSQE_IO_LINK,
            liburing_sys::IOSQE_IO_HARDLINK,
            liburing_sys::IOSQE_IO_LINK | liburing_sys::IOSQE_IO_HARDLINK,
        ] {
            let result = context.prepare_sqe_with(op_id, |sqe| {
                // SAFETY: The callback exclusively borrows an initialized SQE.
                unsafe { (*sqe).flags = flags as u8 };
            });
            assert_eq!(
                result,
                Err(UringError::InvalidPreparedSqe(
                    "linked operations cannot preserve chains across staged submissions"
                ))
            );
            assert_eq!(context.remaining_capacity(), 1);
        }
        context.prepare_sqe_with(op_id, |_| {})?;
        assert_eq!(context.remaining_capacity(), 0);
        Ok(())
    }

    #[test]
    fn staging_rejects_drain_flags_without_consuming_capacity() -> Result<()> {
        let mut staged = VecDeque::with_capacity(1);
        let mut context = SubmissionContext::new(&mut staged, 1);
        let op_id = completion(1, 1).op_id;
        for flags in [
            liburing_sys::IOSQE_IO_DRAIN,
            liburing_sys::IOSQE_IO_DRAIN | liburing_sys::IOSQE_IO_LINK,
            liburing_sys::IOSQE_IO_DRAIN | liburing_sys::IOSQE_IO_HARDLINK,
        ] {
            let result = context.prepare_sqe_with(op_id, |sqe| {
                // SAFETY: The callback exclusively borrows an initialized SQE.
                unsafe { (*sqe).flags = flags as u8 };
            });
            assert!(matches!(result, Err(UringError::InvalidPreparedSqe(_))));
            assert_eq!(context.remaining_capacity(), 1);
        }
        context.prepare_sqe_with(op_id, |_| {})?;
        assert_eq!(context.remaining_capacity(), 0);
        Ok(())
    }

    #[test]
    fn bounded_staging_rejects_before_preparation_and_stamps_identity() -> Result<()> {
        let mut staged = VecDeque::with_capacity(1);
        let entry = completion(255, 41);
        let invoked = Cell::new(false);
        {
            let mut context = SubmissionContext::new(&mut staged, 1);
            for raw in [0, 1, 2] {
                assert_eq!(
                    context.prepare_sqe_with(OpId::from_raw(raw), |_| invoked.set(true)),
                    Err(UringError::InvalidSubsystemId(0))
                );
            }
            assert_eq!(
                context.prepare_sqe_with(OpId::from_raw(u64::MAX), |_| invoked.set(true)),
                Err(UringError::InvalidPayload(u64::MAX))
            );
            context.prepare_sqe_with(entry.op_id, |sqe| {
                // SAFETY: The callback receives an exclusively borrowed live SQE.
                unsafe { (*sqe).user_data = u64::MAX };
            })?;
            assert_eq!(context.remaining_capacity(), 0);
            let rejected = context.prepare_sqe_with(entry.op_id, |_| invoked.set(true));
            assert_eq!(rejected, Err(UringError::SqRingFull));
        }
        assert!(!invoked.get());
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].sqe.user_data, entry.op_id.raw());
        Ok(())
    }

    struct PanicOnce {
        calls: Rc<Cell<usize>>,
    }

    impl SubsystemHandler for PanicOnce {
        fn on_completion(&mut self, _: Completion, _: &mut SubmissionContext<'_>) -> Result<()> {
            let calls = self.calls.get();
            self.calls.set(calls + 1);
            assert_ne!(calls, 0, "controlled callback panic");
            Ok(())
        }
    }

    #[test]
    fn registry_preserves_handler_after_callback_unwinds() -> Result<()> {
        let id = SubsystemId::new_unchecked(255);
        let calls = Rc::new(Cell::new(0));
        let mut registry = SubsystemRegistry::new();
        registry.register(
            id,
            PanicOnce {
                calls: Rc::clone(&calls),
            },
        )?;
        let mut staged = VecDeque::with_capacity(1);
        let mut context = SubmissionContext::new(&mut staged, 1);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            registry.dispatch(completion(255, 1), &mut context)
        }));
        assert!(unwound.is_err());
        assert!(registry.contains(id));
        registry.dispatch(completion(255, 2), &mut context)?;
        assert_eq!(calls.get(), 2);
        registry.unregister(id)?;
        assert!(registry.is_empty());
        assert_eq!(
            registry.dispatch(completion(255, 3), &mut context),
            Err(UringError::InvalidSubsystemId(255))
        );
        Ok(())
    }
}
