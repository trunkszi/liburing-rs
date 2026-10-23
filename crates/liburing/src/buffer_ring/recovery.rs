//! Bounded recovery records for exhausted multishot receives.

use std::{cell::Cell, os::fd::RawFd};

use super::invalid;
use crate::{
    error::{Result, UringError},
    id::{BufferGroupId, OperationId},
};

#[derive(Clone, Copy)]
struct DepletedRecv {
    fd: RawFd,
    flags: i32,
    operation_id: OperationId,
    deferred: bool,
}

pub(super) struct DepletedRecvs {
    records: Box<[Cell<Option<DepletedRecv>>]>,
    rearming: Cell<bool>,
    returned: Cell<u64>,
    credits: Cell<u64>,
    started: Cell<bool>,
}

struct RearmGuard<'a>(&'a Cell<bool>);

impl Drop for RearmGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl DepletedRecvs {
    pub(super) fn new(capacity: u16) -> Self {
        Self {
            records: (0..capacity).map(|_| Cell::new(None)).collect(),
            rearming: Cell::new(false),
            returned: Cell::new(0),
            credits: Cell::new(0),
            started: Cell::new(false),
        }
    }

    pub(super) fn mark(
        &self,
        fd: RawFd,
        flags: i32,
        operation_id: OperationId,
        returned: u64,
    ) -> Result<()> {
        if fd < 0 {
            return Err(invalid(
                "depleted receive requires a nonnegative descriptor",
            ));
        }
        let mut vacant = None;
        for record in &self.records {
            match record.get() {
                Some(previous) if previous.operation_id == operation_id => {
                    return if previous.fd == fd && previous.flags == flags {
                        Ok(())
                    } else {
                        Err(invalid(
                            "depleted operation ID has conflicting receive parameters",
                        ))
                    };
                }
                None if vacant.is_none() => vacant = Some(record),
                _ => {}
            }
        }
        if !self.started.get() && !self.records.iter().any(|record| record.get().is_some()) {
            self.returned.set(returned);
            self.credits.set(0);
        }
        let record = vacant.ok_or(UringError::Syscall {
            operation: "mark_depleted_recv",
            errno: libc::ENOSPC,
        })?;
        record.set(Some(DepletedRecv {
            fd,
            flags,
            operation_id,
            deferred: self.rearming.get(),
        }));
        Ok(())
    }

    pub(super) fn forget(&self, operation_id: OperationId) -> Result<bool> {
        if self.rearming.get() {
            return Err(UringError::ReentrantDispatch);
        }
        for record in &self.records {
            if record
                .get()
                .is_some_and(|pending| pending.operation_id == operation_id)
            {
                record.set(None);
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn rearm(
        &self,
        returned: u64,
        group: BufferGroupId,
        mut available: impl FnMut() -> Result<u64>,
        mut submitter: impl FnMut(RawFd, i32, OperationId, BufferGroupId) -> Result<()>,
    ) -> Result<usize> {
        if self.rearming.replace(true) {
            return Err(UringError::ReentrantDispatch);
        }
        let _guard = RearmGuard(&self.rearming);
        for record in &self.records {
            if let Some(mut pending) = record.get() {
                pending.deferred = false;
                record.set(Some(pending));
            }
        }
        let replenished = returned.wrapping_sub(self.returned.replace(returned));
        self.credits
            .set(self.credits.get().saturating_add(replenished));
        if self.records.iter().any(|record| record.get().is_some()) {
            let count = available()?;
            // Inventory can include earlier staged reservations. After the first
            // callback succeeds, queries may only reduce the remaining quota.
            self.credits.set(if self.started.get() {
                self.credits.get().min(count)
            } else {
                count
            });
        }
        let mut staged = 0;
        for record in &self.records {
            if let Some(pending) = record.get() {
                if pending.deferred || self.credits.get() == 0 {
                    continue;
                }
                submitter(pending.fd, pending.flags, pending.operation_id, group)?;
                record.set(None);
                self.credits.set(self.credits.get() - 1);
                self.started.set(true);
                staged += 1;
            }
        }
        Ok(staged)
    }
}

#[cfg(test)]
mod unit {
    use super::{DepletedRecvs, invalid};
    use crate::{
        error::UringError,
        id::{BufferGroupId, OperationId},
    };
    fn unavailable() -> crate::error::Result<u64> {
        Ok(0)
    }
    fn reject(_: i32, _: i32, _: OperationId, _: BufferGroupId) -> crate::error::Result<()> {
        panic!("no receive may be staged");
    }
    #[test]
    fn scenario_buffers_returned_before_depletion_and_query_failure() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(2);
        let group = BufferGroupId(2);
        let id = OperationId::from_raw(3);
        pending.mark(10, 0, id, 4)?;
        pending.mark(11, 0, OperationId::from_raw(4), 4)?;
        let status_failure = UringError::syscalls("buf_ring_head", libc::EIO);
        assert_eq!(
            pending.rearm(4, group, || Err(status_failure), reject),
            Err(status_failure)
        );
        assert_eq!(pending.rearm(4, group, unavailable, reject), Ok(0));
        let stage = |fd, _, operation, _| {
            assert_eq!((fd, operation), (10, id));
            Ok(())
        };
        assert_eq!(pending.rearm(4, group, || Ok(1), stage), Ok(1));
        assert_eq!(pending.rearm(4, group, || Ok(1), reject), Ok(0));
        Ok(())
    }
    #[test]
    fn scenario_mixed_epoch_query_retry_reserves_once() -> crate::error::Result<()> {
        for (reverse, inventory) in [(false, 1), (false, 2), (true, 1), (true, 2)] {
            let pending = DepletedRecvs::new(2);
            let (first, second, group) = (OperationId(1), OperationId(2), BufferGroupId(3));
            if reverse {
                pending.mark(11, 0, second, 1)?;
            }
            pending.mark(10, 0, first, 1)?;
            if reverse {
                assert!(pending.forget(second)?);
            }
            pending.mark(11, 0, second, 2)?;
            let error = invalid("inventory query failed");
            assert_eq!(pending.rearm(2, group, || Err(error), reject), Err(error));
            assert_eq!(pending.credits.get(), 1);
            let mut seen = Vec::new();
            let submit = |_, _, operation, _| {
                if seen.len() == 1 {
                    return Err(error);
                }
                seen.push(operation);
                Ok(())
            };
            let result = pending.rearm(2, group, || Ok(inventory), submit);
            assert_eq!(result, if inventory == 1 { Ok(1) } else { Err(error) });
            assert_eq!(pending.credits.get(), inventory - 1);
            let epoch = if inventory == 1 { 3 } else { 2 };
            let submit = |_, _, operation, _| {
                seen.push(operation);
                Ok(())
            };
            assert_eq!(pending.rearm(epoch, group, || Ok(1), submit), Ok(1));
            assert_eq!(
                seen,
                if reverse {
                    [second, first]
                } else {
                    [first, second]
                }
            );
            pending.mark(12, 0, OperationId(4), epoch)?;
            assert_eq!(pending.rearm(epoch, group, || Ok(2), reject), Ok(0));
        }
        Ok(())
    }
    #[test]
    fn scenario_multishot_consumption_invalidates_leftover_credit() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(2);
        let (id, group) = (OperationId(1), BufferGroupId(3));
        pending.mark(10, 0, id, 0)?;
        assert_eq!(
            pending.rearm(0, group, || Ok(2), |_, _, _, _| Ok(())),
            Ok(1)
        );
        assert_eq!(pending.credits.get(), 1);
        pending.mark(10, 0, id, 0)?;
        assert_eq!(pending.rearm(0, group, unavailable, reject), Ok(0));
        assert_eq!(pending.credits.get(), 0);
        assert_eq!(
            pending.rearm(2, group, || Ok(2), |_, _, _, _| Ok(())),
            Ok(1)
        );
        Ok(())
    }
    #[test]
    fn lifecycle_scenario_depleted_receive_retry() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(1);
        let operation_id = OperationId::from_raw(7);
        let group = BufferGroupId(9);
        pending.mark(12, 3, operation_id, 10)?;
        pending.mark(12, 3, operation_id, 11)?;
        assert!(pending.mark(13, 3, operation_id, 10).is_err());
        assert!(pending.mark(13, 0, OperationId::from_raw(8), 10).is_err());
        assert_eq!(pending.rearm(10, group, unavailable, reject), Ok(0));
        assert!(
            pending
                .rearm(11, group, || Ok(1), |_, _, _, _| Err(invalid("SQ full")))
                .is_err()
        );
        let mut calls = 0;
        let submit = |fd, flags, id, actual_group| {
            calls += 1;
            assert_eq!((fd, flags, id, actual_group), (12, 3, operation_id, group));
            Ok(())
        };
        assert_eq!(pending.rearm(11, group, || Ok(1), submit), Ok(1));
        assert_eq!(calls, 1);
        assert_eq!(pending.rearm(12, group, unavailable, reject), Ok(0));
        assert_eq!(pending.forget(operation_id), Ok(false));
        Ok(())
    }
    #[test]
    fn scenario_callback_depletion_waits_for_new_return() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(2);
        let first = OperationId::from_raw(1);
        let second = OperationId::from_raw(2);
        let group = BufferGroupId(3);
        pending.mark(10, 0, first, 0)?;
        assert_eq!(
            pending.rearm(
                1,
                group,
                || Ok(1),
                |_, _, id, _| {
                    assert_eq!(id, first);
                    pending.mark(11, 0, second, 2)?;
                    Ok(())
                }
            ),
            Ok(1)
        );
        assert_eq!(pending.rearm(2, group, unavailable, reject), Ok(0));
        assert_eq!(
            pending.rearm(
                3,
                group,
                || Ok(1),
                |fd, _, id, _| {
                    assert_eq!((fd, id), (11, second));
                    Ok(())
                }
            ),
            Ok(1)
        );
        Ok(())
    }
    #[test]
    fn lifecycle_scenario_reentrant_and_panicking_recovery() -> crate::error::Result<()> {
        let pending = DepletedRecvs::new(2);
        let first = OperationId::from_raw(1);
        let second = OperationId::from_raw(2);
        let group = BufferGroupId(4);
        pending.mark(10, 0, first, 0)?;
        pending.mark(11, 0, second, 0)?;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pending.rearm(
                1,
                group,
                || Ok(1),
                |_, _, id, _| {
                    assert_eq!(
                        pending.rearm(1, group, unavailable, |_, _, _, _| Ok(())),
                        Err(UringError::ReentrantDispatch)
                    );
                    assert_eq!(pending.forget(id), Err(UringError::ReentrantDispatch));
                    pending.mark(10, 0, id, 1)?;
                    panic!("callback failed before staging");
                },
            )
        }));
        assert!(panic.is_err());
        assert_eq!(pending.forget(second), Ok(true));
        assert_eq!(pending.forget(second), Ok(false));
        assert_eq!(
            pending.rearm(
                1,
                group,
                || Ok(1),
                |fd, _, id, _| {
                    assert_eq!((fd, id), (10, first));
                    Ok(())
                }
            ),
            Ok(1)
        );
        Ok(())
    }
}
