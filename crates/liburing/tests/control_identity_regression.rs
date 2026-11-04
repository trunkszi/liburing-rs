//! Kernel identity translation for poll and timeout control operations.
use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use liburing::{
    Completion, OperationId, OperationPayload, Proactor, Result, SubmissionContext, SubsystemId,
    UringError, ops,
};

fn id(value: u64) -> OperationId {
    OperationId::pack(SubsystemId(3), OperationPayload(value))
}
fn poll_ring() -> Result<(Proactor, OwnedFd)> {
    let ring = Proactor::builder().entries(8).build()?;
    // SAFETY: eventfd returns an owned descriptor, checked before adoption.
    let raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: This successful fresh descriptor has no other owner.
    Ok((ring, unsafe { OwnedFd::from_raw_fd(raw) }))
}
fn wait_for(ring: &mut Proactor, target: OperationId) -> Result<i32> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut result = None;
    while result.is_none() {
        assert!(Instant::now() < deadline, "missing control completion");
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |c: Completion, _: &mut SubmissionContext<'_>| {
                if c.operation_id == target {
                    result = Some(c.result);
                }
                Ok(())
            },
        )?;
    }
    result.ok_or(UringError::InvalidConfig("missing result"))
}
#[test]
fn poll_user_data_update_is_rejected_without_losing_live_target() -> Result<()> {
    let (mut ring, event) = poll_ring()?;
    ring.prepare_sqe_with(id(1), |sqe| {
        // SAFETY: Exclusive SQE; event remains alive through shutdown.
        unsafe { ops::prep_poll_multishot(sqe, event.as_raw_fd(), libc::POLLIN as u32) }
    })?;
    ring.submit()?;
    let error = ring.prepare_sqe_with(id(2), |sqe| {
        // SAFETY: Exclusive SQE, target identity names the live poll.
        unsafe { ops::prep_poll_update(sqe, id(1).raw(), id(9).raw(), 0, 1 << 2) }
    });
    assert_eq!(
        error,
        Err(UringError::InvalidPreparedSqe(
            "poll user_data update is not supported on Proactor-managed operations"
        ))
    );
    assert_eq!(ring.operation_count(), 1);
    ring.shutdown()
}
#[test]
fn poll_event_updates_translate_pollout_and_pollpri_targets() -> Result<()> {
    for events in [libc::POLLIN | libc::POLLOUT, libc::POLLIN | libc::POLLPRI] {
        let (mut ring, event) = poll_ring()?;
        ring.prepare_sqe_with(id(1), |sqe| {
            // SAFETY: Exclusive SQE; event is retained through shutdown.
            unsafe { ops::prep_poll_multishot(sqe, event.as_raw_fd(), libc::POLLIN as u32) }
        })?;
        ring.submit()?;
        ring.prepare_sqe_with(id(2), |sqe| {
            // SAFETY: Exclusive SQE, update keeps the live poll's identity.
            unsafe { ops::prep_poll_update(sqe, id(1).raw(), 0, events as u32, 1 << 1) }
        })?;
        assert_eq!(wait_for(&mut ring, id(2))?, 0);
        assert_eq!(ring.operation_count(), 1);
        assert!(ring.cancel(id(1))?);
        assert_eq!(wait_for(&mut ring, id(1))?, -libc::ECANCELED);
        ring.shutdown()?;
    }
    Ok(())
}
#[test]
fn timeout_remove_and_update_translate_target_identity() -> Result<()> {
    for update in [false, true] {
        let mut ring = Proactor::builder().entries(8).build()?;
        let initial = ops::KernelTimespec {
            tv_sec: 30,
            tv_nsec: 0,
        };
        let replacement = ops::KernelTimespec {
            tv_sec: 60,
            tv_nsec: 0,
        };
        ring.prepare_sqe_with(id(1), |sqe| {
            // SAFETY: Timespec stays alive through final completion and shutdown.
            unsafe { ops::prep_timeout(sqe, &initial, 0, 0) }
        })?;
        ring.submit()?;
        ring.prepare_sqe_with(id(2), |sqe| {
            // SAFETY: Exclusive SQE; replacement remains alive until shutdown.
            unsafe {
                if update {
                    ops::prep_timeout_update(sqe, &replacement, id(1).raw(), 0)
                } else {
                    ops::prep_timeout_remove(sqe, id(1).raw(), 0)
                }
            }
        })?;
        assert_eq!(wait_for(&mut ring, id(2))?, 0);
        if update {
            assert_eq!(ring.operation_count(), 1);
            assert!(ring.cancel(id(1))?);
            assert_eq!(wait_for(&mut ring, id(1))?, -libc::ECANCELED);
        }
        ring.shutdown()?;
    }
    Ok(())
}

#[test]
fn unknown_timeout_control_target_is_rejected_before_staging() -> Result<()> {
    let mut ring = Proactor::builder().entries(8).build()?;
    let replacement = ops::KernelTimespec {
        tv_sec: 60,
        tv_nsec: 0,
    };
    for update in [false, true] {
        let result = ring.prepare_sqe_with(id(2), |sqe| {
            // SAFETY: Exclusive SQE; replacement stays alive until shutdown.
            unsafe {
                if update {
                    ops::prep_timeout_update(sqe, &replacement, id(1).raw(), 0)
                } else {
                    ops::prep_timeout_remove(sqe, id(1).raw(), 0)
                }
            }
        });
        assert_eq!(result, Err(UringError::UnknownOperation(id(1))));
        assert_eq!(ring.operation_count(), 0);
    }
    ring.shutdown()
}
