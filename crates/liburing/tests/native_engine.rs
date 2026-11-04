//! Public native engine cutover contracts.
use liburing::{Completion, OperationId};
#[test]
fn completion_accessors_preserve_public_fields() {
    let completion = Completion {
        operation_id: OperationId::from_raw(0x0100_0000_0000_0007),
        result: -5,
        flags: 2,
    };
    assert_eq!(completion.id(), completion.operation_id);
    assert_eq!(completion.result(), -5);
    assert_eq!(completion.flags(), 2);
    assert!(completion.has_more());
}

#[test]
fn restricted_mixed_ring_suppresses_wrap_pad() -> liburing::Result<()> {
    use std::os::fd::AsRawFd;

    use liburing::backend::{
        register::{RegisterTarget, register_enable_rings, register_restrictions},
        ring::{
            NativeRing,
            geometry::{Cqe16, SqeMixed},
        },
        sys::{params::*, register::*, sqe::*},
    };
    let mut ring = match NativeRing::<SqeMixed, Cqe16>::with_params(
        4,
        IoUringParams {
            flags: IORING_SETUP_R_DISABLED | IORING_SETUP_NO_SQARRAY,
            ..Default::default()
        },
    ) {
        Ok(ring) => ring,
        Err(liburing::UringError::RingInit(libc::EINVAL)) => return Ok(()),
        Err(err) => return Err(err),
    };
    let fd = match ring.handle().expect("live ring") {
        liburing::backend::mapping::RingHandle::Vfs { fd, .. } => fd.as_raw_fd(),
        _ => panic!("expected VFS ring"),
    };
    let rules = [IoUringRestriction {
        opcode: IORING_RESTRICTION_SQE_OP,
        register_op: IORING_OP_NOP128,
        ..Default::default()
    }];
    // SAFETY: Disabled ring is exclusively owned, with no published operations or competing policy.
    unsafe {
        register_restrictions(RegisterTarget::VfsFd(fd), &rules)?;
        register_enable_rings(RegisterTarget::VfsFd(fd))?;
    }
    {
        let mut sq = ring.submission()?;
        for user_data in 10..13 {
            // SAFETY: NOP has no operands; the initialized SQE is copied into reserved storage.
            unsafe {
                sq.push(&RawSqe {
                    user_data,
                    ..Default::default()
                })?;
            }
        }
        assert_eq!(sq.publish_and_need_wakeup().0, 3);
    }
    assert_eq!(ring.enter(3, 3, IORING_ENTER_GETEVENTS)?, 3);
    {
        let mut cq = ring.completion();
        cq.refresh_tail();
        for expected in 10..13 {
            let cqe = cq.pop().expect("initial NOP CQE");
            assert_eq!((cqe.user_data, cqe.res), (expected, 0));
        }
        assert!(cq.pop().is_none());
        assert_eq!(cq.commit_head(), 3);
    }
    {
        let wide = RawSqe128 {
            base: RawSqe {
                opcode: IORING_OP_NOP128,
                user_data: 99,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut sq = ring.submission()?;
        // SAFETY: NOP128 references no operands; native reservation pads the final 64-byte slot.
        unsafe {
            sq.reserve_wide(&wide)?;
        }
        assert_eq!(sq.publish_and_need_wakeup().0, 3);
    }
    assert_eq!(ring.enter(3, 1, IORING_ENTER_GETEVENTS)?, 3);
    let mut cq = ring.completion();
    cq.refresh_tail();
    let cqe = cq.pop().expect("wide completion");
    assert_eq!((cqe.user_data, cqe.res), (99, 0));
    assert!(
        cq.pop().is_none(),
        "internal user_data=0 padding must not emit EACCES CQEs"
    );
    assert_eq!(cq.commit_head(), 1);
    Ok(())
}

#[test]
fn standard_proactor_rejects_wide_preparation() -> liburing::Result<()> {
    use liburing::{
        Proactor, ProactorConfig, UringError,
        backend::sys::sqe::{IORING_OP_NOP128, IORING_OP_URING_CMD128},
    };
    let mut proactor = Proactor::new(ProactorConfig::default())?;
    for opcode in [IORING_OP_NOP128, IORING_OP_URING_CMD128] {
        let result =
            proactor.prepare_sqe_with(OperationId::from_raw(0x0100_0000_0000_0007), |sqe| {
                // SAFETY: Callback owns one initialized unpublished standard 64-byte SQE.
                unsafe {
                    (*sqe).opcode = opcode;
                }
            });
        assert!(matches!(result, Err(UringError::InvalidPreparedSqe(_))));
        assert_eq!(proactor.operation_count(), 0);
    }
    proactor.shutdown()
}
