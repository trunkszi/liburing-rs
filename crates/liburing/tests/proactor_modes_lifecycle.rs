//! Kernel lifecycle coverage for mode admission and teardown ownership.

#[path = "support/mode_affinity.rs"]
mod mode_affinity;
use io_uring::opcode;
use liburing::{
    OperationId, OperationPayload, Proactor, ProactorConfig, ProactorMode, Result, SubsystemId,
    UringError,
};
use mode_affinity::sq_thread_cpu;

fn identity(payload: u64) -> OperationId {
    OperationId::pack(SubsystemId(1), OperationPayload(payload))
}

#[test]
fn iopoll_rejects_unadmitted_opcodes() -> Result<()> {
    for mode in [
        ProactorMode::io_poll(),
        ProactorMode::sq_poll_io_poll(sq_thread_cpu()?),
    ] {
        let mut proactor = Proactor::new(ProactorConfig {
            mode,
            ..Default::default()
        })?;
        let capacity = proactor.remaining_capacity();
        for code in [
            opcode::Close::CODE,
            opcode::AsyncCancel::CODE,
            opcode::Fsync::CODE,
            opcode::Timeout::CODE,
            opcode::PollAdd::CODE,
            opcode::Send::CODE,
            opcode::Recv::CODE,
            opcode::UringCmd16::CODE,
        ] {
            assert_eq!(
                proactor.prepare_sqe_with(identity(1), |sqe| {
                    // SAFETY: The preparation callback owns initialized exclusive SQE storage.
                    unsafe { (*sqe).opcode = code };
                }),
                Err(UringError::OpcodeNotAdmitted {
                    opcode: code,
                    mode: mode.name()
                })
            );
            assert_eq!(proactor.operation_count(), 0);
            assert_eq!(proactor.remaining_capacity(), capacity);
        }
        proactor.alloc_sqe(identity(1))?;
        assert_eq!(proactor.operation_count(), 1);
        proactor.shutdown()?;
    }
    Ok(())
}

#[test]
fn socket_engine_rejects_iopoll_rings() -> Result<()> {
    use liburing::socket_io::{CompletionSocketIo, SocketIoConfig};
    for mode in [
        ProactorMode::io_poll(),
        ProactorMode::sq_poll_io_poll(sq_thread_cpu()?),
    ] {
        let mut proactor = Proactor::new(ProactorConfig {
            mode,
            ..Default::default()
        })?;
        assert!(
            matches!(CompletionSocketIo::new(&mut proactor, SocketIoConfig::default()),
            Err(UringError::OpcodeNotAdmitted { opcode: opcode::Recv::CODE, mode: name }) if name == mode.name())
        );
        // SAFETY: No handles escape this query and the proactor owns the live ring.
        assert!(unsafe { proactor.fixed_buffers() }.is_err());
        proactor.configure_fixed_buffers(1, 4096)?;
        // SAFETY: The pool reference and checkout remain within the proactor lifetime.
        let pool = unsafe { proactor.fixed_buffers() }?;
        let buffer = pool.checkout()?.into_in_flight();
        assert_eq!(pool.available(), 0);
        assert_eq!(
            proactor.prepare_buffer_sqe_with(identity(1), buffer, |sqe| {
                // SAFETY: The callback owns initialized exclusive SQE storage.
                unsafe { (*sqe).opcode = opcode::Recv::CODE };
            }),
            Err(UringError::OpcodeNotAdmitted {
                opcode: opcode::Recv::CODE,
                mode: mode.name()
            })
        );
        // SAFETY: No handles escape this query and the pool remains ring-owned.
        assert_eq!(unsafe { proactor.fixed_buffers() }?.available(), 1);
        proactor.shutdown()?;
    }
    Ok(())
}

#[test]
fn iopoll_cancel_preserves_live_generation() -> Result<()> {
    use liburing::{Completion, SubmissionContext, operation_slab::OperationState};
    for mode in [
        ProactorMode::io_poll(),
        ProactorMode::sq_poll_io_poll(sq_thread_cpu()?),
    ] {
        let mut proactor = Proactor::new(ProactorConfig {
            mode,
            staged_capacity: 1,
            ..Default::default()
        })?;
        proactor.alloc_sqe(identity(1))?;
        let key = proactor.operation_key(identity(1))?;
        assert_eq!(
            proactor.cancel_key(key),
            Err(UringError::CancellationUnavailable { mode: mode.name() })
        );
        assert_eq!(
            proactor.cancel(identity(1)),
            Err(UringError::CancellationUnavailable { mode: mode.name() })
        );
        assert_eq!(
            proactor.operation_state(identity(1))?,
            OperationState::InFlight
        );
        assert_eq!(proactor.pending_cancel_count(), 0);
        let mut completed = 0;
        proactor.shutdown_with(
            &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                assert_eq!(cqe.result, -libc::ECANCELED);
                assert!(!context.cancel_key(key)?);
                assert_eq!(context.remaining_capacity(), 0);
                completed += 1;
                Ok(())
            },
        )?;
        assert_eq!(completed, 1);
        assert!(!proactor.cancel_key(key)?);
    }
    Ok(())
}

#[test]
fn iopoll_admission_matches_kernel() -> Result<()> {
    use io_uring::IoUring;
    use liburing::backend::RawSqe;
    for code in [
        opcode::Nop::CODE,
        opcode::Read::CODE,
        opcode::Write::CODE,
        opcode::Readv::CODE,
        opcode::Writev::CODE,
        opcode::ReadFixed::CODE,
        opcode::WriteFixed::CODE,
        opcode::ReadvFixed::CODE,
        opcode::WritevFixed::CODE,
        opcode::Close::CODE,
        opcode::AsyncCancel::CODE,
        opcode::Fsync::CODE,
        opcode::Timeout::CODE,
        opcode::PollAdd::CODE,
        opcode::Send::CODE,
        opcode::Recv::CODE,
    ] {
        let admitted = [
            opcode::Nop::CODE,
            opcode::Read::CODE,
            opcode::Write::CODE,
            opcode::Readv::CODE,
            opcode::Writev::CODE,
            opcode::ReadFixed::CODE,
            opcode::WriteFixed::CODE,
            opcode::ReadvFixed::CODE,
            opcode::WritevFixed::CODE,
        ]
        .contains(&code);
        let mut proactor = Proactor::new(ProactorConfig {
            mode: ProactorMode::io_poll(),
            ..Default::default()
        })?;
        let outcome = proactor.prepare_sqe_with(identity(1), |sqe| {
            // SAFETY: Exclusive initialized SQE; fd -1 prevents external DMA operands.
            unsafe {
                (*sqe).opcode = code;
                (*sqe).fd = -1;
            };
        });
        assert_eq!(
            outcome.is_ok(),
            admitted,
            "library admission for opcode {code}"
        );
        proactor.shutdown()?;
        let mut ring: IoUring = IoUring::builder().setup_iopoll().build(8)?;
        let entry = RawSqe {
            opcode: code,
            fd: -1,
            ..Default::default()
        }
        .into_entry();
        // SAFETY: fd -1 is deliberately invalid and no entry references user memory.
        unsafe { ring.submission().push(&entry) }.map_err(|_| UringError::SqRingFull)?;
        ring.submit_and_wait(1)?;
        let result = ring
            .completion()
            .next()
            .ok_or(UringError::Wait(libc::EIO))?
            .result();
        if admitted {
            assert_ne!(
                result,
                -libc::EINVAL,
                "kernel rejected admitted opcode {code}"
            );
        } else {
            assert_eq!(
                result,
                -libc::EINVAL,
                "kernel admitted rejected opcode {code}"
            );
        }
    }
    Ok(())
}

#[test]
fn four_modes_drain_published_and_staged() -> Result<()> {
    use liburing::{Completion, SubmissionContext};
    for mode in [
        ProactorMode::event_driven(),
        ProactorMode::sq_poll(sq_thread_cpu()?),
        ProactorMode::io_poll(),
        ProactorMode::sq_poll_io_poll(sq_thread_cpu()?),
    ] {
        let mut proactor = Proactor::new(ProactorConfig {
            mode,
            entries: 64,
            max_cqe_batch: 1,
            ..Default::default()
        })?;
        for payload in 0..24 {
            proactor.alloc_sqe(identity(payload))?;
        }
        proactor.submit()?;
        for payload in 24..32 {
            proactor.alloc_sqe(identity(payload))?;
        }
        let mut seen = [false; 32];
        proactor.shutdown_with(
            &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                assert_eq!(context.remaining_capacity(), 0);
                let index = cqe.operation_id.payload().0 as usize;
                assert!(!seen[index]);
                seen[index] = true;
                assert_eq!(cqe.result, if index < 24 { 0 } else { -libc::ECANCELED });
                Ok(())
            },
        )?;
        assert!(seen.iter().all(|seen| *seen));
        assert!(proactor.is_idle());
        proactor.shutdown()?;
    }
    Ok(())
}

#[test]
fn sq_shutdown_recovers_sleeping_thread() -> Result<()> {
    use std::{
        num::NonZeroU32,
        time::{Duration, Instant},
    };

    use liburing::{Completion, SqPollConfig, SubmissionContext, ops::Timeout};
    let timeout = Timeout::new(Duration::from_secs(60))?;
    let mode =
        ProactorMode::SqPoll(SqPollConfig::pinned(sq_thread_cpu()?).with_idle_ms(NonZeroU32::MIN));
    let mut proactor = Proactor::new(ProactorConfig {
        mode,
        entries: 64,
        ..Default::default()
    })?;
    for payload in 0..48 {
        proactor.prepare_sqe_with(identity(payload), |sqe| {
            // SAFETY: The immutable timeout precedes the ring and outlives all completions.
            unsafe { timeout.prepare(sqe) };
        })?;
    }
    proactor.submit()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: The ring is live, exclusively borrowed, and the queue borrow ends here.
        if unsafe { &mut *proactor.ring_mut() }
            .submission()
            .need_wakeup()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "SQ thread did not enter idle sleep"
        );
        core::hint::spin_loop();
    }
    let mut completed = 0;
    proactor.shutdown_with(
        &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.result, -libc::ECANCELED);
            assert_eq!(context.remaining_capacity(), 0);
            completed += 1;
            Ok(())
        },
    )?;
    assert_eq!(completed, 48);
    assert!(proactor.is_idle());
    Ok(())
}

#[test]
fn callback_guards_preserve_iopoll_targets() -> Result<()> {
    use std::time::{Duration, Instant};

    use liburing::{Completion, SubmissionContext};
    for mode in [
        ProactorMode::io_poll(),
        ProactorMode::sq_poll_io_poll(sq_thread_cpu()?),
    ] {
        let mut proactor = Proactor::new(ProactorConfig {
            mode,
            ..Default::default()
        })?;
        proactor.alloc_sqe(identity(1))?;
        proactor.alloc_sqe(identity(2))?;
        let keys = [
            proactor.operation_key(identity(1))?,
            proactor.operation_key(identity(2))?,
        ];
        let mut completed = 0;
        let deadline = Instant::now() + Duration::from_secs(2);
        while completed != 2 {
            proactor.tick(
                &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                    let own = (cqe.operation_id.payload().0 - 1) as usize;
                    assert!(!context.cancel_key(keys[own])?);
                    if completed == 0 {
                        assert_eq!(
                            context.cancel_key(keys[1 - own]),
                            Err(UringError::CancellationUnavailable { mode: mode.name() })
                        );
                    }
                    assert_eq!(
                        context.prepare_sqe_with(identity(3), |sqe| {
                            // SAFETY: Initialized exclusive SQE storage within the preparation
                            // callback.
                            unsafe { (*sqe).opcode = opcode::Recv::CODE };
                        }),
                        Err(UringError::OpcodeNotAdmitted {
                            opcode: opcode::Recv::CODE,
                            mode: mode.name()
                        })
                    );
                    completed += 1;
                    Ok(())
                },
            )?;
            assert!(Instant::now() < deadline, "IOPOLL NOP did not complete");
        }
        assert_eq!(proactor.pending_cancel_count(), 0);
        assert!(!proactor.cancel_key(keys[0])?);
        assert!(!proactor.cancel_key(keys[1])?);
        proactor.shutdown()?;
    }
    Ok(())
}
