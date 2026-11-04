//! Generation-safe descriptor reuse and transactional fixed-budget backpressure.

use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    os::fd::OwnedFd,
    time::Duration,
};

use liburing::{
    BufferGroupId, Completion, OperationId, OperationPayload, Proactor, ProactorConfig, Result,
    SubmissionContext, SubsystemId, UringError,
    socket_io::{CompletionSocketIo, SocketEvent, SocketIoConfig},
};
use uring_macros as _;

fn pair() -> Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let left = TcpStream::connect(listener.local_addr()?)?;
    let (right, _) = listener.accept()?;
    Ok((left, right))
}
fn config() -> SocketIoConfig {
    SocketIoConfig {
        sockets: 1,
        operations: 8,
        receive_buffers: 2,
        send_buffers: 2,
        buffer_len: 32,
        ..SocketIoConfig::default()
    }
}

#[test]
fn socket_reuse_rejects_stale_handles() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(&mut ring, config())?;
    let (left, right) = pair()?;
    let original = io.insert(OwnedFd::from(left))?;
    let (extra, _) = pair()?;
    assert_eq!(
        io.insert(extra.into()),
        Err(UringError::FixedFileSlotsExhausted)
    );
    io.close(&mut ring, original)?;
    let replacement = io.insert(right.into())?;
    assert_ne!(original, replacement);
    assert!(io.close(&mut ring, original).is_err());
    assert_eq!(io.socket_count(), 1);
    io.close(&mut ring, replacement)?;
    ring.shutdown()
}

#[test]
fn failed_submission_returns_dma_credit() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 8,
        staged_capacity: 1,
        operation_capacity: 1,
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(&mut ring, config())?;
    let (left, mut right) = pair()?;
    right.set_read_timeout(Some(Duration::from_secs(2)))?;
    let socket = io.insert(left.into())?;
    let nop = OperationId::pack(
        SubsystemId::new_unchecked(99),
        OperationPayload::new_unchecked(1),
    );
    ring.alloc_sqe(nop)?;
    assert_eq!(
        io.send(&mut ring, socket, b"data", false),
        Err(UringError::SqRingFull)
    );
    assert_eq!(io.operation_count(), 0);
    // SAFETY: Only inspect credit; no handle escapes or outlives the ring.
    assert_eq!(unsafe { ring.fixed_buffers() }?.available(), 2);
    let mut observed = false;
    let mut dispatcher = |cqe: Completion, _: &mut SubmissionContext<'_>| {
        assert_eq!(cqe.operation_id, nop);
        observed = true;
        Ok(())
    };
    ring.wait_completions(1, Some(Duration::from_secs(2)), &mut dispatcher)?;
    assert!(observed);
    io.send(&mut ring, socket, b"data", false)?;
    let mut sent = false;
    let mut dispatcher = |cqe, ctx: &mut SubmissionContext<'_>| {
        io.on_completion(cqe, ctx, |event| {
            if let SocketEvent::Sent { bytes, .. } = event {
                assert_eq!(bytes, 4);
                sent = true;
            }
            Ok(())
        })
    };
    ring.wait_completions(1, Some(Duration::from_secs(2)), &mut dispatcher)?;
    assert!(sent);
    let mut bytes = [0; 4];
    right.read_exact(&mut bytes)?;
    assert_eq!(&bytes, b"data");
    assert_eq!(io.operation_count(), 0);
    io.close(&mut ring, socket)?;
    ring.shutdown()
}

#[test]
fn failed_group_registration_rolls_back() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        ..ProactorConfig::default()
    })?;
    ring.register_buffer_ring(BufferGroupId(1), 2, 32)?;
    assert!(CompletionSocketIo::new(&mut ring, config()).is_err());
    // SAFETY: Only inspect registration status; no detached handle escapes.
    assert!(unsafe { ring.fixed_buffers() }.is_err());
    let io = CompletionSocketIo::new(
        &mut ring,
        SocketIoConfig {
            receive_group: BufferGroupId(2),
            ..config()
        },
    )?;
    assert_eq!(io.socket_count(), 0);
    assert_eq!(ring.operation_count(), 0);
    ring.shutdown()
}

#[test]
fn oversized_send_preserves_buffer_generation() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig::default())?;
    let mut io = CompletionSocketIo::new(&mut ring, config())?;
    let (left, _right) = pair()?;
    let socket = io.insert(left.into())?;
    // SAFETY: No handle outlives the ring and no SQE is staged for these tokens.
    let first = unsafe { ring.fixed_buffers() }?
        .checkout()?
        .into_in_flight();
    let generation = first.generation();
    let id = first.id();
    // SAFETY: This token was never referenced by an SQE.
    drop(unsafe { first.complete() }?);
    let oversized = [0; 33];
    let error = UringError::InvalidConfig("send exceeds fixed buffer length");
    assert_eq!(io.send(&mut ring, socket, &oversized, false), Err(error));
    // SAFETY: The ring owns the pool and this token is returned before shutdown.
    let next = unsafe { ring.fixed_buffers() }?
        .checkout()?
        .into_in_flight();
    assert_eq!(next.id(), id);
    assert_eq!(next.generation(), generation + 1);
    // SAFETY: This token was never referenced by an SQE.
    drop(unsafe { next.complete() }?);
    io.close(&mut ring, socket)?;
    ring.shutdown()
}

#[test]
fn oversized_send_precedes_exhaustion() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig::default())?;
    let mut io = CompletionSocketIo::new(&mut ring, config())?;
    let (left, _right) = pair()?;
    let socket = io.insert(left.into())?;
    // SAFETY: These handles remain local and are dropped before shutdown.
    let first = unsafe { ring.fixed_buffers() }?.checkout()?;
    // SAFETY: The second handle owns a distinct free slot in the live ring's pool.
    let second = unsafe { ring.fixed_buffers() }?.checkout()?;
    let oversized = [0; 33];
    assert_eq!(
        io.send(&mut ring, socket, &oversized, false),
        Err(UringError::InvalidConfig(
            "send exceeds fixed buffer length"
        ))
    );
    drop((first, second));
    io.close(&mut ring, socket)?;
    ring.shutdown()
}

#[test]
fn failed_close_keeps_socket_active() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 8,
        staged_capacity: 1,
        operation_capacity: 8,
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(&mut ring, config())?;
    let (left, mut right) = pair()?;
    let socket = io.insert(left.into())?;
    let receive = io.receive(&mut ring, socket, liburing::socket_io::ReceiveMode::Once)?;
    ring.submit()?;
    let trigger = OperationId::pack(
        SubsystemId::new_unchecked(99),
        OperationPayload::new_unchecked(1),
    );
    let filler = OperationId::pack(
        SubsystemId::new_unchecked(99),
        OperationPayload::new_unchecked(2),
    );
    ring.alloc_sqe(trigger)?;
    let mut rejected = false;
    ring.wait_completions(
        1,
        Some(Duration::from_secs(2)),
        &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.operation_id, trigger);
            context.prepare_sqe_with(filler, |sqe| {
                // SAFETY: The callback supplies exclusive initialized storage and NOP has no
                // operands.
                unsafe { liburing::ops::prep_nop(sqe) };
            })?;
            assert_eq!(
                io.close_with_context(context, socket),
                Err(UringError::SqRingFull)
            );
            rejected = true;
            Ok(())
        },
    )?;
    assert!(rejected);
    std::io::Write::write_all(&mut right, b"live")?;
    let mut received = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !received {
        assert!(std::time::Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                if cqe.operation_id == filler {
                    return Ok(());
                }
                assert_eq!(cqe.operation_id, receive);
                io.on_completion(cqe, context, |event| {
                    match event {
                        SocketEvent::Received { data, .. } => {
                            assert_eq!(&*data, b"live");
                            received = true;
                        }
                        SocketEvent::Closed { .. } => {
                            panic!("failed cancellation closed an active socket")
                        }
                        _ => panic!("unexpected completion after rejected close"),
                    }
                    Ok(())
                })
            },
        )?;
    }
    assert_eq!(io.socket_count(), 1);
    io.send(&mut ring, socket, b"reply", false)?;
    let mut sent = false;
    while !sent {
        assert!(std::time::Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe, context: &mut SubmissionContext<'_>| {
                io.on_completion(cqe, context, |event| {
                    sent |= matches!(event, SocketEvent::Sent { .. });
                    Ok(())
                })
            },
        )?;
    }
    io.close(&mut ring, socket)?;
    ring.shutdown()
}

#[test]
fn waiting_notification_preserves_failed_close() -> Result<()> {
    use liburing::{backend, operation_slab::OperationState, socket_io::ReceiveMode};
    let mut ring = Proactor::new(ProactorConfig {
        entries: 8,
        staged_capacity: 1,
        operation_capacity: 8,
        max_cqe_batch: 1,
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(&mut ring, config())?;
    let (left, mut right) = pair()?;
    let socket = io.insert(left.into())?;
    let receive = io.receive(&mut ring, socket, ReceiveMode::Once)?;
    ring.submit()?;
    let send = io.send(&mut ring, socket, b"waiting", true)?;
    let filler = OperationId::pack(
        SubsystemId::new_unchecked(99),
        OperationPayload::new_unchecked(3),
    );
    let mut rejected = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !rejected {
        assert!(std::time::Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                assert_eq!(cqe.operation_id, send);
                assert_eq!(cqe.result, 7);
                assert_eq!(cqe.flags & backend::IORING_CQE_F_NOTIF, 0);
                assert_ne!(cqe.flags & backend::IORING_CQE_F_MORE, 0);
                io.on_completion(cqe, context, |event| {
                    assert!(matches!(event, SocketEvent::Sent { bytes: 7, .. }));
                    Ok(())
                })?;
                assert_eq!(io.operation_count(), 2);
                context.prepare_sqe_with(filler, |sqe| {
                    // SAFETY: The callback supplies exclusive initialized storage; NOP has no
                    // operands.
                    unsafe { liburing::ops::prep_nop(sqe) };
                })?;
                assert_eq!(
                    io.close_with_context(context, socket),
                    Err(UringError::SqRingFull)
                );
                rejected = true;
                Ok(())
            },
        )?;
    }
    assert_eq!(
        ring.operation_state(send)?,
        OperationState::AwaitingZeroCopyNotification
    );
    assert_eq!(ring.operation_state(receive)?, OperationState::InFlight);
    io.send(&mut ring, socket, b"reply", false)?;
    std::io::Write::write_all(&mut right, b"live")?;
    let mut received = false;
    let mut released = false;
    let mut replied = false;
    while io.operation_count() != 0 || !received || !released || !replied {
        assert!(std::time::Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                if cqe.operation_id == filler {
                    assert_eq!(cqe.result, 0);
                    return Ok(());
                }
                io.on_completion(cqe, context, |event| {
                    match event {
                        SocketEvent::Received { data, .. } => {
                            assert_eq!(&*data, b"live");
                            received = true;
                        }
                        SocketEvent::SendReleased { .. } => released = true,
                        SocketEvent::Sent { bytes: 5, .. } => replied = true,
                        SocketEvent::Closed { .. } => {
                            panic!("rejected close retired an active socket")
                        }
                        _ => panic!("unexpected event after rejected close"),
                    }
                    Ok(())
                })
            },
        )?;
    }
    assert_eq!(io.socket_count(), 1);
    assert_eq!(ring.operation_count(), 0);
    io.close(&mut ring, socket)?;
    ring.shutdown()
}

#[test]
fn notification_only_close_still_drains() -> Result<()> {
    use liburing::{backend, operation_slab::OperationState};
    let mut ring = Proactor::new(ProactorConfig {
        entries: 8,
        staged_capacity: 1,
        operation_capacity: 8,
        max_cqe_batch: 1,
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(&mut ring, config())?;
    let (left, _right) = pair()?;
    let socket = io.insert(left.into())?;
    let send = io.send(&mut ring, socket, b"waiting", true)?;
    let filler = OperationId::pack(
        SubsystemId::new_unchecked(99),
        OperationPayload::new_unchecked(4),
    );
    let mut closing = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !closing {
        assert!(std::time::Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                assert_eq!(cqe.operation_id, send);
                assert_eq!(cqe.flags & backend::IORING_CQE_F_NOTIF, 0);
                assert_ne!(cqe.flags & backend::IORING_CQE_F_MORE, 0);
                io.on_completion(cqe, context, |event| {
                    assert!(matches!(event, SocketEvent::Sent { bytes: 7, .. }));
                    Ok(())
                })?;
                assert_eq!(io.operation_count(), 1);
                context.prepare_sqe_with(filler, |sqe| {
                    // SAFETY: The callback supplies exclusive initialized storage; NOP has no
                    // operands.
                    unsafe { liburing::ops::prep_nop(sqe) };
                })?;
                io.close_with_context(context, socket)?;
                closing = true;
                Ok(())
            },
        )?;
    }
    assert_eq!(
        ring.operation_state(send)?,
        OperationState::AwaitingZeroCopyNotification
    );
    assert_eq!(
        io.send(&mut ring, socket, b"closed", false),
        Err(UringError::InvalidConfig("socket is closing"))
    );
    let mut closed = false;
    let mut released = false;
    let mut filled = false;
    while !closed || !filled {
        assert!(std::time::Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                if cqe.operation_id == filler {
                    assert_eq!(cqe.result, 0);
                    filled = true;
                    return Ok(());
                }
                io.on_completion(cqe, context, |event| {
                    match event {
                        SocketEvent::SendReleased { .. } => released = true,
                        SocketEvent::Closed { .. } => {
                            assert!(released);
                            closed = true;
                        }
                        _ => panic!("unexpected event while draining notification"),
                    }
                    Ok(())
                })
            },
        )?;
    }
    assert_eq!(io.operation_count(), 0);
    assert_eq!(io.socket_count(), 0);
    assert_eq!(ring.operation_count(), 0);
    ring.shutdown()
}
