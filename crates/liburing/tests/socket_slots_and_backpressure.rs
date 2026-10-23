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
use liburing_macros as _;
use static_assertions as _;

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
fn lifecycle_socket_generation_rejects_stale_handles_after_slot_reuse() -> Result<()> {
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
fn scenario_failed_root_submission_returns_the_socket_slot_and_dma_credit() -> Result<()> {
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
fn integration_failed_group_registration_rolls_back_the_new_fixed_table() -> Result<()> {
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
