//! Verified completion handoff against forgery, replay, and selected errors.

use std::{
    io::Write,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

use liburing::{
    BufferGroupId, Completion, OperationId, OperationPayload, Proactor, ProactorConfig, Result,
    SubmissionContext, SubsystemId, backend,
    socket_io::{CompletionSocketIo, ReceiveMode, SocketEvent, SocketId, SocketIoConfig},
};

fn fixture() -> Result<(Proactor, CompletionSocketIo, SocketId, UnixStream)> {
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 16,
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(
        &mut proactor,
        SocketIoConfig {
            sockets: 1,
            operations: 8,
            receive_buffers: 2,
            send_buffers: 1,
            buffer_len: 64,
            ..SocketIoConfig::default()
        },
    )?;
    let (receiver, sender) = UnixStream::pair()?;
    let socket = io.insert(receiver.into())?;
    Ok((proactor, io, socket, sender))
}

fn close(proactor: &mut Proactor, io: &mut CompletionSocketIo, socket: SocketId) -> Result<()> {
    io.close(proactor, socket)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while io.operation_count() != 0 {
        assert!(
            Instant::now() < deadline,
            "socket cancellation did not retire"
        );
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe, context: &mut SubmissionContext<'_>| {
                io.on_completion(cqe, context, |_| Ok(()))
            },
        )?;
    }
    assert_eq!(io.socket_count(), 0);
    proactor.shutdown()
}

#[test]
fn integration_unrelated_completion_cannot_forge_receive_buffer_ownership() -> Result<()> {
    let (mut proactor, mut io, socket, _sender) = fixture()?;
    let receive = io.receive(&mut proactor, socket, ReceiveMode::Multishot)?;
    let audit = OperationId::pack(SubsystemId(2), OperationPayload::new_unchecked(17));
    proactor.alloc_sqe(audit)?;
    let mut rejected = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !rejected {
        assert!(Instant::now() < deadline, "audit completion did not arrive");
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |actual: Completion, context: &mut SubmissionContext<'_>| {
                assert_eq!(actual.operation_id, audit);
                let forged = Completion {
                    operation_id: receive,
                    result: 1,
                    flags: backend::IORING_CQE_F_BUFFER | backend::IORING_CQE_F_MORE,
                };
                assert!(
                    io.on_completion(forged, context, |_| panic!("forged payload was exposed"))
                        .is_err()
                );
                assert_eq!(io.operation_count(), 1);
                assert_eq!(context.buffer_ring(BufferGroupId(1))?.returned_count(), 0);
                context.claim_completion(actual)?;
                assert!(context.claim_completion(actual).is_err());
                rejected = true;
                Ok(())
            },
        )?;
    }
    close(&mut proactor, &mut io, socket)
}

#[test]
fn lifecycle_multishot_cqe_handoff_cannot_be_replayed_after_lease_return() -> Result<()> {
    let (mut proactor, mut io, socket, mut sender) = fixture()?;
    let receive = io.receive(&mut proactor, socket, ReceiveMode::Multishot)?;
    sender.write_all(b"leased")?;
    let mut observed = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !observed {
        assert!(
            Instant::now() < deadline,
            "selected completion did not arrive"
        );
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |actual: Completion, context: &mut SubmissionContext<'_>| {
                assert_eq!(actual.operation_id, receive);
                assert_eq!(actual.result, 6);
                assert_ne!(actual.flags & backend::IORING_CQE_F_MORE, 0);
                let returned = context.buffer_ring(BufferGroupId(1))?.returned_count();
                let mut payloads = 0;
                io.on_completion(actual, context, |event| {
                    if let SocketEvent::Received { data, .. } = event {
                        assert_eq!(&*data, b"leased");
                        payloads += 1;
                    }
                    Ok(())
                })?;
                assert_eq!(payloads, 1);
                assert_eq!(
                    context.buffer_ring(BufferGroupId(1))?.returned_count(),
                    returned + 1
                );
                assert!(
                    io.on_completion(actual, context, |_| panic!("replayed payload was exposed"))
                        .is_err()
                );
                assert_eq!(
                    context.buffer_ring(BufferGroupId(1))?.returned_count(),
                    returned + 1
                );
                assert_eq!(io.operation_count(), 1);
                observed = true;
                Ok(())
            },
        )?;
    }
    close(&mut proactor, &mut io, socket)
}
