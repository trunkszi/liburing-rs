//! Safe socket ownership and selecting-group authentication at real CQ handoff.
use std::{
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

use liburing::{
    BufferGroupId, Completion, OperationId, OperationPayload, Proactor, ProactorConfig, Result,
    SubmissionContext, SubsystemId, backend, ops,
    socket_io::{CompletionSocketIo, ReceiveMode, SocketEvent, SocketIoConfig},
};
fn config() -> SocketIoConfig {
    SocketIoConfig {
        sockets: 1,
        operations: 8,
        receive_buffers: 2,
        send_buffers: 1,
        buffer_len: 64,
        ..SocketIoConfig::default()
    }
}
#[test]
fn foreign_proactor_rejects_submission_and_completion_without_consuming_claim() -> Result<()> {
    let mut a = Proactor::new(ProactorConfig::default())?;
    let mut b = Proactor::new(ProactorConfig::default())?;
    assert_ne!(a.owner_id(), b.owner_id());
    let mut ia = CompletionSocketIo::new(&mut a, config())?;
    let mut ib = CompletionSocketIo::new(&mut b, config())?;
    let (ar, _aw) = UnixStream::pair()?;
    let (br, mut bw) = UnixStream::pair()?;
    let sa = ia.insert(ar.into())?;
    let sb = ib.insert(br.into())?;
    assert!(ia.receive(&mut b, sa, ReceiveMode::Once).is_err());
    assert_eq!(ia.operation_count(), 0);
    assert_eq!(b.operation_count(), 0);
    let oa = ia.receive(&mut a, sa, ReceiveMode::Once)?;
    let ob = ib.receive(&mut b, sb, ReceiveMode::Once)?;
    assert_eq!(oa, ob);
    a.submit()?;
    bw.write_all(b"ring-B-secret")?;
    let mut delivered = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !delivered {
        assert!(Instant::now() < deadline);
        b.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |c: Completion, ctx: &mut SubmissionContext<'_>| {
                assert!(ia.receive_with_context(ctx, sa, ReceiveMode::Once).is_err());
                assert!(ia.send_with_context(ctx, sa, b"foreign", false).is_err());
                assert!(ia.close_with_context(ctx, sa).is_err());
                assert!(
                    ia.on_completion(c, ctx, |_| panic!("foreign payload exposed"))
                        .is_err()
                );
                assert_eq!(ia.operation_count(), 1);
                assert_eq!(ib.operation_count(), 1);
                assert_eq!(ctx.buffer_ring(BufferGroupId(1))?.returned_count(), 0);
                ib.on_completion(c, ctx, |event| {
                    if let SocketEvent::Received { data, .. } = event {
                        assert_eq!(data.as_slice(), b"ring-B-secret");
                        delivered = true;
                    }
                    Ok(())
                })
            },
        )?;
    }
    assert_eq!(ia.operation_count(), 1);
    assert_eq!(a.operation_count(), 1);
    assert_eq!(ib.operation_count(), 0);
    assert_eq!(b.operation_count(), 0);
    assert!(ia.send(&mut b, sa, b"foreign", true).is_err());
    assert!(ia.close(&mut b, sa).is_err());
    a.shutdown()?;
    b.shutdown()
}
#[test]
fn authentic_same_owner_cqe_for_wrong_group_preserves_claim_and_buffer_inventory() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig::default())?;
    let mut io = CompletionSocketIo::new(&mut ring, config())?;
    ring.register_buffer_ring(BufferGroupId(2), 2, 64)?;
    let (receiver, _peer) = UnixStream::pair()?;
    let socket = io.insert(receiver.into())?;
    let receive = io.receive(&mut ring, socket, ReceiveMode::Once)?;
    ring.submit()?;
    assert!(ring.cancel(receive)?);
    let deadline = Instant::now() + Duration::from_secs(2);
    while ring.operation_count() != 0 {
        assert!(Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |_: Completion, _: &mut SubmissionContext<'_>| Ok(()),
        )?;
    }
    // The application omitted delivery to this socket owner; its local receive is still tracked.
    assert_eq!(io.operation_count(), 1);
    let (foreign, mut writer) = UnixStream::pair()?;
    let (pending, _pending_writer) = UnixStream::pair()?;
    let other = OperationId::pack(SubsystemId(9), OperationPayload(1));
    for (id, fd, group) in [
        (receive, foreign.as_raw_fd(), BufferGroupId(2)),
        (other, pending.as_raw_fd(), BufferGroupId(1)),
    ] {
        ring.prepare_sqe_with(id, |sqe| {
            // SAFETY: Descriptors and registered groups remain alive until shutdown.
            unsafe {
                ops::net::prep_recv(sqe, fd, std::ptr::null_mut(), 64, 0);
                (*sqe).flags |= backend::IOSQE_BUFFER_SELECT as u8;
                (*sqe).buf_index = group.raw();
            }
        })?;
    }
    writer.write_all(b"wrong-group")?;
    let mut checked = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !checked {
        assert!(Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |c: Completion, ctx: &mut SubmissionContext<'_>| {
                assert_eq!(c.operation_id, receive);
                assert!(
                    io.on_completion(c, ctx, |_| panic!("wrong-group buffer exposed"))
                        .is_err()
                );
                assert_eq!(io.operation_count(), 1);
                assert_eq!(ctx.buffer_ring(BufferGroupId(1))?.returned_count(), 0);
                ctx.claim_completion(c)?;
                // SAFETY: The authentic current CQE came from the group-2 operation above;
                // its claim is now exclusively held and authorizes this exact group.
                drop(unsafe {
                    ctx.buffer_ring(BufferGroupId(2))?
                        .lease_from_cqe(c.flags, c.result)
                }?);
                checked = true;
                Ok(())
            },
        )?;
    }
    assert_eq!(ring.operation_count(), 1);
    assert_eq!(ring.buffer_ring(BufferGroupId(1))?.returned_count(), 0);
    ring.shutdown()
}
