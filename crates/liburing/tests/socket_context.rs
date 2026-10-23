//! Dispatcher follow-up sends and receives on the same caller-owned socket state.

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

use liburing::{
    Completion, Proactor, ProactorConfig, Result, SubmissionContext,
    socket_io::{CompletionSocketIo, ReceiveMode, SocketEvent, SocketIoConfig},
};

#[test]
fn dispatcher_sends_a_response_and_rearms_receive_after_returning_the_lease() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        ..ProactorConfig::default()
    })?;
    let mut sockets = CompletionSocketIo::new(
        &mut ring,
        SocketIoConfig {
            sockets: 1,
            operations: 8,
            receive_buffers: 2,
            send_buffers: 1,
            buffer_len: 64,
            ..SocketIoConfig::default()
        },
    )?;
    let (receiver, mut peer) = UnixStream::pair()?;
    peer.set_read_timeout(Some(Duration::from_secs(2)))?;
    let socket = sockets.insert(receiver.into())?;
    sockets.receive(&mut ring, socket, ReceiveMode::Once)?;
    peer.write_all(b"first")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let (mut received, mut sent) = (0, false);
    while received < 2 || !sent {
        assert!(
            Instant::now() < deadline,
            "context follow-up socket work did not complete"
        );
        ring.tick(
            &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                let mut rearm = false;
                sockets.on_completion(cqe, context, |event| {
                    match event {
                        SocketEvent::Received { data, .. } => {
                            if received == 0 {
                                assert_eq!(&*data, b"first");
                                rearm = true;
                            } else {
                                assert_eq!(&*data, b"second");
                            }
                            received += 1;
                        }
                        SocketEvent::Sent { bytes, .. } => {
                            assert_eq!(bytes, 5);
                            sent = true;
                        }
                        SocketEvent::BufferUnavailable { .. } => {
                            panic!("unexpected buffer depletion")
                        }
                        _ => {}
                    }
                    Ok(())
                })?;
                // The selecting lease has returned before the next receive is armed.
                if rearm {
                    sockets.send_with_context(context, socket, b"reply", false)?;
                    sockets.receive_with_context(context, socket, ReceiveMode::Once)?;
                    peer.write_all(b"second")?;
                }
                Ok(())
            },
        )?;
    }
    let mut reply = [0; 5];
    peer.read_exact(&mut reply)?;
    assert_eq!(&reply, b"reply");
    assert_eq!(sockets.operation_count(), 0);
    sockets.close(&mut ring, socket)?;
    assert_eq!(sockets.socket_count(), 0);
    assert!(ring.is_idle());
    ring.shutdown()
}
