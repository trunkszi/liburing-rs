use std::{
    io::Write,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

use super::*;
use crate::ProactorConfig;

#[test]
fn negative_selection_preserves_inventory() -> Result<()> {
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
    let (receiver, mut sender) = UnixStream::pair()?;
    let socket = io.insert(receiver.into())?;
    let receive = io.receive(&mut proactor, socket, ReceiveMode::Once)?;
    sender.write_all(b"selected")?;
    let mut observed = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !observed {
        assert!(Instant::now() < deadline, "receive timeout");
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |actual: Completion, context: &mut SubmissionContext<'_>| {
                assert_eq!(actual.operation_id, receive);
                assert_eq!(actual.result, 8);
                assert_ne!(actual.flags & backend::IORING_CQE_F_BUFFER, 0);
                assert_eq!(actual.flags & backend::IORING_CQE_F_MORE, 0);
                // The real selecting CQE above already transferred this buffer
                // out of kernel ownership. Only its result is fault-injected;
                // unread or still kernel-owned storage is never fabricated.
                let negative = Completion {
                    result: -libc::EIO,
                    ..actual
                };
                context.current_completion = Some(negative);
                let returned = context.buffer_ring(BufferGroupId(1))?.returned_count();
                let mut errors = 0;
                io.on_completion(negative, context, |event| {
                    if let SocketEvent::Error { errno, .. } = event {
                        assert_eq!(errno, libc::EIO);
                        errors += 1;
                    } else {
                        assert!(!matches!(event, SocketEvent::Received { .. }));
                    }
                    Ok(())
                })?;
                assert_eq!(errors, 1);
                assert_eq!(
                    context.buffer_ring(BufferGroupId(1))?.returned_count(),
                    returned + 1
                );
                assert_eq!(io.operation_count(), 0);
                observed = true;
                Ok(())
            },
        )?;
    }
    io.close(&mut proactor, socket)?;
    assert_eq!(io.socket_count(), 0);
    proactor.shutdown()
}
