//! Real TCP/Unix completion I/O across integration, lifecycle, and scenario seams.

use std::{
    net::{TcpListener, TcpStream},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::{Duration, Instant},
};

use liburing::{
    Completion, CompletionDispatcher, Proactor, ProactorConfig, Result, SubmissionContext,
    socket_io::{CompletionSocketIo, ReceiveMode, SocketEvent, SocketId, SocketIoConfig},
};
use uring_macros as _;

#[derive(Default)]
struct WorkerState {
    bytes: Vec<u8>,
    received: usize,
    sent: usize,
    released: usize,
    cancelled: usize,
    closed: usize,
}

struct Dispatcher<'a> {
    io: &'a mut CompletionSocketIo,
    worker: &'a mut WorkerState,
}
impl CompletionDispatcher for Dispatcher<'_> {
    fn dispatch(&mut self, cqe: Completion, context: &mut SubmissionContext<'_>) -> Result<()> {
        self.io.on_completion(cqe, context, |event| {
            match event {
                SocketEvent::Received { data, .. } => {
                    self.worker.bytes.extend_from_slice(&data);
                    self.worker.received += 1;
                }
                SocketEvent::Sent { bytes, .. } => self.worker.sent += bytes,
                SocketEvent::SendReleased { .. } => self.worker.released += 1,
                SocketEvent::Cancelled { .. } => self.worker.cancelled += 1,
                SocketEvent::Closed { .. } => self.worker.closed += 1,
                SocketEvent::Error { errno, .. } => {
                    return Err(liburing::UringError::syscalls("socket completion", errno));
                }
                SocketEvent::BufferUnavailable { .. } => panic!("unexpected receive exhaustion"),
                SocketEvent::ReadClosed { .. } => {}
            }
            Ok(())
        })
    }
}

fn ring_and_io() -> Result<(Proactor, CompletionSocketIo)> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 32,
        staged_capacity: 32,
        operation_capacity: 64,
        ..ProactorConfig::default()
    })?;
    let io = CompletionSocketIo::new(
        &mut ring,
        SocketIoConfig {
            sockets: 4,
            operations: 32,
            send_buffers: 4,
            receive_buffers: 4,
            buffer_len: 4096,
            ..SocketIoConfig::default()
        },
    )?;
    Ok((ring, io))
}

fn tcp_pair() -> Result<(OwnedFd, OwnedFd)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let left = TcpStream::connect(listener.local_addr()?)?;
    let (right, _) = listener.accept()?;
    Ok((left.into(), right.into()))
}

fn drive(
    ring: &mut Proactor,
    io: &mut CompletionSocketIo,
    worker: &mut WorkerState,
    ready: impl Fn(&WorkerState, &CompletionSocketIo) -> bool,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !ready(worker, io) {
        assert!(
            Instant::now() < deadline,
            "completion I/O did not reach its terminal observation"
        );
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut Dispatcher { io, worker },
        )?;
    }
    Ok(())
}

fn close_pair(
    ring: &mut Proactor,
    io: &mut CompletionSocketIo,
    worker: &mut WorkerState,
    left: SocketId,
    right: SocketId,
) -> Result<()> {
    io.close(ring, left)?;
    io.close(ring, right)?;
    drive(ring, io, worker, |_, io| {
        io.socket_count() == 0 && io.operation_count() == 0
    })?;
    assert_eq!(ring.operation_count(), 0);
    ring.shutdown()
}

#[test]
fn tcp_receive_hands_off_payload() -> Result<()> {
    let (mut ring, mut io) = ring_and_io()?;
    let (left, right) = tcp_pair()?;
    let left = io.insert(left)?;
    let right = io.insert(right)?;
    io.receive(&mut ring, right, ReceiveMode::Once)?;
    io.send(&mut ring, left, b"completion payload", false)?;
    let mut worker = WorkerState::default();
    drive(&mut ring, &mut io, &mut worker, |worker, _| {
        worker.bytes == b"completion payload" && worker.sent == 18
    })?;
    assert_eq!(worker.received, 1);
    close_pair(&mut ring, &mut io, &mut worker, left, right)
}

#[test]
fn multishot_receives_multiple_transfers() -> Result<()> {
    let (mut ring, mut io) = ring_and_io()?;
    let (left, right) = UnixStream::pair()?;
    let left = io.insert(left.into())?;
    let right = io.insert(right.into())?;
    io.receive(&mut ring, right, ReceiveMode::Multishot)?;
    let mut worker = WorkerState::default();
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        let expected = worker.bytes.len() + payload.len();
        io.send(&mut ring, left, payload, false)?;
        drive(&mut ring, &mut io, &mut worker, |worker, _| {
            worker.bytes.len() == expected && worker.sent == expected
        })?;
    }
    assert_eq!(worker.bytes, b"firstsecond");
    assert!(worker.received >= 2);
    close_pair(&mut ring, &mut io, &mut worker, left, right)
}

#[test]
fn cancel_retains_descriptor_until_final() -> Result<()> {
    let (mut ring, mut io) = ring_and_io()?;
    let (left, right) = tcp_pair()?;
    let fd = right.as_raw_fd();
    let left = io.insert(left)?;
    let right = io.insert(right)?;
    io.receive(&mut ring, right, ReceiveMode::Multishot)?;
    ring.submit()?;
    io.close(&mut ring, right)?;
    // SAFETY: F_GETFD queries the live descriptor without borrowing its buffers.
    assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    let mut worker = WorkerState::default();
    drive(&mut ring, &mut io, &mut worker, |worker, io| {
        worker.closed == 1 && io.operation_count() == 0
    })?;
    assert_eq!(worker.cancelled, 1);
    // SAFETY: F_GETFD only queries the old descriptor number after final CQE.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert!(io.receive(&mut ring, right, ReceiveMode::Once).is_err());
    io.close(&mut ring, left)?;
    ring.shutdown()
}

#[test]
fn send_zc_retains_buffer_until_notification() -> Result<()> {
    let (mut ring, mut io) = ring_and_io()?;
    let (left, right) = tcp_pair()?;
    let left = io.insert(left)?;
    let right = io.insert(right)?;
    io.receive(&mut ring, right, ReceiveMode::Once)?;
    io.send(&mut ring, left, b"zero-copy", true)?;
    // SAFETY: This temporary pool reference creates no handle that escapes;
    // Proactor owns all in-flight tokens throughout this observation.
    assert_eq!(unsafe { ring.fixed_buffers() }?.available(), 3);
    let mut worker = WorkerState::default();
    drive(&mut ring, &mut io, &mut worker, |worker, _| {
        worker.released == 1 && worker.bytes == b"zero-copy"
    })?;
    // SAFETY: All send token CQEs, including notification, have retired.
    assert_eq!(unsafe { ring.fixed_buffers() }?.available(), 4);
    close_pair(&mut ring, &mut io, &mut worker, left, right)
}

#[test]
fn cancel_works_with_full_operation_slab() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 8,
        staged_capacity: 1,
        operation_capacity: 1,
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(
        &mut ring,
        SocketIoConfig {
            sockets: 1,
            operations: 1,
            send_buffers: 1,
            receive_buffers: 2,
            ..SocketIoConfig::default()
        },
    )?;
    let (left, _right) = UnixStream::pair()?;
    let socket = io.insert(left.into())?;
    let target = io.receive(&mut ring, socket, ReceiveMode::Multishot)?;
    assert_eq!(ring.operation_count(), 1);
    io.close(&mut ring, socket)?;
    assert_eq!(
        ring.operation_state(target)?,
        liburing::operation_slab::OperationState::Canceling
    );
    assert_eq!(
        ring.operation_count(),
        1,
        "control CQE must not consume a target slot"
    );
    let mut worker = WorkerState::default();
    drive(&mut ring, &mut io, &mut worker, |worker, io| {
        worker.cancelled == 1 && io.socket_count() == 0
    })?;
    assert_eq!(io.operation_count(), 0);
    ring.shutdown()
}

#[test]
fn closing_socket_preserves_sibling_receive() -> Result<()> {
    let (mut ring, mut io) = ring_and_io()?;
    let (first, _first_peer) = UnixStream::pair()?;
    let (second, mut second_peer) = UnixStream::pair()?;
    let first = io.insert(first.into())?;
    let second = io.insert(second.into())?;
    io.receive(&mut ring, first, ReceiveMode::Multishot)?;
    io.receive(&mut ring, second, ReceiveMode::Multishot)?;
    // Send completion removes a head while the receive remains linked beneath it.
    io.send(&mut ring, first, b"head", false)?;
    let mut worker = WorkerState::default();
    drive(&mut ring, &mut io, &mut worker, |worker, _| {
        worker.sent == 4
    })?;
    io.close(&mut ring, first)?;
    io.close(&mut ring, first)?;
    drive(&mut ring, &mut io, &mut worker, |worker, _| {
        worker.closed == 1
    })?;
    assert_eq!(io.operation_count(), 1);
    std::io::Write::write_all(&mut second_peer, b"still live")?;
    drive(&mut ring, &mut io, &mut worker, |worker, _| {
        worker.bytes == b"still live"
    })?;
    let (replacement, _peer) = UnixStream::pair()?;
    let replacement = io.insert(replacement.into())?;
    assert_ne!(replacement, first);
    io.receive(&mut ring, replacement, ReceiveMode::Once)?;
    io.close(&mut ring, replacement)?;
    io.close(&mut ring, second)?;
    drive(&mut ring, &mut io, &mut worker, |_, io| {
        io.socket_count() == 0
    })?;
    assert_eq!(worker.cancelled, 3);
    assert_eq!(io.operation_count(), 0);
    ring.shutdown()
}

#[test]
fn prepared_entries_preserve_wire_layout() {
    use liburing::{
        BufferGroupId, BufferId, OperationId, UringFileSlot,
        backend::{RawSqe, opcode, types},
        ops,
    };
    fn check(entry: liburing::backend::squeue::Entry, mut prepare: impl FnMut(*mut RawSqe)) {
        for seed in [0xa5_u8, 0x5a] {
            // SAFETY: RawSqe is a padding-free 64-byte integer wire layout; every bit pattern is
            // valid.
            let mut actual: RawSqe = unsafe { std::mem::transmute([seed; 64]) };
            let mut expected = entry;
            expected.flags |= actual.flags;
            expected.user_data = actual.user_data;
            expected.personality = actual.personality;
            prepare(&mut actual);
            // SAFETY: Both initialized RawSqes have no padding, references, or owned resources.
            let actual: [u8; 64] = unsafe { std::mem::transmute(actual) };
            // SAFETY: The independent io-uring builder initializes every byte of its wire layout.
            let expected: [u8; 64] = unsafe { std::mem::transmute(expected) };
            assert_eq!(actual, expected);
        }
    }
    let fd = 23;
    let buf = std::ptr::null_mut();
    let msg = std::ptr::null_mut();
    let addr = std::ptr::null_mut();
    let addrlen = std::ptr::null_mut();
    let iov = std::ptr::null();
    let target = OperationId::from_raw(0x1234_5678);
    // SAFETY: Each closure receives exclusive initialized storage. These encoding checks
    // publish no SQEs and never dereference the null operands or transfer descriptor ownership.
    unsafe {
        check(opcode::Nop::new().build(), |sqe| ops::prep_nop(sqe));
        check(
            opcode::Send::new(types::Fd(fd), buf, 7).flags(3).build(),
            |sqe| ops::net::prep_send(sqe, fd, buf, 7, 3),
        );
        check(
            opcode::Send::new(types::Fd(fd), buf, 7).flags(3).build(),
            |sqe| ops::net::prep_send_fixed(sqe, fd, buf, 7, 3),
        );
        check(
            opcode::SendZc::new(types::Fd(fd), buf, 7)
                .flags(3)
                .zc_flags(2)
                .build(),
            |sqe| ops::net::prep_send_zc(sqe, fd, buf, 7, 3, 2),
        );
        check(
            opcode::SendZc::new(types::Fd(fd), buf, 7)
                .flags(3)
                .zc_flags(2)
                .buf_index(Some(5))
                .build(),
            |sqe| ops::net::prep_send_zc_fixed(sqe, fd, buf, 7, 3, 2, BufferId(5)),
        );
        check(
            opcode::Recv::new(types::Fd(fd), buf, 9).flags(2).build(),
            |sqe| ops::net::prep_recv(sqe, fd, buf, 9, 2),
        );
        check(
            opcode::RecvMulti::new(types::Fd(fd), 5).flags(2).build(),
            |sqe| ops::net::prep_recv_multishot(sqe, fd, BufferGroupId(5), 2),
        );
        check(
            opcode::SendMsg::new(types::Fd(fd), msg).flags(2).build(),
            |sqe| ops::net::prep_sendmsg(sqe, fd, msg, 2),
        );
        check(
            opcode::RecvMsg::new(types::Fd(fd), msg).flags(2).build(),
            |sqe| ops::net::prep_recvmsg(sqe, fd, msg, 2),
        );
        check(
            opcode::Connect::new(types::Fd(fd), addr, 16).build(),
            |sqe| ops::net::prep_connect(sqe, fd, addr, 16),
        );
        check(
            opcode::Accept::new(types::Fd(fd), addr, addrlen)
                .flags(2)
                .build(),
            |sqe| ops::net::prep_accept(sqe, fd, addr, addrlen, 2),
        );
        let mut multi = opcode::Accept::new(types::Fd(fd), addr, addrlen)
            .flags(2)
            .build();
        multi.ioprio = 1;
        check(multi, |sqe| {
            ops::net::prep_multishot_accept(sqe, fd, addr, addrlen, 2)
        });
        let mut cancel = opcode::AsyncCancel::new(target.raw()).build();
        cancel.operation_flags = 4;
        check(cancel, |sqe| ops::net::prep_cancel(sqe, target, 4));
        let mut cancel_fd = opcode::AsyncCancel::new(0).build();
        cancel_fd.fd = fd;
        cancel_fd.operation_flags = 6;
        check(cancel_fd, |sqe| ops::net::prep_cancel_fd(sqe, fd, 4));
        check(
            opcode::PollAdd::new(types::Fd(fd), 0x1234_5678).build(),
            |sqe| ops::net::prep_poll_add(sqe, fd, 0x1234_5678),
        );
        check(
            opcode::PollAdd::new(types::Fd(fd), 3).multi(true).build(),
            |sqe| ops::net::prep_poll_multishot(sqe, fd, 3),
        );
        check(opcode::PollRemove::new(target.raw()).build(), |sqe| {
            ops::net::prep_poll_remove(sqe, target)
        });
        check(opcode::Close::new(types::Fd(fd)).build(), |sqe| {
            ops::net::prep_close(sqe, fd)
        });
        let mut close = opcode::Close::new(types::Fd(0)).build();
        close.splice_fd_in = 6;
        check(close, |sqe| {
            ops::net::prep_close_direct(sqe, UringFileSlot(5))
        });
        check(
            opcode::Read::new(types::Fd(fd), buf, 11).offset(29).build(),
            |sqe| ops::fs::prep_read(sqe, fd, buf, 11, 29),
        );
        check(
            opcode::Write::new(types::Fd(fd), buf, 11)
                .offset(29)
                .build(),
            |sqe| ops::fs::prep_write(sqe, fd, buf, 11, 29),
        );
        check(
            opcode::Readv::new(types::Fd(fd), iov, 2).offset(29).build(),
            |sqe| ops::fs::prep_readv(sqe, fd, iov, 2, 29),
        );
        check(
            opcode::Writev::new(types::Fd(fd), iov, 2)
                .offset(29)
                .build(),
            |sqe| ops::fs::prep_writev(sqe, fd, iov, 2, 29),
        );
        check(
            opcode::ReadFixed::new(types::Fd(fd), buf, 11, 5)
                .offset(29)
                .build(),
            |sqe| ops::fs::prep_read_fixed(sqe, fd, buf, 11, 29, BufferId(5)),
        );
        check(
            opcode::WriteFixed::new(types::Fd(fd), buf, 11, 5)
                .offset(29)
                .build(),
            |sqe| ops::fs::prep_write_fixed(sqe, fd, buf, 11, 29, BufferId(5)),
        );
        check(
            opcode::ReadvFixed::new(types::Fd(fd), iov, 2, 5)
                .offset(29)
                .build(),
            |sqe| ops::fs::prep_readv_fixed(sqe, fd, iov, 2, 29, BufferId(5)),
        );
        check(
            opcode::WritevFixed::new(types::Fd(fd), iov, 2, 5)
                .offset(29)
                .build(),
            |sqe| ops::fs::prep_writev_fixed(sqe, fd, iov, 2, 29, BufferId(5)),
        );
    }
}

#[test]
fn close_retry_preserves_pending_links() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 8,
        staged_capacity: 1,
        operation_capacity: 8,
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(
        &mut ring,
        SocketIoConfig {
            sockets: 2,
            operations: 1024,
            send_buffers: 2,
            receive_buffers: 2,
            buffer_len: 64,
            ..SocketIoConfig::default()
        },
    )?;
    let (local, _peer) = UnixStream::pair()?;
    let socket = io.insert(local.into())?;
    io.receive(&mut ring, socket, ReceiveMode::Multishot)?;
    assert!(matches!(
        io.send(&mut ring, socket, b"rollback", false),
        Err(liburing::UringError::SqRingFull)
    ));
    assert_eq!(io.operation_count(), 1);
    // SAFETY: The rejected send was never published and its token has been returned.
    assert_eq!(unsafe { ring.fixed_buffers() }?.available(), 2);
    ring.submit()?;
    let trigger = liburing::OperationId::from_raw(0x0100_0000_0000_0042);
    let filler = liburing::OperationId::from_raw(0x0100_0000_0000_0043);
    ring.prepare_sqe_with(trigger, |sqe| {
        // SAFETY: The proactor supplies exclusive initialized SQE storage; NOP has no operands.
        unsafe { liburing::ops::prep_nop(sqe) };
    })?;
    let mut rejected = false;
    ring.wait_completions(
        1,
        Some(Duration::from_secs(1)),
        &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.operation_id, trigger);
            context.prepare_sqe_with(filler, |sqe| {
                // SAFETY: The callback supplies exclusive initialized SQE storage; NOP has no
                // operands.
                unsafe { liburing::ops::prep_nop(sqe) };
            })?;
            assert!(matches!(
                io.close_with_context(context, socket),
                Err(liburing::UringError::SqRingFull)
            ));
            rejected = true;
            Ok(())
        },
    )?;
    assert!(rejected);
    assert_eq!(io.operation_count(), 1);
    ring.wait_completions(
        1,
        Some(Duration::from_secs(1)),
        &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
            assert_eq!(cqe.operation_id, filler);
            Ok(())
        },
    )?;
    io.close(&mut ring, socket)?;
    let mut worker = WorkerState::default();
    drive(&mut ring, &mut io, &mut worker, |_, io| {
        io.socket_count() == 0
    })?;
    assert_eq!(worker.closed, 1);
    assert_eq!(io.operation_count(), 0);
    assert_eq!(ring.operation_count(), 0);
    ring.shutdown()
}

#[test]
fn completed_tail_preserves_receive_head() -> Result<()> {
    let (mut ring, mut io) = ring_and_io()?;
    let (local, _peer) = UnixStream::pair()?;
    let socket = io.insert(local.into())?;
    io.send(&mut ring, socket, b"tail", false)?;
    io.send(&mut ring, socket, b"middle", false)?;
    io.receive(&mut ring, socket, ReceiveMode::Multishot)?;
    let mut worker = WorkerState::default();
    drive(&mut ring, &mut io, &mut worker, |worker, _| {
        worker.sent == 10
    })?;
    assert_eq!(io.operation_count(), 1);
    io.close(&mut ring, socket)?;
    drive(&mut ring, &mut io, &mut worker, |_, io| {
        io.socket_count() == 0
    })?;
    assert_eq!(worker.cancelled, 1);
    assert_eq!(io.operation_count(), 0);
    ring.shutdown()
}

#[test]
fn cancel_event_precedes_descriptor_retirement() -> Result<()> {
    let (mut ring, mut io) = ring_and_io()?;
    let (local, _peer) = UnixStream::pair()?;
    let fd = local.as_raw_fd();
    let socket = io.insert(local.into())?;
    io.receive(&mut ring, socket, ReceiveMode::Multishot)?;
    ring.submit()?;
    io.close(&mut ring, socket)?;
    let mut events = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while events.len() != 2 {
        assert!(Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe, context: &mut SubmissionContext<'_>| {
                io.on_completion(cqe, context, |event| {
                    match event {
                        SocketEvent::Cancelled { socket: actual, .. } => {
                            assert_eq!(actual, socket);
                            // SAFETY: F_GETFD queries descriptor liveness without borrowing DMA
                            // storage.
                            assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                            events.push("cancelled");
                        }
                        SocketEvent::Closed { socket: actual } => {
                            assert_eq!(actual, socket);
                            // SAFETY: F_GETFD only queries the old descriptor number after
                            // retirement.
                            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                            events.push("closed");
                        }
                        _ => panic!("unexpected cancellation event"),
                    }
                    Ok(())
                })
            },
        )?;
    }
    assert_eq!(events, ["cancelled", "closed"]);
    assert_eq!(io.socket_count(), 0);
    ring.shutdown()
}

#[test]
fn callback_failure_defers_closed_notification() -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig::default())?;
    let mut io = CompletionSocketIo::new(
        &mut ring,
        SocketIoConfig {
            sockets: 1,
            operations: 4,
            receive_buffers: 2,
            send_buffers: 1,
            buffer_len: 64,
            ..SocketIoConfig::default()
        },
    )?;
    let (local, _peer) = UnixStream::pair()?;
    let fd = local.as_raw_fd();
    let socket = io.insert(local.into())?;
    io.receive(&mut ring, socket, ReceiveMode::Multishot)?;
    ring.submit()?;
    io.close(&mut ring, socket)?;
    let mut observed = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !observed {
        assert!(Instant::now() < deadline);
        ring.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |cqe, context: &mut SubmissionContext<'_>| {
                let failure = liburing::UringError::InvalidConfig("application callback failed");
                assert_eq!(
                    io.on_completion(cqe, context, |event| {
                        assert!(matches!(event, SocketEvent::Cancelled { .. }));
                        Err(failure)
                    }),
                    Err(failure)
                );
                assert_eq!(io.operation_count(), 0);
                assert_eq!(io.socket_count(), 1);
                for forged in [
                    Completion {
                        result: cqe.result ^ 1,
                        ..cqe
                    },
                    Completion {
                        flags: cqe.flags ^ 1,
                        ..cqe
                    },
                ] {
                    assert!(
                        io.on_completion(forged, context, |_| panic!(
                            "forged retry delivered an event"
                        ))
                        .is_err()
                    );
                    assert_eq!(io.socket_count(), 1);
                }
                // SAFETY: The terminal operation has completed, but the closing slot must retain
                // its fd.
                assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                let (replacement, _) = UnixStream::pair()?;
                assert_eq!(
                    io.insert(replacement.into()),
                    Err(liburing::UringError::FixedFileSlotsExhausted)
                );
                io.on_completion(cqe, context, |event| {
                    assert!(
                        matches!(event, SocketEvent::Closed { socket: actual } if actual == socket)
                    );
                    // SAFETY: F_GETFD only queries the retired descriptor number.
                    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                    Ok(())
                })?;
                assert_eq!(io.socket_count(), 0);
                assert!(
                    io.on_completion(cqe, context, |_| panic!(
                        "replayed completion notified twice"
                    ))
                    .is_err()
                );
                observed = true;
                Ok(())
            },
        )?;
    }
    let (replacement, _) = UnixStream::pair()?;
    let replacement = io.insert(replacement.into())?;
    assert_ne!(replacement, socket);
    io.close(&mut ring, replacement)?;
    ring.shutdown()
}
