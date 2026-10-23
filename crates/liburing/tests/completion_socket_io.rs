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
use liburing_macros as _;
use static_assertions as _;

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
fn integration_tcp_recv_select_has_payload_at_cqe_handoff() -> Result<()> {
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
fn e2e_unix_multishot_receives_multiple_transfers_without_readiness_polling() -> Result<()> {
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
fn lifecycle_cancel_holds_descriptor_until_receive_final_cqe() -> Result<()> {
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
fn scenario_send_zc_releases_fixed_buffer_only_after_notification() -> Result<()> {
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
fn lifecycle_cancel_remains_available_with_every_operation_slot_occupied() -> Result<()> {
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
