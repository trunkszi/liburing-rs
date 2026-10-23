//! True TCP and Unix completion I/O with provided receives and retained fixed sends.

use std::{
    net::{TcpListener, TcpStream},
    os::{fd::OwnedFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

use liburing::{
    Completion, CompletionDispatcher, Proactor, ProactorConfig, Result, SubmissionContext,
    UringError,
    socket_io::{CompletionSocketIo, ReceiveMode, SocketEvent, SocketId, SocketIoConfig},
};

struct Worker {
    io: CompletionSocketIo,
    left: SocketId,
    client: Vec<u8>,
    server: Vec<u8>,
    sent: usize,
}
impl CompletionDispatcher for Worker {
    fn dispatch(&mut self, cqe: Completion, context: &mut SubmissionContext<'_>) -> Result<()> {
        let Worker {
            io,
            left,
            client,
            server,
            sent,
        } = self;
        io.on_completion(cqe, context, |event| {
            match event {
                SocketEvent::Received { socket, data, .. } if socket == *left => {
                    client.extend_from_slice(&data)
                }
                SocketEvent::Received { data, .. } => server.extend_from_slice(&data),
                SocketEvent::Sent { bytes, .. } => *sent += bytes,
                SocketEvent::Error { errno, .. } => {
                    return Err(UringError::syscalls("socket transfer", errno));
                }
                SocketEvent::BufferUnavailable { .. } => {
                    return Err(UringError::InvalidConfig("receive pool exhausted"));
                }
                _ => {}
            }
            Ok(())
        })
    }
}

fn exchange(left: OwnedFd, right: OwnedFd, zero_copy: bool) -> Result<()> {
    let mut ring = Proactor::new(ProactorConfig {
        entries: 32,
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(
        &mut ring,
        SocketIoConfig {
            sockets: 2,
            operations: 16,
            send_buffers: 4,
            receive_buffers: 4,
            buffer_len: 4096,
            ..SocketIoConfig::default()
        },
    )?;
    let left = io.insert(left)?;
    let right = io.insert(right)?;
    io.receive(&mut ring, left, ReceiveMode::Once)?;
    io.receive(&mut ring, right, ReceiveMode::Once)?;
    io.send(&mut ring, left, b"ping", zero_copy)?;
    let mut worker = Worker {
        io,
        left,
        client: Vec::new(),
        server: Vec::new(),
        sent: 0,
    };
    let mut echoed = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while worker.client != b"pong" || worker.sent != 8 || worker.io.operation_count() != 0 {
        if Instant::now() >= deadline {
            return Err(UringError::Wait(libc::ETIMEDOUT));
        }
        ring.wait_completions(1, Some(Duration::from_millis(100)), &mut worker)?;
        if !echoed && worker.server == b"ping" {
            worker.io.send(&mut ring, right, b"pong", zero_copy)?;
            echoed = true;
        }
    }
    worker.io.close(&mut ring, left)?;
    worker.io.close(&mut ring, right)?;
    if ring.operation_count() != 0 || worker.io.socket_count() != 0 {
        return Err(UringError::InvalidConfig("socket resources did not retire"));
    }
    ring.shutdown()
}

fn main() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let client = TcpStream::connect(listener.local_addr()?)?;
    let (server, _) = listener.accept()?;
    exchange(client.into(), server.into(), true)?;
    let (client, server) = UnixStream::pair()?;
    exchange(client.into(), server.into(), false)?;
    println!(
        "TCP SendZc notification and Unix Send/Recv exchanges passed with BufferLease payloads."
    );
    Ok(())
}
