//! One caller-owned worker drives socket, timer, and audit completion routing.

use std::{
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};

use liburing::{
    OperationId, OperationPayload, Proactor, ProactorConfig, Result, SubsystemId, UringError,
    ops::Timeout,
    socket_io::{CompletionSocketIo, ReceiveMode, SocketEvent, SocketId, SocketIoConfig},
};
use liburing_macros::define_subsystems;
use static_assertions as _;

define_subsystems! { enum Routes { Socket = 1, Timer = 2, Audit = 3 } }

struct WorkerState {
    io: CompletionSocketIo,
    received: Vec<u8>,
    sent: usize,
    timer_done: bool,
    audit_done: bool,
    timer: Timeout,
}

fn operation(route: Routes, payload: u64) -> OperationId {
    OperationId::pack(
        SubsystemId::new_unchecked(route.id()),
        OperationPayload::new_unchecked(payload),
    )
}

fn turn(proactor: &mut Proactor, state: &mut WorkerState) -> Result<usize> {
    let mut dispatcher = Routes::dispatcher(state, |route, state, cqe, context| match route {
        Routes::Socket => {
            let WorkerState {
                io, received, sent, ..
            } = state;
            io.on_completion(cqe, context, |event| {
                match event {
                    SocketEvent::Received { data, .. } => received.extend_from_slice(&data),
                    SocketEvent::Sent { bytes, .. } => *sent += bytes,
                    SocketEvent::Error { errno, .. } => {
                        return Err(UringError::syscalls("worker socket", errno));
                    }
                    _ => {}
                }
                Ok(())
            })
        }
        Routes::Timer => {
            assert_eq!(cqe.result, -libc::ETIME);
            state.timer_done = true;
            Ok(())
        }
        Routes::Audit => {
            assert_eq!(cqe.result, 0);
            state.audit_done = true;
            Ok(())
        }
    });
    proactor.wait_completions(1, Some(Duration::from_millis(25)), &mut dispatcher)
}

fn prepare() -> Result<(Proactor, WorkerState, SocketId, SocketId)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let left = TcpStream::connect(listener.local_addr()?)?;
    let (right, _) = listener.accept()?;
    let mut ring = Proactor::new(ProactorConfig {
        entries: 32,
        staged_capacity: 32,
        ..ProactorConfig::default()
    })?;
    let mut io = CompletionSocketIo::new(
        &mut ring,
        SocketIoConfig {
            sockets: 4,
            operations: 32,
            receive_buffers: 8,
            send_buffers: 8,
            ..SocketIoConfig::default()
        },
    )?;
    let left = io.insert(left.into())?;
    let right = io.insert(right.into())?;
    Ok((
        ring,
        WorkerState {
            io,
            received: Vec::new(),
            sent: 0,
            timer_done: false,
            audit_done: false,
            timer: Timeout::new(Duration::from_millis(10))?,
        },
        left,
        right,
    ))
}

fn finish(
    ring: &mut Proactor,
    state: &mut WorkerState,
    left: SocketId,
    right: SocketId,
) -> Result<()> {
    state.io.close(ring, left)?;
    state.io.close(ring, right)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while state.io.operation_count() != 0 {
        assert!(Instant::now() < deadline);
        turn(ring, state)?;
    }
    assert_eq!(state.io.socket_count(), 0);
    assert_eq!(ring.operation_count(), 0);
    ring.shutdown()
}

#[test]
fn e2e_network_timer_and_audit_share_one_mutable_worker() -> Result<()> {
    let (mut ring, mut state, left, right) = prepare()?;
    state.io.receive(&mut ring, right, ReceiveMode::Multishot)?;
    state
        .io
        .send(&mut ring, left, b"one shared worker", false)?;
    ring.alloc_sqe(operation(Routes::Audit, 7))?;
    ring.prepare_sqe_with(operation(Routes::Timer, 8), |sqe| {
        // SAFETY: The caller retains the stable timeout operand through final CQE.
        unsafe { state.timer.prepare(sqe) };
    })?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while !(state.timer_done
        && state.audit_done
        && state.received == b"one shared worker"
        && state.sent == 17)
    {
        assert!(Instant::now() < deadline);
        turn(&mut ring, &mut state)?;
    }
    finish(&mut ring, &mut state, left, right)
}

#[test]
fn scenario_repeated_selected_receives_replenish_without_copying_pool_storage() -> Result<()> {
    let (mut ring, mut state, left, right) = prepare()?;
    state.io.receive(&mut ring, right, ReceiveMode::Multishot)?;
    for value in 0..64u8 {
        let count = state.received.len() + 1;
        state.io.send(&mut ring, left, &[value], false)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while state.received.len() < count || state.sent < count {
            assert!(Instant::now() < deadline);
            turn(&mut ring, &mut state)?;
        }
    }
    assert_eq!(state.received, (0..64u8).collect::<Vec<_>>());
    finish(&mut ring, &mut state, left, right)
}
