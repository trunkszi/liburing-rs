//! Single-ring network, timeout, and control-plane end-to-end checks.

use std::{
    cell::RefCell,
    net::{TcpListener, TcpStream, UdpSocket},
    os::fd::{AsRawFd, RawFd},
    rc::Rc,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use liburing::{
    Completion, CrossThreadCommandQueue, OpId, OpPayload, Proactor, ProactorConfig, Result,
    SubmissionContext, SubsystemHandler, SubsystemId, UringError,
    ops::{Timeout, net},
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
const TIMEOUT_PAYLOAD: u64 = 100;

fn op(payload: u64) -> OpId {
    OpId::pack(
        SubsystemId::new_unchecked(74),
        OpPayload::new_unchecked(payload),
    )
}

struct Transfer {
    source: RawFd,
    destination: RawFd,
    datagram: bool,
    sent: Box<[u8]>,
    received: Box<[u8]>,
    send_offset: usize,
    receive_offset: usize,
    send_cqes: usize,
    receive_cqes: usize,
}

impl Transfer {
    fn new(source: RawFd, destination: RawFd, datagram: bool, seed: u8, len: usize) -> Self {
        Self {
            source,
            destination,
            datagram,
            sent: (0..len)
                .map(|index| seed.wrapping_add(index as u8))
                .collect(),
            received: vec![0; len].into_boxed_slice(),
            send_offset: 0,
            receive_offset: 0,
            send_cqes: 0,
            receive_cqes: 0,
        }
    }

    fn prepare(&mut self, receive: bool, sqe: *mut liburing_sys::io_uring_sqe) {
        if receive {
            let remaining = self.received.len() - self.receive_offset;
            let pointer = self.received.as_mut_ptr().wrapping_add(self.receive_offset);
            // SAFETY: The callback supplies exclusive SQE storage. Each receive
            // owns a disjoint boxed destination retained by the registered
            // handler through its final CQE and ring shutdown on every exit.
            unsafe { net::prep_recv(sqe, self.destination, pointer, remaining, 0) };
        } else {
            let remaining = self.sent.len() - self.send_offset;
            let pointer = self.sent.as_ptr().wrapping_add(self.send_offset);
            // SAFETY: SQE storage is exclusive. The immutable boxed source and
            // descriptor remain handler-owned through the send final CQE; no
            // receive writes this source allocation.
            unsafe { net::prep_send(sqe, self.source, pointer, remaining, libc::MSG_NOSIGNAL) };
        }
    }

    fn done(&self) -> bool {
        self.send_offset == self.sent.len() && self.receive_offset == self.received.len()
    }
}

struct EndpointState {
    // These owners also keep descriptors alive if an assertion unwinds while
    // the proactor cancels and drains other outstanding network operations.
    _tcp: [TcpStream; 2],
    _udp: [UdpSocket; 2],
    transfers: [Transfer; 4],
    timeout: Timeout,
    timer_done: bool,
    network_cqes: usize,
}

impl EndpointState {
    fn done(&self) -> bool {
        self.timer_done && self.transfers.iter().all(Transfer::done)
    }
}

struct EndpointHandler(Rc<RefCell<EndpointState>>);

impl SubsystemHandler for EndpointHandler {
    fn on_completion(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        // Cancellation on an error exit must not resubmit or panic during Drop.
        if completion.result == -libc::ECANCELED {
            return Ok(());
        }
        assert_eq!(completion.flags & liburing_sys::IORING_CQE_F_MORE, 0);
        let payload = completion.op_id.payload().raw();
        if payload == TIMEOUT_PAYLOAD {
            assert!(!state.timer_done, "duplicate timeout completion");
            assert_eq!(completion.result, -libc::ETIME);
            state.timer_done = true;
            return Ok(());
        }
        if completion.result < 0 {
            return Err(UringError::Wait(-completion.result));
        }
        assert!(completion.result > 0, "unexpected zero-length network CQE");
        state.network_cqes += 1;
        let receive = payload & 1 != 0;
        let transfer = &mut state.transfers[(payload / 2) as usize];
        let (offset, length) = if receive {
            transfer.receive_cqes += 1;
            (&mut transfer.receive_offset, transfer.received.len())
        } else {
            transfer.send_cqes += 1;
            (&mut transfer.send_offset, transfer.sent.len())
        };
        let count = completion.result as usize;
        assert!(count <= length - *offset, "CQE exceeds submitted extent");
        if transfer.datagram {
            assert_eq!(count, length, "UDP datagram must remain atomic");
        }
        *offset += count;
        if *offset < length {
            submissions.prepare_sqe_with(completion.op_id, |sqe| transfer.prepare(receive, sqe))?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Stop,
}

#[test]
fn e2e_one_ring_full_duplex_tcp_udp_timeout_and_cross_thread_stop() -> TestResult {
    let _serial = crate::kernel_test_lock();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    // Connection setup is synchronous; every payload send and receive below is
    // submitted to the same owner-thread ring, with no synchronous peer actor.
    let tcp_client = TcpStream::connect(listener.local_addr()?)?;
    let (tcp_server, _) = listener.accept()?;
    tcp_client.set_nodelay(true)?;
    tcp_server.set_nodelay(true)?;
    let udp_client = UdpSocket::bind("127.0.0.1:0")?;
    let udp_server = UdpSocket::bind("127.0.0.1:0")?;
    udp_client.connect(udp_server.local_addr()?)?;
    udp_server.connect(udp_client.local_addr()?)?;
    let transfers = [
        Transfer::new(
            tcp_client.as_raw_fd(),
            tcp_server.as_raw_fd(),
            false,
            3,
            241,
        ),
        Transfer::new(
            tcp_server.as_raw_fd(),
            tcp_client.as_raw_fd(),
            false,
            57,
            219,
        ),
        Transfer::new(
            udp_client.as_raw_fd(),
            udp_server.as_raw_fd(),
            true,
            101,
            173,
        ),
        Transfer::new(
            udp_server.as_raw_fd(),
            udp_client.as_raw_fd(),
            true,
            193,
            197,
        ),
    ];
    let state = Rc::new(RefCell::new(EndpointState {
        _tcp: [tcp_client, tcp_server],
        _udp: [udp_client, udp_server],
        transfers,
        timeout: Timeout::new(Duration::from_millis(10))?,
        timer_done: false,
        network_cqes: 0,
    }));
    // Declaration order and registered ownership retain every DMA allocation
    // through ring teardown, including early errors and assertion unwinding.
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 32,
        staged_capacity: 32,
        max_cqe_batch: 32,
        enable_waker: true,
        ..ProactorConfig::default()
    })?;
    proactor.register_subsystem(
        SubsystemId::new_unchecked(74),
        EndpointHandler(Rc::clone(&state)),
    )?;
    let waker = proactor.waker().ok_or("control-plane waker missing")?;
    let commands = CrossThreadCommandQueue::new(1, waker.clone());
    let producer_commands = commands.clone();
    let (release_stop, may_stop) = mpsc::sync_channel(0);
    let producer = thread::spawn(move || -> Result<()> {
        may_stop
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| UringError::InvalidConfig("network completion handshake timed out"))?;
        producer_commands.push(Command::Stop)
    });
    for index in 0..4 {
        for receive in [false, true] {
            proactor.prepare_sqe_with(op((index * 2 + usize::from(receive)) as u64), |sqe| {
                state.borrow_mut().transfers[index].prepare(receive, sqe);
            })?;
        }
    }
    proactor.prepare_sqe_with(op(TIMEOUT_PAYLOAD), |sqe| {
        // SAFETY: SQE storage is exclusive and the registered handler retains
        // the stable timeout operand through final CQE or ring shutdown.
        unsafe { state.borrow().timeout.prepare(sqe) };
    })?;
    let mut observed = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    while !state.borrow().done() && Instant::now() < deadline {
        proactor.wait_completions(1, Some(Duration::from_millis(100)), |completion, _| {
            assert_eq!(completion.op_id.subsystem_id(), SubsystemId(74));
            observed += 1;
            Ok(())
        })?;
    }
    {
        let state = state.borrow();
        assert!(state.done(), "network and timeout CQEs did not all arrive");
        assert!(state.network_cqes >= 8);
        assert_eq!(observed, state.network_cqes + 1);
        for transfer in &state.transfers {
            assert_eq!(transfer.received.as_ref(), transfer.sent.as_ref());
            assert_eq!(transfer.send_offset, transfer.sent.len());
            assert_eq!(transfer.receive_offset, transfer.received.len());
            assert!(transfer.send_cqes >= 1 && transfer.receive_cqes >= 1);
        }
    }
    // Stop can only be published after both protocols, both directions, and
    // the real kernel timeout finish. Only the internal wake poll remains.
    assert!(commands.is_empty()?);
    release_stop.send(())?;
    let mut stopped = false;
    let mut wake_batches = 0;
    let stop_deadline = Instant::now() + Duration::from_secs(3);
    while !stopped && Instant::now() < stop_deadline {
        wake_batches +=
            proactor.wait_completions(1, Some(Duration::from_millis(100)), |_, _| {
                Err(UringError::InvalidConfig(
                    "application CQE after completed traffic",
                ))
            })?;
        let drained = commands.drain_with(|command| {
            assert_eq!(command, Command::Stop);
            assert!(!stopped, "duplicate stop command");
            stopped = true;
        });
        assert!(drained <= 1);
    }
    producer.join().map_err(|_| "stop producer panicked")??;
    assert!(stopped, "control-plane stop did not wake idle event loop");
    assert!(
        wake_batches > 0,
        "stop command did not complete the kernel wake poll"
    );
    assert!(commands.is_empty()?);
    proactor.shutdown()?;
    assert!(waker.is_closed());
    assert!(proactor.submit().is_err());
    assert!(proactor.alloc_sqe(op(9)).is_err());
    Ok(())
}
