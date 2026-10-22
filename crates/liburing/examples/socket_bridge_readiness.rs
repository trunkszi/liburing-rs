//! Adapt an external nonblocking socket state machine to real io_uring CQEs.
//!
//! The bridge records desired readiness; its adapter translates staged operations
//! into SQEs. Clear interest to remove a readiness subscription, and use `close`
//! to remove a socket only after its target and control CQEs have retired.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    io::{self, Write},
    net::{SocketAddr, TcpListener},
    os::fd::RawFd,
    rc::Rc,
    time::{Duration, Instant},
};

use liburing::{
    Completion, OpId, OpPayload, Proactor, SubmissionContext, SubsystemHandler, SubsystemId,
    UringError,
    ops::net,
    socket_bridge::{
        BridgeEvent, BridgeOpKind, BridgeSubmission, SocketInterest, UringSocketBridge,
        UringSocketOps,
    },
};

type ExampleResult<T = ()> = Result<T, Box<dyn Error>>;
type StagingQueue = Rc<RefCell<VecDeque<(OpId, BridgeSubmission<OpId>)>>>;
type Bridge = UringSocketBridge<Adapter>;
const ROUTE: SubsystemId = SubsystemId(1);
const CLIENTS: usize = 3;
const PAYLOAD: &[u8] = b"loopback readiness via io_uring";

struct Adapter(StagingQueue);

impl UringSocketOps for Adapter {
    type OpId = OpId;
    type Error = UringError;

    fn subsystem_id(&self) -> SubsystemId {
        ROUTE
    }

    fn submit(&mut self, token: u64, op: BridgeSubmission<OpId>) -> liburing::Result<OpId> {
        let payload = OpPayload::new(token).ok_or(UringError::InvalidPayload(token))?;
        let id = OpId::pack(ROUTE, payload);
        self.0.borrow_mut().push_back((id, op));
        Ok(id)
    }
}

#[derive(Default)]
struct Resources {
    sockets: HashSet<RawFd>,
    close_ids: HashMap<OpId, RawFd>,
    // Boxed pointees stay stable when the map grows, and survive shutdown.
    addresses: HashMap<OpId, Box<libc::sockaddr_in>>,
}

impl Drop for Resources {
    fn drop(&mut self) {
        for fd in self.sockets.drain() {
            // SAFETY: Each remaining descriptor is uniquely owned here, and
            // the registered handler retains Resources through ring shutdown.
            unsafe { libc::close(fd) };
        }
    }
}

struct CompletionOwner(Rc<RefCell<Resources>>);

impl SubsystemHandler for CompletionOwner {
    fn on_completion(
        &mut self,
        completion: Completion,
        _: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        if completion.flags & liburing_sys::IORING_CQE_F_MORE == 0 {
            let mut resources = self.0.borrow_mut();
            resources.addresses.remove(&completion.op_id);
            if let Some(fd) = resources.close_ids.remove(&completion.op_id)
                && completion.result != -libc::ECANCELED
            {
                // A final Linux close consumes ownership, including error
                // results; only cancellation means the close did not execute.
                resources.sockets.remove(&fd);
            }
        }
        Ok(())
    }
}

struct Driver {
    queue: StagingQueue,
    resources: Rc<RefCell<Resources>>,
    events: Vec<BridgeEvent>,
    started: Instant,
}

impl Driver {
    fn check_deadline(&self) -> ExampleResult {
        if self.started.elapsed() > Duration::from_secs(10) {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "bridge deadline expired").into());
        }
        Ok(())
    }

    fn flush(&mut self, proactor: &mut Proactor) -> ExampleResult {
        loop {
            let Some((id, op)) = self.queue.borrow().front().copied() else {
                break;
            };
            let address = match op {
                BridgeSubmission::Connect {
                    address: SocketAddr::V4(address),
                    ..
                } => {
                    let address = Box::new(libc::sockaddr_in {
                        sin_family: libc::AF_INET as _,
                        sin_port: address.port().to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(address.ip().octets()),
                        },
                        sin_zero: [0; 8],
                    });
                    let pointer = address.as_ref() as *const libc::sockaddr_in;
                    self.resources.borrow_mut().addresses.insert(id, address);
                    pointer.cast::<libc::sockaddr>()
                }
                BridgeSubmission::Connect { .. } => {
                    return Err(io::Error::other("this example uses IPv4 loopback").into());
                }
                BridgeSubmission::Close { fd } => {
                    self.resources.borrow_mut().close_ids.insert(id, fd);
                    std::ptr::null()
                }
                _ => std::ptr::null(),
            };
            proactor.prepare_sqe_with(id, |sqe| {
                // SAFETY: The callback exclusively owns this unpublished SQE.
                // Connect addresses are boxed in handler-owned Resources until
                // their final CQE; fds remain owned until the final close CQE.
                // Control operations reference exact, unique bridge target IDs.
                unsafe {
                    match op {
                        BridgeSubmission::Connect { fd, .. } => net::prep_connect(
                            sqe,
                            fd,
                            address,
                            std::mem::size_of::<libc::sockaddr_in>() as _,
                        ),
                        BridgeSubmission::PollAdd { fd, interest } => {
                            net::prep_poll_add(sqe, fd, interest.poll_mask())
                        }
                        BridgeSubmission::PollRemove { target, .. } => {
                            net::prep_poll_remove(sqe, target)
                        }
                        BridgeSubmission::Cancel { target, .. } => {
                            liburing_sys::uring_shim_prep_cancel64(sqe, target.raw(), 0)
                        }
                        BridgeSubmission::Close { fd } => net::prep_close(sqe, fd),
                    }
                }
            })?;
            self.queue.borrow_mut().pop_front();
        }
        proactor.submit()?;
        Ok(())
    }

    fn batch(&mut self, proactor: &mut Proactor, bridge: &mut Bridge) -> ExampleResult {
        self.check_deadline()?;
        bridge.drive()?;
        self.flush(proactor)?;
        let mut failure = None;
        proactor.wait_completions(1, Some(Duration::from_millis(50)), |completion, _| {
            if let Some(event) = bridge.on_completion(completion) {
                if event.kind == BridgeOpKind::PollAdd && !event.interest.is_empty() {
                    // Consume one readiness notification; the application
                    // decides whether a subsequent poll is required.
                    if let Err(error) = bridge.set_interest(event.fd, SocketInterest::EMPTY) {
                        failure = Some(error);
                    }
                }
                self.events.push(event);
            }
            Ok(())
        })?;
        if let Some(error) = failure {
            return Err(error.into());
        }
        Ok(())
    }

    fn count_since(&self, start: usize, kind: BridgeOpKind) -> usize {
        self.events[start..]
            .iter()
            .filter(|event| event.kind == kind)
            .count()
    }
}

fn main() -> ExampleResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let queue = Rc::new(RefCell::new(VecDeque::new()));
    let resources = Rc::new(RefCell::new(Resources::default()));
    let mut bridge = Bridge::new(ROUTE, Adapter(Rc::clone(&queue)), 1)?;
    let mut driver = Driver {
        queue,
        resources: Rc::clone(&resources),
        events: Vec::new(),
        started: Instant::now(),
    };
    // Declared after resources so error unwinding shuts down the ring first.
    // Handler ownership also preserves pointer operands if shutdown fails.
    let mut proactor = Proactor::builder().entries(32).build()?;
    proactor.register_subsystem(ROUTE, CompletionOwner(Rc::clone(&resources)))?;
    let mut clients = Vec::new();
    let connect_start = driver.events.len();
    for _ in 0..CLIENTS {
        // SAFETY: socket has no pointer arguments and creates a fresh fd.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        resources.borrow_mut().sockets.insert(fd);
        bridge.register(fd)?;
        bridge.connect(fd, address)?;
        clients.push(fd);
    }
    println!("Registered {CLIENTS} nonblocking sockets from initial bridge capacity 1.");
    while driver.count_since(connect_start, BridgeOpKind::Connect) < CLIENTS {
        driver.batch(&mut proactor, &mut bridge)?;
    }
    for event in driver.events[connect_start..]
        .iter()
        .filter(|event| event.kind == BridgeOpKind::Connect)
    {
        if event.result != 0 || !event.interest.contains(SocketInterest::WRITABLE) {
            return Err(io::Error::other(format!("connect failed: {event:?}")).into());
        }
    }
    println!("Connect: all loopback connection CQEs reported writable.");
    let mut peers = Vec::new();
    while peers.len() < CLIENTS {
        driver.check_deadline()?;
        match listener.accept() {
            Ok((peer, _)) => peers.push(peer),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(error) => return Err(error.into()),
        }
    }
    let writable_start = driver.events.len();
    for &fd in &clients {
        bridge.set_interest(fd, SocketInterest::WRITABLE)?;
    }
    while driver.count_since(writable_start, BridgeOpKind::PollAdd) < CLIENTS {
        driver.batch(&mut proactor, &mut bridge)?;
    }
    for event in driver.events[writable_start..]
        .iter()
        .filter(|event| event.kind == BridgeOpKind::PollAdd)
    {
        if event.result < 0 || !event.interest.contains(SocketInterest::WRITABLE) {
            return Err(io::Error::other(format!("writable poll failed: {event:?}")).into());
        }
    }
    println!("Writable: native polls completed; subscriptions cleared after delivery.");
    for peer in &mut peers {
        peer.set_write_timeout(Some(Duration::from_secs(1)))?;
        peer.write_all(PAYLOAD)?;
    }
    let mut received: HashMap<RawFd, Vec<u8>> =
        clients.iter().map(|&fd| (fd, Vec::new())).collect();
    for &fd in &clients {
        bridge.set_interest(fd, SocketInterest::READABLE)?;
    }
    let mut next_event = driver.events.len();
    while received.values().any(|bytes| bytes.len() < PAYLOAD.len()) {
        driver.batch(&mut proactor, &mut bridge)?;
        for event in &driver.events[next_event..] {
            if event.kind != BridgeOpKind::PollAdd || event.interest.is_empty() {
                continue;
            }
            if event.result < 0 || !event.interest.contains(SocketInterest::READABLE) {
                return Err(io::Error::other(format!("readable poll failed: {event:?}")).into());
            }
            let bytes = received
                .get_mut(&event.fd)
                .ok_or_else(|| io::Error::other("unknown fd"))?;
            let mut chunk = [0_u8; 128];
            // SAFETY: fd remains Resources-owned, chunk is exclusive writable
            // storage, and recv is synchronous with an explicit nonblocking flag.
            let size = unsafe {
                libc::recv(
                    event.fd,
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if size > 0 {
                bytes.extend_from_slice(&chunk[..size as usize]);
            } else if size == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "early TCP EOF").into());
            } else {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::WouldBlock
                    && error.kind() != io::ErrorKind::Interrupted
                {
                    return Err(error.into());
                }
            }
            if bytes.len() < PAYLOAD.len() {
                bridge.set_interest(event.fd, SocketInterest::READABLE)?;
            }
        }
        next_event = driver.events.len();
    }
    if received.values().any(|bytes| bytes != PAYLOAD) {
        return Err(io::Error::other("loopback payload mismatch").into());
    }
    println!(
        "Readable: verified {} bytes on each of {CLIENTS} sockets.",
        PAYLOAD.len()
    );
    // Arm non-ready polls, then demonstrate removal and the deferred-close
    // barrier rather than closing descriptors underneath pending kernel work.
    for &fd in &clients {
        bridge.set_interest(fd, SocketInterest::READABLE)?;
    }
    driver.flush(&mut proactor)?;
    let removal_start = driver.events.len();
    for &fd in &clients {
        bridge.set_interest(fd, SocketInterest::EMPTY)?;
    }
    while driver.count_since(removal_start, BridgeOpKind::PollRemove) < CLIENTS {
        driver.batch(&mut proactor, &mut bridge)?;
    }
    for event in driver.events[removal_start..]
        .iter()
        .filter(|event| event.kind == BridgeOpKind::PollRemove)
    {
        if event.result < 0 && ![-libc::ENOENT, -libc::EALREADY].contains(&event.result) {
            return Err(io::Error::other(format!("poll removal failed: {event:?}")).into());
        }
    }
    let close_start = driver.events.len();
    for &fd in &clients {
        bridge.close(fd)?;
    }
    while driver.count_since(close_start, BridgeOpKind::Close) < CLIENTS {
        driver.batch(&mut proactor, &mut bridge)?;
    }
    for event in driver.events[close_start..]
        .iter()
        .filter(|event| event.kind == BridgeOpKind::Close)
    {
        if event.result != 0 {
            return Err(io::Error::other(format!("close failed: {event:?}")).into());
        }
    }
    if !resources.borrow().sockets.is_empty() || !driver.queue.borrow().is_empty() {
        return Err(io::Error::other("socket cleanup incomplete").into());
    }
    proactor.shutdown()?;
    println!(
        "Removed all interests and closed {CLIENTS} sockets after final CQEs; shutdown complete."
    );
    Ok(())
}
