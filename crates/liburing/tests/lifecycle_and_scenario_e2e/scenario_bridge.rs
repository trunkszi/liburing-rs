use std::{
    collections::{HashMap, VecDeque},
    io,
    mem::ManuallyDrop,
    net::{SocketAddr, TcpListener},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
};

use liburing::{
    UringError,
    socket_bridge::{
        BridgeEvent, BridgeOpKind, BridgeSubmission, SocketInterest, UringSocketBridge,
        UringSocketOps,
    },
};
use liburing_sys as sys;

use super::*;

type Queue = Rc<RefCell<VecDeque<(OpId, BridgeSubmission<OpId>)>>>;
type Bridge = UringSocketBridge<Adapter>;

struct Adapter(Queue);

impl UringSocketOps for Adapter {
    type OpId = OpId;
    type Error = UringError;

    fn subsystem_id(&self) -> SubsystemId {
        route()
    }

    fn submit(&mut self, token: u64, submission: BridgeSubmission<OpId>) -> liburing::Result<OpId> {
        let id = op(token);
        self.0.borrow_mut().push_back((id, submission));
        Ok(id)
    }
}

struct Driver {
    queue: Queue,
    // Retain sockaddr DMA allocations even on a failure path with pending connect.
    #[allow(clippy::vec_box)] // Each sockaddr address must survive vector growth.
    addresses: ManuallyDrop<Vec<Box<libc::sockaddr_in>>>,
    inflight: HashMap<OpId, (RawFd, BridgeOpKind)>,
    events: Vec<(Completion, BridgeEvent)>,
}

impl Driver {
    fn flush(&mut self, proactor: &mut Proactor) -> TestResult {
        while let Some((id, submission)) = self.queue.borrow_mut().pop_front() {
            let (fd, kind) = match submission {
                BridgeSubmission::PollAdd { fd, .. } => (fd, BridgeOpKind::PollAdd),
                BridgeSubmission::PollRemove { fd, .. } => (fd, BridgeOpKind::PollRemove),
                BridgeSubmission::Cancel { fd, .. } => (fd, BridgeOpKind::Cancel),
                BridgeSubmission::Connect { fd, .. } => (fd, BridgeOpKind::Connect),
                BridgeSubmission::Close { fd } => {
                    assert!(
                        !self
                            .inflight
                            .values()
                            .any(|(pending_fd, _)| *pending_fd == fd),
                        "close crossed an unfinished target/control CQE barrier"
                    );
                    (fd, BridgeOpKind::Close)
                }
            };
            let address = match submission {
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
                    self.addresses.push(address);
                    Some(self.addresses.last().expect("retained address").as_ref()
                        as *const libc::sockaddr_in)
                }
                BridgeSubmission::Connect { .. } => panic!("scenario uses IPv4 loopback"),
                _ => None,
            };
            proactor.prepare_sqe_with(id, |sqe| {
                // SAFETY: SQE is exclusive. Poll/control operations retain no
                // pointers. Connect addresses are boxed and retained through all
                // final CQEs; the bridge owns each fd until its unique close CQE.
                unsafe {
                    match submission {
                        BridgeSubmission::PollAdd { fd, interest } => {
                            sys::uring_shim_prep_poll_add(sqe, fd, interest.poll_mask())
                        }
                        BridgeSubmission::PollRemove { target, .. } => {
                            sys::uring_shim_prep_poll_remove(sqe, target.raw())
                        }
                        BridgeSubmission::Cancel { target, .. } => {
                            sys::uring_shim_prep_cancel64(sqe, target.raw(), 0)
                        }
                        BridgeSubmission::Connect { fd, .. } => sys::uring_shim_prep_connect(
                            sqe,
                            fd,
                            address.expect("connect address").cast(),
                            std::mem::size_of::<libc::sockaddr_in>() as _,
                        ),
                        BridgeSubmission::Close { fd } => sys::uring_shim_prep_close(sqe, fd),
                    }
                }
            })?;
            assert!(self.inflight.insert(id, (fd, kind)).is_none());
        }
        proactor.submit()?;
        Ok(())
    }

    fn batch(&mut self, proactor: &mut Proactor, bridge: &mut Bridge) -> TestResult {
        bridge.drive()?;
        self.flush(proactor)?;
        proactor.wait_completions(1, Some(WAIT), |completion, _| {
            assert_eq!(completion.flags & sys::IORING_CQE_F_MORE, 0);
            let (fd, kind) = self
                .inflight
                .remove(&completion.op_id)
                .expect("one final native CQE per operation");
            let event = bridge
                .on_completion(completion)
                .expect("active native bridge token");
            assert_eq!((event.fd, event.kind), (fd, kind));
            if kind == BridgeOpKind::PollAdd && !event.interest.is_empty() {
                bridge
                    .set_interest(fd, SocketInterest::EMPTY)
                    .expect("retire readiness interest");
            }
            self.events.push((completion, event));
            Ok(())
        })?;
        Ok(())
    }

    fn count(&self, kind: BridgeOpKind) -> usize {
        self.events
            .iter()
            .filter(|(_, event)| event.kind == kind)
            .count()
    }
}

fn socket() -> io::Result<OwnedFd> {
    // SAFETY: socket has no pointer arguments and requests one fresh TCP fd.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful socket transfers its unique new descriptor to OwnedFd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn duplicate_at_least(fd: RawFd, minimum: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl duplicates a live borrowed fd without changing its ownership.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful fcntl returned a fresh, uniquely owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

#[test]
fn growing_bridge_connects_replaces_polls_closes_and_reuses_fd_without_stale_events() -> TestResult
{
    let _serial = crate::kernel_test_lock();
    const CLIENTS: usize = 4;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let mut proactor = kernel(false)?;
    let record = Rc::new(RefCell::new(Vec::new()));
    proactor.register_subsystem(route(), Recorder(Rc::clone(&record)))?;
    let queue = Rc::new(RefCell::new(VecDeque::new()));
    let mut bridge = Bridge::new(route(), Adapter(Rc::clone(&queue)), 1)?;
    let mut driver = Driver {
        queue,
        addresses: ManuallyDrop::new(Vec::new()),
        inflight: HashMap::new(),
        events: Vec::new(),
    };
    let mut fds = Vec::new();
    for index in 0..CLIENTS {
        let socket = socket()?;
        // A high descriptor isolates the explicit reuse check from ordinary
        // low-fd allocation in concurrently running test cases.
        let socket = if index == 0 {
            duplicate_at_least(socket.as_raw_fd(), 512)?
        } else {
            socket
        };
        let fd = socket.into_raw_fd();
        bridge.register(fd)?;
        bridge.connect(fd, listener.local_addr()?)?;
        fds.push(fd);
    }
    let start = Instant::now();
    while driver.count(BridgeOpKind::Connect) < CLIENTS {
        deadline(start);
        driver.batch(&mut proactor, &mut bridge)?;
    }
    for (_, event) in &driver.events {
        assert_eq!(event.kind, BridgeOpKind::Connect);
        assert_eq!(event.result, 0);
        assert_eq!(event.interest, SocketInterest::WRITABLE);
    }
    let mut peers = Vec::new();
    while peers.len() < CLIENTS {
        deadline(start);
        match listener.accept() {
            Ok((peer, _)) => peers.push(peer),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(error) => return Err(error.into()),
        }
    }
    for &fd in &fds {
        bridge.set_interest(fd, SocketInterest::READABLE)?;
    }
    driver.flush(&mut proactor)?;
    for &fd in &fds {
        bridge.set_interest(fd, SocketInterest::WRITABLE)?;
    }
    while driver.count(BridgeOpKind::PollRemove) < CLIENTS
        || driver
            .events
            .iter()
            .filter(|(_, event)| event.kind == BridgeOpKind::PollAdd && !event.interest.is_empty())
            .count()
            < CLIENTS
    {
        deadline(start);
        driver.batch(&mut proactor, &mut bridge)?;
    }
    for (_, event) in &driver.events {
        match event.kind {
            BridgeOpKind::PollRemove => assert_eq!(event.result, 0),
            BridgeOpKind::PollAdd if event.interest.is_empty() => {
                assert_eq!(event.result, -libc::ECANCELED)
            }
            BridgeOpKind::PollAdd => assert_eq!(event.interest, SocketInterest::WRITABLE),
            _ => {}
        }
    }
    assert_eq!(driver.count(BridgeOpKind::PollAdd), CLIENTS * 2);
    // Close with live non-ready polls, requiring separate cancel and target CQEs.
    for &fd in &fds {
        bridge.set_interest(fd, SocketInterest::READABLE)?;
    }
    driver.flush(&mut proactor)?;
    for &fd in &fds {
        bridge.close(fd)?;
    }
    while driver.count(BridgeOpKind::Close) < CLIENTS {
        deadline(start);
        driver.batch(&mut proactor, &mut bridge)?;
    }
    assert_eq!(driver.count(BridgeOpKind::Cancel), CLIENTS);
    assert!(driver.inflight.is_empty());
    for (_, event) in &driver.events {
        if event.kind == BridgeOpKind::Close {
            assert_eq!(event.result, 0);
        }
    }
    let old_fd = fds[0];
    let fresh = socket()?;
    let reused = duplicate_at_least(fresh.as_raw_fd(), old_fd)?;
    assert_eq!(
        reused.as_raw_fd(),
        old_fd,
        "explicit descriptor identity reuse"
    );
    let fd = reused.into_raw_fd();
    bridge.register(fd)?;
    bridge.connect(fd, listener.local_addr()?)?;
    for (completion, _) in driver.events.clone() {
        assert!(
            bridge.on_completion(completion).is_none(),
            "retired token crossed fd reuse"
        );
    }
    while driver.count(BridgeOpKind::Connect) < CLIENTS + 1 {
        deadline(start);
        driver.batch(&mut proactor, &mut bridge)?;
    }
    let (_, connection) = driver
        .events
        .last()
        .expect("reused fd connection completed");
    assert_eq!((connection.fd, connection.result), (fd, 0));
    bridge.close(fd)?;
    while driver.count(BridgeOpKind::Close) < CLIENTS + 1 {
        deadline(start);
        driver.batch(&mut proactor, &mut bridge)?;
    }
    assert_eq!(driver.events.last().expect("final close").1.result, 0);
    assert!(driver.inflight.is_empty());
    assert!(driver.queue.borrow().is_empty());
    assert_eq!(driver.events.len(), record.borrow().len());
    proactor.shutdown()?;
    // SAFETY: Every Connect delivered its own final CQE and successful shutdown
    // confirms no native operation retains these sockaddr allocations.
    unsafe { ManuallyDrop::drop(&mut driver.addresses) };
    Ok(())
}
