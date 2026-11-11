//! Deferred socket work must progress without any completion wait syscall.

use std::{
    io::{Read, Write},
    net::TcpListener,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use liburing::{
    Completion, OperationId, OperationPayload, Proactor, ProactorConfig, SubmissionContext,
    SubsystemId,
    ops::net::{prep_connect, prep_recv, prep_send},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn identity(payload: u64) -> OperationId {
    OperationId::pack(SubsystemId(1), OperationPayload(payload))
}

fn poll_one(proactor: &mut Proactor) -> Result<Completion, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut observed = None;
        proactor.poll_completions(1, &mut |cqe, _: &mut SubmissionContext<'_>| {
            observed = Some(cqe);
            Ok(())
        })?;
        if let Some(cqe) = observed {
            return Ok(cqe);
        }
        if Instant::now() >= deadline {
            return Err("submit/poll socket completion deadline elapsed".into());
        }
        std::thread::yield_now();
    }
}

#[test]
fn deferred_tcp_connect_send_recv_with_submit_and_poll_only() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let address = Box::new(libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    });
    // SAFETY: socket has no borrowed operands and returns a new owned descriptor.
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: The successful socket call transferred this unique descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let mut receive = Box::new([0_u8; 4]);
    let send = Box::new(*b"ping");
    // All raw operands precede the ring so teardown retains them on early errors.
    let mut proactor = Proactor::new(ProactorConfig {
        ..ProactorConfig::default()
    })?;
    assert!(proactor.kernel_features().defer_taskrun());
    proactor.prepare_sqe_with(identity(1), |sqe| {
        // SAFETY: The descriptor and boxed address outlive the ring and final CQE.
        unsafe {
            prep_connect(
                sqe,
                socket.as_raw_fd(),
                (&*address as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
        }
    })?;
    proactor.submit()?;
    let connected = poll_one(&mut proactor)?;
    assert_eq!((connected.operation_id, connected.result), (identity(1), 0));
    let (mut peer, _) = listener.accept()?;
    peer.set_read_timeout(Some(Duration::from_secs(2)))?;
    proactor.prepare_sqe_with(identity(2), |sqe| {
        // SAFETY: The immutable boxed payload and descriptor outlive final CQE.
        unsafe { prep_send(sqe, socket.as_raw_fd(), send.as_ptr(), send.len(), 0) };
    })?;
    proactor.submit()?;
    let sent = poll_one(&mut proactor)?;
    assert_eq!((sent.operation_id, sent.result), (identity(2), 4));
    let mut request = [0; 4];
    peer.read_exact(&mut request)?;
    assert_eq!(&request, b"ping");
    proactor.prepare_sqe_with(identity(3), |sqe| {
        // SAFETY: Exclusive boxed receive storage outlives the ring and final CQE.
        unsafe { prep_recv(sqe, socket.as_raw_fd(), receive.as_mut_ptr(), 4, 0) };
    })?;
    proactor.submit()?;
    // The receive must pend before the peer makes its payload available.
    assert_eq!(
        proactor.poll_completions(1, &mut |_, _: &mut SubmissionContext<'_>| {
            panic!("receive completed before peer response")
        })?,
        0
    );
    peer.write_all(b"pong")?;
    let received = poll_one(&mut proactor)?;
    assert_eq!((received.operation_id, received.result), (identity(3), 4));
    assert_eq!(&*receive, b"pong");
    assert_eq!(proactor.operation_count(), 0);
    Ok(())
}
