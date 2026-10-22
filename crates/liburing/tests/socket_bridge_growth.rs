//! Growing bridge bookkeeping preserves operation routing and fd reuse barriers.

use std::{cell::RefCell, rc::Rc};

use liburing::{
    SubsystemId,
    socket_bridge::{
        BridgeError, BridgeOpKind, BridgeSubmission, SocketInterest, UringSocketBridge,
        UringSocketOps,
    },
};

const SUBSYSTEM: SubsystemId = SubsystemId(9);
type Requests = Rc<RefCell<Vec<(u64, BridgeSubmission<u64>)>>>;

struct Recorder(Requests);

impl UringSocketOps for Recorder {
    type OpId = u64;
    type Error = &'static str;

    fn subsystem_id(&self) -> SubsystemId {
        SUBSYSTEM
    }

    fn submit(&mut self, token: u64, op: BridgeSubmission<u64>) -> Result<u64, Self::Error> {
        self.0.borrow_mut().push((token, op));
        Ok(token + 1024)
    }
}

#[test]
fn sockets_grow_from_empty_and_small_initial_tables_without_losing_operations()
-> Result<(), BridgeError<&'static str>> {
    for initial in [0, 1, 3] {
        let requests = Rc::new(RefCell::new(Vec::new()));
        let mut bridge =
            UringSocketBridge::new(SUBSYSTEM, Recorder(Rc::clone(&requests)), initial)?;
        for fd in 10..75 {
            bridge.register(fd)?;
            bridge.set_interest(fd, SocketInterest::READABLE)?;
        }
        assert_eq!(requests.borrow().len(), 65);
        assert_eq!(bridge.register(10), Err(BridgeError::AlreadyRegistered));
        for (index, (token, request)) in requests.borrow().iter().enumerate() {
            assert_eq!(*token, index as u64 + 1);
            assert_eq!(
                *request,
                BridgeSubmission::PollAdd {
                    fd: index as i32 + 10,
                    interest: SocketInterest::READABLE,
                }
            );
        }
        // Keep every original poll pending while all removal controls are staged.
        for fd in 10..75 {
            bridge.set_interest(fd, SocketInterest::EMPTY)?;
        }
        assert_eq!(requests.borrow().len(), 130);
        for index in (0..65).rev() {
            let (poll, _) = requests.borrow()[index];
            let (remove, request) = requests.borrow()[index + 65];
            assert_eq!(
                request,
                BridgeSubmission::PollRemove {
                    fd: index as i32 + 10,
                    target: poll + 1024,
                }
            );
            let event =
                bridge
                    .on_cqe(poll, -libc::ECANCELED, false)
                    .ok_or(BridgeError::Submission(
                        "poll token lost during bookkeeping growth",
                    ))?;
            assert_eq!(event.fd, index as i32 + 10);
            assert_eq!(event.kind, BridgeOpKind::PollAdd);
            assert!(event.interest.is_empty());
            assert_eq!(bridge.on_cqe(poll, 1, false), None);
            let control = bridge
                .on_cqe(remove, 0, false)
                .ok_or(BridgeError::Submission(
                    "control token lost during bookkeeping growth",
                ))?;
            assert_eq!(control.fd, event.fd);
            assert_eq!(control.kind, BridgeOpKind::PollRemove);
        }
        bridge.drive()?;
        assert_eq!(requests.borrow().len(), 130);
        for fd in 10..75 {
            bridge.close(fd)?;
        }
        for index in (130..195).rev() {
            let (close, request) = requests.borrow()[index];
            let fd = (index - 130) as i32 + 10;
            assert_eq!(request, BridgeSubmission::Close { fd });
            assert_eq!(bridge.register(fd), Err(BridgeError::AlreadyRegistered));
            assert_eq!(
                bridge.on_cqe(close, 0, false).map(|event| event.fd),
                Some(fd)
            );
            bridge.register(fd)?;
            bridge.set_interest(fd, SocketInterest::WRITABLE)?;
            assert_eq!(bridge.on_cqe((fd - 9) as u64, 1, false), None);
        }
        assert_eq!(requests.borrow().len(), 260);
        // All reused slots remain routable after their original generations retire.
        for index in 195..260 {
            let (token, request) = requests.borrow()[index];
            let BridgeSubmission::PollAdd { fd, interest } = request else {
                return Err(BridgeError::Submission("expected replacement poll"));
            };
            let event = bridge
                .on_cqe(token, i32::from(libc::POLLOUT), false)
                .ok_or(BridgeError::Submission(
                    "replacement token missing after socket reuse",
                ))?;
            assert_eq!(event.fd, fd);
            assert_eq!(event.interest, interest);
        }
    }
    Ok(())
}
