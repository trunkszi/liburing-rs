//! Socket transition, submission retry, and sequence exhaustion checks.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use super::*;
const SUBSYSTEM: SubsystemId = SubsystemId(9);
type Requests = Rc<RefCell<Vec<(u64, BridgeSubmission<u64>)>>>;
struct Recorder {
    requests: Requests,
    fail: Rc<Cell<bool>>,
}
impl UringSocketOps for Recorder {
    type OpId = u64;
    type Error = &'static str;
    fn subsystem_id(&self) -> SubsystemId {
        SUBSYSTEM
    }
    fn submit(&mut self, token: u64, op: BridgeSubmission<u64>) -> Result<u64, Self::Error> {
        if self.fail.replace(false) {
            return Err("queue full");
        }
        self.requests.borrow_mut().push((token, op));
        Ok(token + 1024)
    }
}
struct Harness {
    bridge: UringSocketBridge<Recorder>,
    requests: Requests,
    fail: Rc<Cell<bool>>,
}
impl Harness {
    fn new() -> Result<Self, BridgeError<&'static str>> {
        let requests = Rc::new(RefCell::new(Vec::new()));
        let fail = Rc::new(Cell::new(false));
        let ops = Recorder {
            requests: Rc::clone(&requests),
            fail: Rc::clone(&fail),
        };
        Ok(Self {
            bridge: UringSocketBridge::new(SUBSYSTEM, ops, 1)?,
            requests,
            fail,
        })
    }
    fn token(&self, index: usize) -> u64 {
        self.requests.borrow()[index].0
    }
    fn complete(&mut self, index: usize, result: i32) {
        let token = self.token(index);
        assert!(self.bridge.on_cqe(token, result, false).is_some());
    }
    fn count(&self) -> usize {
        self.requests.borrow().len()
    }
}

#[test]
fn interest_changes_wait_for_target_and_control_in_both_orders()
-> Result<(), BridgeError<&'static str>> {
    for control_first in [false, true] {
        let mut h = Harness::new()?;
        h.bridge.register(7)?;
        h.bridge.set_interest(7, SocketInterest::READABLE)?;
        h.bridge.set_interest(7, SocketInterest::WRITABLE)?;
        h.bridge
            .set_interest(7, SocketInterest::READABLE | SocketInterest::WRITABLE)?;
        assert_eq!(h.count(), 2);
        assert_eq!(
            h.requests.borrow()[1].1,
            BridgeSubmission::PollRemove {
                fd: 7,
                target: h.token(0) + 1024
            }
        );
        h.complete(1, -libc::ENOMEM);
        h.bridge.drive()?;
        assert_eq!(h.count(), 3);
        h.complete(
            if control_first { 2 } else { 0 },
            if control_first { 0 } else { -125 },
        );
        h.bridge.drive()?;
        assert_eq!(h.count(), 3);
        h.complete(
            if control_first { 0 } else { 2 },
            if control_first { -125 } else { 0 },
        );
        h.bridge.drive()?;
        assert_eq!(h.count(), 4);
        assert_eq!(
            h.requests.borrow()[3].1,
            BridgeSubmission::PollAdd {
                fd: 7,
                interest: SocketInterest::READABLE | SocketInterest::WRITABLE,
            }
        );
    }
    Ok(())
}

#[test]
fn close_drains_poll_and_controls_before_fd_reuse() -> Result<(), BridgeError<&'static str>> {
    for control_first in [false, true] {
        let mut h = Harness::new()?;
        h.bridge.register(7)?;
        h.bridge.set_interest(7, SocketInterest::READABLE)?;
        h.bridge.set_interest(7, SocketInterest::WRITABLE)?;
        h.bridge.close(7)?;
        h.bridge.close(7)?;
        assert_eq!(h.count(), 3);
        h.complete(2, -libc::ENOMEM);
        h.bridge.drive()?;
        assert_eq!(h.count(), 4);
        assert_eq!(
            h.requests.borrow()[3].1,
            BridgeSubmission::Cancel {
                fd: 7,
                target: h.token(0) + 1024
            }
        );
        assert_eq!(
            h.bridge.set_interest(7, SocketInterest::WRITABLE),
            Err(BridgeError::Closing)
        );
        let order = if control_first { [1, 3, 0] } else { [0, 1, 3] };
        for (position, index) in order.into_iter().enumerate() {
            h.complete(index, if index == 0 { -libc::ECANCELED } else { 0 });
            h.bridge.drive()?;
            assert_eq!(h.count(), if position == 2 { 5 } else { 4 });
        }
        assert_eq!(h.requests.borrow()[4].1, BridgeSubmission::Close { fd: 7 });
        assert_eq!(h.bridge.register(7), Err(BridgeError::AlreadyRegistered));
        h.complete(4, 0);
        h.bridge.register(7)?;
        h.bridge.set_interest(7, SocketInterest::READABLE)?;
        assert_eq!(h.bridge.on_cqe(h.token(0), 1, false), None);
        assert_eq!(h.count(), 6);
    }
    Ok(())
}

#[test]
fn connect_waits_for_poll_target_and_control() -> Result<(), BridgeError<&'static str>> {
    for control_first in [false, true] {
        let mut h = Harness::new()?;
        let address = SocketAddr::from(([127, 0, 0, 1], 80));
        h.bridge.register(7)?;
        h.bridge.set_interest(7, SocketInterest::READABLE)?;
        assert_eq!(h.bridge.connect(7, address), Err(BridgeError::PollInFlight));
        assert_eq!(h.count(), 1);
        h.bridge.set_interest(7, SocketInterest::EMPTY)?;
        h.complete(if control_first { 1 } else { 0 }, 0);
        assert_eq!(h.bridge.connect(7, address), Err(BridgeError::PollInFlight));
        assert_eq!(h.count(), 2);
        h.complete(if control_first { 0 } else { 1 }, 0);
        h.bridge.connect(7, address)?;
        assert_eq!(h.token(2), 3, "rejections must not consume tokens");
        assert_eq!(
            h.bridge.connect(7, address),
            Err(BridgeError::ConnectInFlight)
        );
        h.bridge.close(7)?;
        assert_eq!(
            h.requests.borrow()[3].1,
            BridgeSubmission::Cancel {
                fd: 7,
                target: h.token(2) + 1024
            }
        );
        for index in if control_first { [3, 2] } else { [2, 3] } {
            h.complete(index, if index == 2 { -libc::ECANCELED } else { 0 });
            h.bridge.drive()?;
        }
        assert_eq!(h.requests.borrow()[4].1, BridgeSubmission::Close { fd: 7 });
        h.complete(4, 0);
    }
    Ok(())
}

#[test]
fn failed_submission_keeps_interest_and_close_for_retry() -> Result<(), BridgeError<&'static str>> {
    let mut h = Harness::new()?;
    h.bridge.register(7)?;
    h.fail.set(true);
    assert_eq!(
        h.bridge.set_interest(7, SocketInterest::READABLE),
        Err(BridgeError::Submission("queue full"))
    );
    h.bridge.drive()?;
    assert_eq!(h.token(0), 1);
    h.bridge.pending.truncate(1);
    h.bridge.close(7)?;
    assert_eq!(h.bridge.pending.len(), 2);
    h.complete(1, -libc::ENOMEM);
    h.bridge.drive()?;
    assert_eq!(h.count(), 3, "failed cancellation must be retried");
    h.complete(2, -libc::ENOENT);
    h.bridge.drive()?;
    assert_eq!(h.count(), 3);
    h.complete(0, -125);
    h.fail.set(true);
    assert_eq!(h.bridge.drive(), Err(BridgeError::Submission("queue full")));
    h.bridge.drive()?;
    h.complete(3, -libc::ECANCELED);
    h.bridge.drive()?;
    assert_eq!(h.count(), 5);
    h.complete(4, -5);
    h.bridge.drive()?;
    assert_eq!(h.count(), 5);
    h.bridge.register(7)?;
    Ok(())
}

#[test]
fn sequence_exhaustion_rejects_aliasing_after_registration_growth()
-> Result<(), BridgeError<&'static str>> {
    let mut h = Harness::new()?;
    assert_eq!(h.bridge.register(-1), Err(BridgeError::InvalidFd));
    h.bridge.register(7)?;
    h.bridge.register(8)?;
    assert_eq!(h.bridge.sockets.len(), 2);
    assert_eq!(
        h.bridge.set_interest(9, SocketInterest::READABLE),
        Err(BridgeError::UnknownFd)
    );
    h.bridge.next_token = OpPayload::MAX_RAW;
    h.bridge.set_interest(7, SocketInterest::READABLE)?;
    assert_eq!(h.token(0), OpPayload::MAX_RAW);
    h.complete(0, 1);
    assert_eq!(h.bridge.drive(), Err(BridgeError::SequenceExhausted));
    assert_eq!(h.count(), 1);
    Ok(())
}

#[test]
fn socket_growth_keeps_larger_pending_table_and_high_slot_operations()
-> Result<(), BridgeError<&'static str>> {
    let mut h = Harness::new()?;
    h.bridge.register(7)?;
    h.bridge.set_interest(7, SocketInterest::READABLE)?;
    h.bridge.pending.resize_with(20, || None);
    h.bridge.pending.swap(0, 19);
    h.bridge.register(8)?;
    assert_eq!(h.bridge.sockets.len(), 2);
    assert_eq!(h.bridge.pending.len(), 20);
    h.bridge.set_interest(8, SocketInterest::WRITABLE)?;
    let event = h.bridge.on_cqe(h.token(0), i32::from(libc::POLLIN), false);
    assert_eq!(event.map(|event| event.fd), Some(7));
    let event = h.bridge.on_cqe(h.token(1), i32::from(libc::POLLOUT), false);
    assert_eq!(event.map(|event| event.fd), Some(8));
    Ok(())
}
