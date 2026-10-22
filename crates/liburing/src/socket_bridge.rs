//! Readiness adaptation for external socket state machines.
//!
//! Submission adapters own operation resources and translate bridge tokens into
//! subsystem-local tokens without overwriting the operation's routing byte.
//! Call `drive` after consuming a completion batch to stage follow-up operations.

use std::{
    fmt,
    net::SocketAddr,
    ops::{BitOr, BitOrAssign},
    os::fd::RawFd,
};

use crate::{Completion, OpPayload, SubsystemId};

/// Readiness requested by an external nonblocking socket state machine.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketInterest(u32);

impl SocketInterest {
    /// No readiness notifications.
    pub const EMPTY: Self = Self(0);
    /// Input, EOF, or a read-side error can be observed.
    pub const READABLE: Self = Self(libc::POLLIN as u32);
    /// Output or a completed connection can be observed.
    pub const WRITABLE: Self = Self(libc::POLLOUT as u32);

    /// Returns the Linux `POLLIN`/`POLLOUT` mask for SQE preparation.
    ///
    /// # Panics
    /// Never panics.
    pub const fn poll_mask(self) -> u32 {
        self.0
    }

    /// Returns whether every requested bit is present.
    ///
    /// # Panics
    /// Never panics.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns whether there are no requested readiness bits.
    ///
    /// # Panics
    /// Never panics.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn completion(result: i32) -> Self {
        if result < 0 || result & i32::from(libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            Self::READABLE | Self::WRITABLE
        } else {
            let mut interest = Self(result as u32 & (libc::POLLIN | libc::POLLOUT) as u32);
            if result & i32::from(libc::POLLRDHUP) != 0 {
                interest |= Self::READABLE;
            }
            interest
        }
    }
}

impl BitOr for SocketInterest {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for SocketInterest {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Kernel operation represented by a bridge completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeOpKind {
    PollAdd,
    PollRemove,
    Cancel,
    Connect,
    Close,
}

/// Completion ready for delivery to an external socket state machine.
///
/// Control completions have empty `interest`; `result` always preserves the
/// kernel CQE result, including negative errno values. Dispatch only nonempty
/// readiness to APIs such as `ares_process_fds`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeEvent {
    pub fd: RawFd,
    pub interest: SocketInterest,
    pub result: i32,
    pub kind: BridgeOpKind,
}

/// Owned arguments for one staged operation; target IDs are opaque operation keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeSubmission<Id> {
    PollAdd { fd: RawFd, interest: SocketInterest },
    PollRemove { fd: RawFd, target: Id },
    Cancel { fd: RawFd, target: Id },
    Connect { fd: RawFd, address: SocketAddr },
    Close { fd: RawFd },
}

/// Submission boundary between the bridge and a registered subsystem submitter.
///
/// A successful submission must reserve its slot and retain any DMA resources
/// through the target's final CQE. An error must stage nothing. `PollRemove` and
/// `Cancel` target the returned operation ID, never the bridge's local token.
/// `Close` must stage a close operation without synchronously recycling the fd.
/// Adapters must preserve `local_token` in their completion routing and isolate
/// it from any other local-token namespace used by the same subsystem.
/// IDs remain unique until their target and referencing controls have retired.
pub trait UringSocketOps {
    type OpId: Copy + Eq;
    type Error;

    /// Returns the registration to which every submitted operation belongs.
    ///
    /// # Panics
    /// Implementations must not panic.
    fn subsystem_id(&self) -> SubsystemId;

    /// Stages an operation without entering or harvesting the kernel ring.
    ///
    /// # Errors
    /// Returns the adapter's capacity, registration, or submission error.
    /// # Panics
    /// Implementations must not panic.
    fn submit(
        &mut self,
        local_token: u64,
        op: BridgeSubmission<Self::OpId>,
    ) -> Result<Self::OpId, Self::Error>;
}

/// A rejected bridge transition or adapter submission.
#[derive(Debug, Eq, PartialEq)]
pub enum BridgeError<E> {
    Submission(E),
    WrongSubsystem,
    InvalidFd,
    AlreadyRegistered,
    UnknownFd,
    Closing,
    ConnectInFlight,
    Capacity,
    SequenceExhausted,
}

impl<E: fmt::Display> fmt::Display for BridgeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submission(error) => write!(f, "socket operation submission failed: {error}"),
            Self::WrongSubsystem => f.write_str("socket adapter belongs to another subsystem"),
            Self::InvalidFd => f.write_str("negative socket descriptor"),
            Self::AlreadyRegistered => f.write_str("socket descriptor is already registered"),
            Self::UnknownFd => f.write_str("socket descriptor is not registered"),
            Self::Closing => f.write_str("socket is closing"),
            Self::ConnectInFlight => f.write_str("socket connect is already in flight"),
            Self::Capacity => f.write_str("socket bridge capacity exhausted"),
            Self::SequenceExhausted => f.write_str("socket bridge completion sequence exhausted"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for BridgeError<E> {}

#[derive(Clone, Copy)]
struct Socket {
    fd: RawFd,
    interest: SocketInterest,
    closing: bool,
}

#[derive(Clone, Copy)]
struct Pending<Id> {
    token: u64,
    id: Id,
    target: Option<Id>,
    socket: usize,
    kind: BridgeOpKind,
    interest: SocketInterest,
    superseded: bool,
    remove_requested: bool,
    cancel_requested: bool,
}

/// Bounded, single-flight readiness bridge bound to one subsystem.
///
/// The adapter and bridge must remain alive until every registered socket has
/// completed close. Dropping this value does not cancel or close descriptors;
/// the caller must drain operations before unregistering its handler. Capacity is
/// allocated at construction; bridge transitions do not allocate.
pub struct UringSocketBridge<O: UringSocketOps> {
    subsystem: SubsystemId,
    ops: O,
    sockets: Vec<Option<Socket>>,
    pending: Vec<Option<Pending<O::OpId>>>,
    next_token: u64,
}

impl<O: UringSocketOps> UringSocketBridge<O> {
    /// Binds an adapter and reserves bookkeeping for `socket_capacity` sockets.
    ///
    /// # Errors
    /// Returns `WrongSubsystem` for a mismatched adapter and `Capacity` if the
    /// capacity overflows or bookkeeping memory cannot be reserved.
    /// # Panics
    /// Never panics.
    pub fn new(
        subsystem: SubsystemId,
        ops: O,
        socket_capacity: usize,
    ) -> Result<Self, BridgeError<O::Error>> {
        if ops.subsystem_id() != subsystem {
            return Err(BridgeError::WrongSubsystem);
        }
        let operation_capacity = socket_capacity
            .checked_mul(6)
            .ok_or(BridgeError::Capacity)?;
        let mut sockets = Vec::new();
        sockets
            .try_reserve_exact(socket_capacity)
            .map_err(|_| BridgeError::Capacity)?;
        sockets.resize_with(socket_capacity, || None);
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(operation_capacity)
            .map_err(|_| BridgeError::Capacity)?;
        pending.resize_with(operation_capacity, || None);
        Ok(Self {
            subsystem,
            ops,
            sockets,
            pending,
            next_token: 1,
        })
    }

    /// Returns the subsystem registration used by this bridge.
    ///
    /// # Panics
    /// Never panics.
    pub fn subsystem_id(&self) -> SubsystemId {
        self.subsystem
    }

    /// Starts managing a descriptor without staging an operation.
    ///
    /// The caller must keep the descriptor open until the bridge's final
    /// close CQE; closing it externally would invalidate the fd reuse barrier.
    /// # Errors
    /// Rejects negative, duplicate, or excess descriptors.
    /// # Panics
    /// Never panics.
    pub fn register(&mut self, fd: RawFd) -> Result<(), BridgeError<O::Error>> {
        if fd < 0 {
            return Err(BridgeError::InvalidFd);
        }
        if self.index(fd).is_some() {
            return Err(BridgeError::AlreadyRegistered);
        }
        let slot = self
            .sockets
            .iter_mut()
            .find(|socket| socket.is_none())
            .ok_or(BridgeError::Capacity)?;
        *slot = Some(Socket {
            fd,
            interest: SocketInterest::EMPTY,
            closing: false,
        });
        Ok(())
    }

    /// Records the latest interest and stages removal or rearming as needed.
    ///
    /// A replacement poll waits for both the old target's final CQE and its
    /// removal control CQE. Multiple changes coalesce into the latest mask.
    /// # Errors
    /// Rejects unknown or closing sockets. Submission failure leaves the desired
    /// mask recorded; call `drive` to retry after restoring submission capacity.
    /// # Panics
    /// Never panics.
    pub fn set_interest(
        &mut self,
        fd: RawFd,
        interest: SocketInterest,
    ) -> Result<(), BridgeError<O::Error>> {
        let index = self.index(fd).ok_or(BridgeError::UnknownFd)?;
        if let Some(socket) = &mut self.sockets[index] {
            if socket.closing {
                return Err(BridgeError::Closing);
            }
            socket.interest = interest;
        }
        self.drive_socket(index)
    }

    /// Stages one owned asynchronous connection attempt.
    ///
    /// UDP adapters needing synchronous POSIX connect semantics should perform
    /// that syscall before registering readiness, rather than call this method.
    /// # Errors
    /// Rejects unknown/closing sockets, duplicate connects, and submission errors.
    /// # Panics
    /// Never panics.
    pub fn connect(&mut self, fd: RawFd, address: SocketAddr) -> Result<(), BridgeError<O::Error>> {
        let index = self.index(fd).ok_or(BridgeError::UnknownFd)?;
        if self.sockets[index].is_some_and(|socket| socket.closing) {
            return Err(BridgeError::Closing);
        }
        if self.operation(index, BridgeOpKind::Connect).is_some() {
            return Err(BridgeError::ConnectInFlight);
        }
        self.stage(
            index,
            BridgeSubmission::Connect { fd, address },
            BridgeOpKind::Connect,
            SocketInterest::EMPTY,
        )?;
        Ok(())
    }

    /// Begins idempotent cancellation and deferred descriptor close.
    ///
    /// Cancel control completions never retire their targets. Close is staged
    /// only once every target and control operation has delivered its final CQE.
    /// # Errors
    /// Returns `UnknownFd` after final close or an adapter submission error.
    /// Submission errors retain closing state for a subsequent `drive` retry.
    /// # Panics
    /// Never panics.
    pub fn close(&mut self, fd: RawFd) -> Result<(), BridgeError<O::Error>> {
        let index = self.index(fd).ok_or(BridgeError::UnknownFd)?;
        if let Some(socket) = &mut self.sockets[index] {
            socket.closing = true;
        }
        self.drive_socket(index)
    }

    /// Consumes a routed CQE, preserving negative errno results.
    ///
    /// `more` is the CQE's `IORING_CQE_F_MORE` flag. Unknown or duplicate final
    /// tokens return `None`. Tokens never repeat, including across fd reuse.
    /// Follow with `drive` after the batch to submit rearmed polls and closes.
    /// A final close consumes the descriptor even on syscall error: retrying
    /// Linux close can affect a reused fd. `-ECANCELED` means close did not run
    /// and retains the descriptor for a subsequent `drive` retry.
    /// # Panics
    /// Never panics.
    pub fn on_cqe(&mut self, local_token: u64, result: i32, more: bool) -> Option<BridgeEvent> {
        let index = self
            .pending
            .iter()
            .position(|entry| entry.is_some_and(|op| op.token == local_token))?;
        let op = self.pending[index]?;
        let socket = self.sockets[op.socket]?;
        if !more {
            self.pending[index] = None;
        }
        let interest = match op.kind {
            BridgeOpKind::PollAdd
                if !socket.closing && op.interest == socket.interest && !op.superseded =>
            {
                SocketInterest::completion(result)
            }
            BridgeOpKind::Connect if !socket.closing => {
                if result < 0 {
                    SocketInterest::READABLE | SocketInterest::WRITABLE
                } else {
                    SocketInterest::WRITABLE
                }
            }
            _ => SocketInterest::EMPTY,
        };
        if !more
            && result < 0
            && result != -libc::ENOENT
            && result != -libc::EALREADY
            && let Some(target) = self
                .pending
                .iter_mut()
                .flatten()
                .find(|pending| Some(pending.id) == op.target)
        {
            match op.kind {
                BridgeOpKind::PollRemove => target.remove_requested = false,
                BridgeOpKind::Cancel => target.cancel_requested = false,
                _ => {}
            }
        }
        if op.kind == BridgeOpKind::Close && !more && result != -libc::ECANCELED {
            self.sockets[op.socket] = None;
        }
        Some(BridgeEvent {
            fd: socket.fd,
            interest,
            result,
            kind: op.kind,
        })
    }

    /// Decodes a native completion after validating its subsystem routing byte.
    ///
    /// The adapter must pack bridge tokens directly into `OpPayload`; adapters
    /// with a separate token namespace should translate it and call `on_cqe`.
    /// # Panics
    /// Never panics.
    pub fn on_completion(&mut self, completion: Completion) -> Option<BridgeEvent> {
        if completion.op_id.subsystem_id() != self.subsystem {
            return None;
        }
        self.on_cqe(
            completion.op_id.payload().raw(),
            completion.result,
            completion.flags & liburing_sys::IORING_CQE_F_MORE != 0,
        )
    }

    /// Stages pending poll replacements, cancellation controls, and closes.
    ///
    /// # Errors
    /// Returns the first adapter/capacity error. Previously staged operations
    /// remain tracked; calling again retries only unfinished transitions.
    /// # Panics
    /// Never panics.
    pub fn drive(&mut self) -> Result<(), BridgeError<O::Error>> {
        for index in 0..self.sockets.len() {
            self.drive_socket(index)?;
        }
        Ok(())
    }

    fn index(&self, fd: RawFd) -> Option<usize> {
        self.sockets
            .iter()
            .position(|entry| entry.is_some_and(|socket| socket.fd == fd))
    }

    fn operation(&self, socket: usize, kind: BridgeOpKind) -> Option<usize> {
        self.pending
            .iter()
            .position(|entry| entry.is_some_and(|op| op.socket == socket && op.kind == kind))
    }

    fn stage(
        &mut self,
        socket: usize,
        submission: BridgeSubmission<O::OpId>,
        kind: BridgeOpKind,
        interest: SocketInterest,
    ) -> Result<(), BridgeError<O::Error>> {
        let index = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(BridgeError::Capacity)?;
        let token = self.next_token;
        if token > OpPayload::MAX_RAW {
            return Err(BridgeError::SequenceExhausted);
        }
        let next = token + 1;
        let id = self
            .ops
            .submit(token, submission)
            .map_err(BridgeError::Submission)?;
        self.next_token = next;
        self.pending[index] = Some(Pending {
            token,
            id,
            target: match submission {
                BridgeSubmission::PollRemove { target, .. }
                | BridgeSubmission::Cancel { target, .. } => Some(target),
                _ => None,
            },
            socket,
            kind,
            interest,
            superseded: false,
            remove_requested: false,
            cancel_requested: false,
        });
        Ok(())
    }

    fn drive_socket(&mut self, index: usize) -> Result<(), BridgeError<O::Error>> {
        let Some(socket) = self.sockets[index] else {
            return Ok(());
        };
        if socket.closing {
            for kind in [BridgeOpKind::PollAdd, BridgeOpKind::Connect] {
                if let Some(target_index) = self.operation(index, kind)
                    && let Some(target) = self.pending[target_index]
                    && !target.cancel_requested
                {
                    self.stage(
                        index,
                        BridgeSubmission::Cancel {
                            fd: socket.fd,
                            target: target.id,
                        },
                        BridgeOpKind::Cancel,
                        SocketInterest::EMPTY,
                    )?;
                    if let Some(target) = &mut self.pending[target_index] {
                        target.cancel_requested = true;
                    }
                }
            }
            if !self
                .pending
                .iter()
                .any(|entry| entry.is_some_and(|op| op.socket == index))
            {
                self.stage(
                    index,
                    BridgeSubmission::Close { fd: socket.fd },
                    BridgeOpKind::Close,
                    SocketInterest::EMPTY,
                )?;
            }
        } else if let Some(target_index) = self.operation(index, BridgeOpKind::PollAdd)
            && let Some(target) = self.pending[target_index]
            && (target.interest != socket.interest || target.superseded)
            && !target.remove_requested
        {
            if let Some(target) = &mut self.pending[target_index] {
                target.superseded = true;
            }
            self.stage(
                index,
                BridgeSubmission::PollRemove {
                    fd: socket.fd,
                    target: target.id,
                },
                BridgeOpKind::PollRemove,
                SocketInterest::EMPTY,
            )?;
            if let Some(target) = &mut self.pending[target_index] {
                target.remove_requested = true;
            }
        } else if !socket.interest.is_empty()
            && !self
                .pending
                .iter()
                .any(|entry| entry.is_some_and(|op| op.socket == index))
        {
            self.stage(
                index,
                BridgeSubmission::PollAdd {
                    fd: socket.fd,
                    interest: socket.interest,
                },
                BridgeOpKind::PollAdd,
                socket.interest,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod unit_lifecycle_scenario {
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
            assert!(
                self.bridge
                    .on_cqe(self.token(index), result, false)
                    .is_some()
            );
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
    fn close_drains_poll_connect_and_controls_before_fd_reuse()
    -> Result<(), BridgeError<&'static str>> {
        for control_first in [false, true] {
            let mut h = Harness::new()?;
            h.bridge.register(7)?;
            h.bridge.set_interest(7, SocketInterest::READABLE)?;
            h.bridge
                .connect(7, SocketAddr::from(([127, 0, 0, 1], 80)))?;
            h.bridge.set_interest(7, SocketInterest::WRITABLE)?;
            h.bridge.close(7)?;
            h.bridge.close(7)?;
            assert_eq!(h.count(), 5);
            h.complete(3, -libc::ENOMEM);
            h.bridge.drive()?;
            assert_eq!(h.count(), 6);
            assert_eq!(
                h.requests.borrow()[5].1,
                BridgeSubmission::Cancel {
                    fd: 7,
                    target: h.token(0) + 1024,
                }
            );
            assert_eq!(
                h.bridge.set_interest(7, SocketInterest::WRITABLE),
                Err(BridgeError::Closing)
            );
            let order = if control_first {
                [2, 5, 4, 0, 1]
            } else {
                [0, 1, 2, 5, 4]
            };
            for (position, index) in order.into_iter().enumerate() {
                h.complete(index, if index < 2 { -libc::ECANCELED } else { 0 });
                h.bridge.drive()?;
                assert_eq!(h.count(), if position == 4 { 7 } else { 6 });
            }
            assert_eq!(h.requests.borrow()[6].1, BridgeSubmission::Close { fd: 7 });
            assert_eq!(h.bridge.register(7), Err(BridgeError::AlreadyRegistered));
            h.complete(6, 0);
            h.bridge.register(7)?;
            h.bridge.set_interest(7, SocketInterest::READABLE)?;
            assert_eq!(h.bridge.on_cqe(h.token(0), 1, false), None);
            assert_eq!(h.count(), 8);
        }
        Ok(())
    }

    #[test]
    fn failed_submission_keeps_interest_and_close_for_retry()
    -> Result<(), BridgeError<&'static str>> {
        let mut h = Harness::new()?;
        h.bridge.register(7)?;
        h.fail.set(true);
        assert_eq!(
            h.bridge.set_interest(7, SocketInterest::READABLE),
            Err(BridgeError::Submission("queue full"))
        );
        h.bridge.drive()?;
        assert_eq!(h.token(0), 1);
        h.bridge.close(7)?;
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
    fn sequence_exhaustion_rejects_aliasing_and_capacity_rejects_extra_fds()
    -> Result<(), BridgeError<&'static str>> {
        let mut h = Harness::new()?;
        assert_eq!(h.bridge.register(-1), Err(BridgeError::InvalidFd));
        h.bridge.register(7)?;
        assert_eq!(h.bridge.register(8), Err(BridgeError::Capacity));
        assert_eq!(
            h.bridge.set_interest(8, SocketInterest::READABLE),
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
}
