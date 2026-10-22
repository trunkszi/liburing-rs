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
    PollInFlight,
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
            Self::PollInFlight => f.write_str("socket readiness poll is still in flight"),
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

/// Single-flight readiness bridge with growing bookkeeping for one subsystem.
///
/// The adapter and bridge must remain alive until every registered socket has
/// completed close. Dropping this value does not cancel or close descriptors;
/// the caller must drain operations before unregistering its handler. Socket and
/// operation bookkeeping grows on demand; transitions can allocate.
pub struct UringSocketBridge<O: UringSocketOps> {
    subsystem: SubsystemId,
    ops: O,
    sockets: Vec<Option<Socket>>,
    pending: Vec<Option<Pending<O::OpId>>>,
    next_token: u64,
}

impl<O: UringSocketOps> UringSocketBridge<O> {
    /// Binds an adapter and reserves initial bookkeeping for `socket_capacity` sockets.
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
    /// Rejects negative or duplicate descriptors; returns `Capacity` if bookkeeping
    /// cannot grow because of overflow or allocation failure.
    /// # Panics
    /// Never panics.
    pub fn register(&mut self, fd: RawFd) -> Result<(), BridgeError<O::Error>> {
        if fd < 0 {
            return Err(BridgeError::InvalidFd);
        }
        if self.index(fd).is_some() {
            return Err(BridgeError::AlreadyRegistered);
        }
        let slot = match self.sockets.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => {
                let old = self.sockets.len();
                let capacity = if old == 0 {
                    4
                } else {
                    old.checked_mul(2).ok_or(BridgeError::Capacity)?
                };
                let pending = capacity.checked_mul(6).ok_or(BridgeError::Capacity)?;
                self.sockets
                    .try_reserve(capacity - old)
                    .map_err(|_| BridgeError::Capacity)?;
                self.pending
                    .try_reserve(pending.saturating_sub(self.pending.len()))
                    .map_err(|_| BridgeError::Capacity)?;
                self.sockets.resize_with(capacity, || None);
                self.pending
                    .resize_with(pending.max(self.pending.len()), || None);
                old
            }
        };
        self.sockets[slot] = Some(Socket {
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
    /// Rejects unknown or closing sockets and bookkeeping allocation failures.
    /// Submission failure leaves the desired mask recorded; call `drive` to retry
    /// after restoring submission capacity.
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
    /// Rejects unknown/closing sockets, duplicate connects, pending polls or poll
    /// removals, bookkeeping allocation failures, and submission errors. Retire
    /// polling before calling connect.
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
        if [BridgeOpKind::PollAdd, BridgeOpKind::PollRemove]
            .into_iter()
            .any(|kind| self.operation(index, kind).is_some())
        {
            return Err(BridgeError::PollInFlight);
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
    /// Returns `UnknownFd` after final close, an adapter submission error, or
    /// `Capacity` if bookkeeping cannot grow. Failures retain closing state for
    /// a subsequent `drive` retry.
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
        let index = match self.pending.iter().position(Option::is_none) {
            Some(index) => index,
            None => {
                let old = self.pending.len();
                let capacity = old.max(1).checked_mul(2).ok_or(BridgeError::Capacity)?;
                self.pending
                    .try_reserve(capacity - old)
                    .map_err(|_| BridgeError::Capacity)?;
                self.pending.resize_with(capacity, || None);
                old
            }
        };
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
mod tests;
