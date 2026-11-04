//! Completion-driven socket operations backed by proactor-owned DMA pools.

use std::{
    os::fd::{AsRawFd, OwnedFd},
    rc::Rc,
};

use crate::{
    BufferGroupId, Completion, OperationId, Proactor, Result, SubmissionContext, SubsystemId,
    UringError, backend,
    buffer_ring::BufferLease,
    operation_slab::{OperationKey, OperationKind, OperationSlab, OperationState},
    ops::net,
};

/// Generation-checked socket identity, independent of descriptor recycling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketId {
    slot: u32,
    generation: u32,
}

impl SocketId {
    /// Encodes the slot and its current generation.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub const fn raw(self) -> u64 {
        ((self.generation as u64) << 32) | self.slot as u64
    }
}

/// Preallocated socket, operation, and DMA budgets.
#[derive(Debug, Clone, Copy)]
pub struct SocketIoConfig {
    pub subsystem: SubsystemId,
    pub sockets: usize,
    pub operations: usize,
    pub receive_group: BufferGroupId,
    pub receive_buffers: u16,
    pub send_buffers: u16,
    pub buffer_len: usize,
}

impl Default for SocketIoConfig {
    fn default() -> Self {
        Self {
            subsystem: SubsystemId::new_unchecked(1),
            sockets: 256,
            operations: 1024,
            receive_group: BufferGroupId(1),
            receive_buffers: 64,
            send_buffers: 64,
            buffer_len: 8192,
        }
    }
}

/// Receive completion shape chosen at submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveMode {
    Once,
    Multishot,
}

/// A completion whose received payload is already in a kernel-selected lease.
pub enum SocketEvent<'a> {
    Received {
        socket: SocketId,
        operation: OperationId,
        data: BufferLease<'a>,
    },
    ReadClosed {
        socket: SocketId,
    },
    Sent {
        socket: SocketId,
        operation: OperationId,
        bytes: usize,
    },
    SendReleased {
        socket: SocketId,
        operation: OperationId,
    },
    BufferUnavailable {
        socket: SocketId,
    },
    Cancelled {
        socket: SocketId,
        operation: OperationId,
    },
    Error {
        socket: SocketId,
        operation: OperationId,
        errno: i32,
    },
    Closed {
        socket: SocketId,
    },
}

#[derive(Clone, Copy)]
enum SocketOperationKind {
    Receive,
    Send { zero_copy: bool },
}
struct SocketOperation {
    key: OperationKey,
    prev_op: Option<OperationKey>,
    next_op: Option<OperationKey>,
    socket: SocketId,
    kind: SocketOperationKind,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketSlotPhase {
    Active = 0,
    DrainingInFlight = 1,
    Closed = 2,
}

struct SocketRecord {
    fd: Rc<OwnedFd>,
    active: usize,
    head_op: Option<OperationKey>,
    closed_completion: Option<Completion>,
    receive: Option<OperationId>,
    phase: SocketSlotPhase,
}
struct SocketSlot {
    generation: u32,
    record: Option<SocketRecord>,
}

/// Caller-owned completion I/O retaining descriptors and DMA through final CQEs.
/// Registration allocates; receive/send progress uses fixed slots and selected leases.
pub struct CompletionSocketIo {
    config: SocketIoConfig,
    sockets: Box<[SocketSlot]>,
    free: Vec<usize>,
    operations: OperationSlab<SocketOperation>,
}

impl CompletionSocketIo {
    /// Registers proactor-owned fixed send memory and a provided receive group.
    /// # Errors
    /// Returns mode, invalid budget, group conflict, allocation, or kernel errors.
    /// # Panics
    /// May panic on allocation failure.
    pub fn new(proactor: &mut Proactor, config: SocketIoConfig) -> Result<Self> {
        if !proactor.mode().supports_sockets_and_timers() {
            return Err(UringError::OpcodeNotAdmitted {
                opcode: io_uring::opcode::Recv::CODE,
                mode: proactor.mode().name(),
            });
        }
        if config.subsystem == SubsystemId::INTERNAL
            || config.sockets == 0
            || config.sockets > u32::MAX as usize
        {
            return Err(socket_error("socket identity and capacity must be valid"));
        }
        if config.send_buffers == 0
            || !config.receive_buffers.is_power_of_two()
            || config.receive_buffers > 32768
            || config.buffer_len == 0
            || config.buffer_len > i32::MAX as usize
        {
            return Err(socket_error(
                "socket DMA budgets must fit kernel buffer limits",
            ));
        }
        let operations = OperationSlab::new(config.operations)?;
        proactor.configure_socket_buffers(
            config.send_buffers,
            config.receive_group,
            config.receive_buffers,
            config.buffer_len,
        )?;
        Ok(Self {
            config,
            sockets: (0..config.sockets)
                .map(|_| SocketSlot {
                    generation: 1,
                    record: None,
                })
                .collect(),
            free: (0..config.sockets).rev().collect(),
            operations,
        })
    }
    /// Transfers a connected TCP or Unix descriptor to a generation-checked slot.
    /// # Errors
    /// Returns a capacity error when all sockets are occupied.
    /// # Panics
    /// May panic if allocating the shared descriptor owner fails.
    pub fn insert(&mut self, fd: OwnedFd) -> Result<SocketId> {
        let index = self.free.pop().ok_or(UringError::FixedFileSlotsExhausted)?;
        let slot = &mut self.sockets[index];
        slot.record = Some(SocketRecord {
            fd: Rc::new(fd),
            active: 0,
            head_op: None,
            closed_completion: None,
            receive: None,
            phase: SocketSlotPhase::Active,
        });
        Ok(SocketId {
            slot: index as u32,
            generation: slot.generation,
        })
    }
    /// Submits buffer-select Recv or RecvMulti directly to the kernel.
    /// # Errors
    /// Returns stale socket, duplicate receive, capacity, or preparation errors.
    /// # Panics
    /// Does not intentionally panic.
    #[inline]
    pub fn receive(
        &mut self,
        proactor: &mut Proactor,
        socket: SocketId,
        mode: ReceiveMode,
    ) -> Result<OperationId> {
        proactor.with_submission_context(|context| self.receive_with_context(context, socket, mode))
    }
    /// Stages a selecting receive from the current completion dispatcher.
    /// # Errors
    /// Returns stale socket, duplicate receive, capacity, or preparation errors.
    /// # Panics
    /// Does not intentionally panic.
    #[inline]
    pub fn receive_with_context(
        &mut self,
        context: &mut SubmissionContext<'_>,
        socket: SocketId,
        mode: ReceiveMode,
    ) -> Result<OperationId> {
        let record = Self::record_mut(&mut self.sockets, socket)?;
        if record.phase != SocketSlotPhase::Active || record.receive.is_some() {
            return Err(socket_error("socket is closing or already receiving"));
        }
        let fd = Rc::clone(&record.fd);
        let kind = if mode == ReceiveMode::Multishot {
            OperationKind::Multishot
        } else {
            OperationKind::Single
        };
        let key = self.operations.insert_with(kind, |key| SocketOperation {
            key,
            socket,
            kind: SocketOperationKind::Receive,
            prev_op: None,
            next_op: None,
        })?;
        let id = OperationId::pack(self.config.subsystem, key.payload());
        let group = self.config.receive_group;
        let length = self.config.buffer_len;
        let raw_fd = fd.as_raw_fd();
        let prepared = context.prepare_owned_sqe_with(id, fd, None, |sqe| {
            // SAFETY: Proactor owns the registered group and retains the socket
            // until this receive's final CQE. Selected leases control reuse.
            unsafe {
                if mode == ReceiveMode::Multishot {
                    net::prep_recv_multishot(sqe, raw_fd, group, 0);
                } else {
                    net::prep_recv(sqe, raw_fd, std::ptr::null_mut(), length, 0);
                    (*sqe).buf_index = group.raw();
                    (*sqe).flags |= backend::IOSQE_BUFFER_SELECT as u8;
                }
            }
        });
        if let Err(error) = prepared {
            self.rollback(key)?;
            return Err(error);
        }
        record.receive = Some(id);
        self.link_op(key, socket)?;
        Ok(id)
    }
    /// Copies one bounded payload into fixed memory and submits Send or SendZc.
    /// # Errors
    /// Returns stale socket, buffer/operation capacity, or preparation errors.
    /// # Panics
    /// Does not intentionally panic.
    #[inline]
    pub fn send(
        &mut self,
        proactor: &mut Proactor,
        socket: SocketId,
        bytes: &[u8],
        zero_copy: bool,
    ) -> Result<OperationId> {
        proactor.with_submission_context(|context| {
            self.send_with_context(context, socket, bytes, zero_copy)
        })
    }
    /// Copies and stages a fixed-buffer send from the current completion dispatcher.
    /// # Errors
    /// Returns stale socket, buffer/operation capacity, or preparation errors.
    /// # Panics
    /// Does not intentionally panic.
    #[inline]
    pub fn send_with_context(
        &mut self,
        context: &mut SubmissionContext<'_>,
        socket: SocketId,
        bytes: &[u8],
        zero_copy: bool,
    ) -> Result<OperationId> {
        let record = Self::record_mut(&mut self.sockets, socket)?;
        if record.phase != SocketSlotPhase::Active {
            return Err(socket_error("socket is closing"));
        }
        if bytes.len() > self.config.buffer_len {
            return Err(socket_error("send exceeds fixed buffer length"));
        }
        let fd = Rc::clone(&record.fd);
        // SAFETY: The handle is consumed by Proactor's tracked DMA metadata before
        // this method returns, or released before any SQE is published on error.
        let mut buffer = unsafe { context.fixed_buffers() }?.checkout()?;
        buffer.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
        let pointer = buffer.as_ptr();
        let index = buffer.id();
        let kind = if zero_copy {
            OperationKind::ZeroCopy
        } else {
            OperationKind::Single
        };
        let key = self.operations.insert_with(kind, |key| SocketOperation {
            key,
            socket,
            kind: SocketOperationKind::Send { zero_copy },
            prev_op: None,
            next_op: None,
        })?;
        let id = OperationId::pack(self.config.subsystem, key.payload());
        let raw_fd = fd.as_raw_fd();
        let prepared =
            context.prepare_owned_sqe_with(id, fd, Some(buffer.into_in_flight()), |sqe| {
                // SAFETY: Proactor retains the descriptor and exact registered DMA
                // token until final send completion and any required ZC notification.
                unsafe {
                    if zero_copy {
                        net::prep_send_zc_fixed(
                            sqe,
                            raw_fd,
                            pointer,
                            bytes.len(),
                            libc::MSG_NOSIGNAL,
                            0,
                            index,
                        );
                    } else {
                        net::prep_send_fixed(sqe, raw_fd, pointer, bytes.len(), libc::MSG_NOSIGNAL);
                    }
                }
            });
        if let Err(error) = prepared {
            self.rollback(key)?;
            return Err(error);
        }
        self.link_op(key, socket)?;
        Ok(id)
    }
    /// Handles an already-completed kernel receive/send and hands over leases.
    /// Drop receive leases before rearming. If operation delivery fails on a closing
    /// socket, retry the same completion to deliver only its pending Closed event.
    /// # Errors
    /// Returns invalid CQE, lease, operation-state, or callback errors.
    /// # Panics
    /// Propagates a callback panic after accounting for the current completion.
    #[inline]
    pub fn on_completion<F>(
        &mut self,
        completion: Completion,
        context: &mut SubmissionContext<'_>,
        mut deliver: F,
    ) -> Result<()>
    where
        F: FnMut(SocketEvent<'_>) -> Result<()>,
    {
        if completion.operation_id.subsystem_id() != self.config.subsystem {
            return Err(UringError::InvalidSubsystemId(
                completion.operation_id.subsystem_id().raw(),
            ));
        }
        if let Err(error) = context.claim_completion(completion) {
            return self
                .retry_closed(completion, &mut deliver)
                .unwrap_or(Err(error));
        }
        let key = OperationKey::from_payload(completion.operation_id.payload())?;
        let Ok(metadata) = self.operations.get(key) else {
            return self
                .retry_closed(completion, &mut deliver)
                .unwrap_or(Ok(()));
        };
        let (socket, kind) = (metadata.socket, metadata.kind);
        let terminal = self
            .operations
            .complete(key, completion.result, completion.flags)?;
        if terminal {
            let operation = self.operations.remove(key)?;
            debug_assert_eq!(operation.key, key);
            self.unlink_op(operation)?;
            let record = Self::record_mut(&mut self.sockets, socket)?;
            record.active = record.active.saturating_sub(1);
            if matches!(kind, SocketOperationKind::Receive) {
                record.receive = None;
            }
            if record.phase == SocketSlotPhase::DrainingInFlight && record.active == 0 {
                record.phase = SocketSlotPhase::Closed;
                record.closed_completion = Some(completion);
            }
        }
        let closed = self.record(socket)?.phase == SocketSlotPhase::Closed;
        if completion.flags & backend::IORING_CQE_F_NOTIF != 0 {
            // Notification usage reports are not errno-bearing send results.
        } else if completion.result < 0 {
            if matches!(kind, SocketOperationKind::Receive)
                && completion.flags & backend::IORING_CQE_F_BUFFER != 0
            {
                let pool = context.buffer_ring(self.config.receive_group)?;
                // SAFETY: The one-shot context claim authenticates this actual
                // selecting CQE. Negative results must return selected inventory.
                match unsafe { pool.lease_from_cqe(completion.flags, completion.result) } {
                    Err(UringError::Syscall {
                        operation: "buffer ring",
                        errno,
                    }) if errno == completion.result.saturating_neg() => {}
                    Err(error) => return Err(error),
                    Ok(lease) => {
                        drop(lease);
                        return Err(socket_error("negative CQE unexpectedly yielded a payload"));
                    }
                }
            }
            match completion.result.saturating_neg() {
                libc::ECANCELED => deliver(SocketEvent::Cancelled {
                    socket,
                    operation: completion.operation_id,
                })?,
                libc::ENOBUFS if matches!(kind, SocketOperationKind::Receive) => {
                    deliver(SocketEvent::BufferUnavailable { socket })?
                }
                errno => deliver(SocketEvent::Error {
                    socket,
                    operation: completion.operation_id,
                    errno,
                })?,
            }
        } else {
            match kind {
                SocketOperationKind::Receive => {
                    if completion.flags & backend::IORING_CQE_F_BUFFER != 0 {
                        let pool = context.buffer_ring(self.config.receive_group)?;
                        // SAFETY: This is the selecting receive's actual CQE;
                        // the kernel has handed off its selected initialized bytes.
                        let lease =
                            unsafe { pool.lease_from_cqe(completion.flags, completion.result) }?;
                        if completion.result > 0 {
                            deliver(SocketEvent::Received {
                                socket,
                                operation: completion.operation_id,
                                data: lease,
                            })?;
                        } else {
                            drop(lease);
                        }
                    } else if completion.result > 0 {
                        return Err(socket_error("receive CQE has no selected buffer"));
                    }
                    if completion.result == 0 {
                        deliver(SocketEvent::ReadClosed { socket })?;
                    }
                }
                SocketOperationKind::Send { .. } => {
                    deliver(SocketEvent::Sent {
                        socket,
                        operation: completion.operation_id,
                        bytes: completion.result as usize,
                    })?;
                }
            }
        }
        if terminal && matches!(kind, SocketOperationKind::Send { zero_copy: true }) {
            deliver(SocketEvent::SendReleased {
                socket,
                operation: completion.operation_id,
            })?;
        }
        if closed {
            self.retire_socket(socket)?;
            deliver(SocketEvent::Closed { socket })?;
        }
        Ok(())
    }
    /// Requests cancellation and defers descriptor reuse through every final CQE.
    /// # Errors
    /// Returns stale identity, operation-budget, or submission errors. Retry is safe.
    /// # Panics
    /// Does not intentionally panic.
    #[inline]
    pub fn close(&mut self, proactor: &mut Proactor, socket: SocketId) -> Result<()> {
        self.close_with(socket, |target| proactor.cancel(target))
    }
    /// Cancels a socket directly from a statically dispatched sibling subsystem.
    /// # Errors
    /// Returns stale identity or bounded staging errors; retrying is safe.
    /// # Panics
    /// Does not intentionally panic.
    #[inline]
    pub fn close_with_context(
        &mut self,
        context: &mut SubmissionContext<'_>,
        socket: SocketId,
    ) -> Result<()> {
        self.close_with(socket, |target| context.cancel(target))
    }

    #[inline]
    fn close_with(
        &mut self,
        socket: SocketId,
        mut cancel: impl FnMut(OperationId) -> Result<bool>,
    ) -> Result<()> {
        let record = Self::record_mut(&mut self.sockets, socket)?;
        if record.active == 0 {
            record.phase = SocketSlotPhase::Closed;
            return self.retire_socket(socket);
        }
        let mut cursor = record.head_op;
        while let Some(key) = cursor {
            let operation = self.operations.get(key)?;
            cursor = operation.next_op;
            if self.operations.state(key)? == OperationState::InFlight {
                let target = OperationId::pack(self.config.subsystem, key.payload());
                if !cancel(target)? {
                    return Err(UringError::InvalidPayload(target.raw()));
                }
                self.operations.mark_canceling(key)?;
                Self::record_mut(&mut self.sockets, socket)?.phase =
                    SocketSlotPhase::DrainingInFlight;
            }
        }
        Self::record_mut(&mut self.sockets, socket)?.phase = SocketSlotPhase::DrainingInFlight;
        Ok(())
    }
    /// Counts retained socket descriptors.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub fn socket_count(&self) -> usize {
        self.sockets
            .iter()
            .filter(|slot| slot.record.is_some())
            .count()
    }
    /// Counts targets retained through their required notifications.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[inline]
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }
    #[cold]
    fn retry_closed<F>(&mut self, completion: Completion, deliver: &mut F) -> Option<Result<()>>
    where
        F: FnMut(SocketEvent<'_>) -> Result<()>,
    {
        // Only a previously authenticated terminal CQE can retry its pending close notification.
        let (index, slot) = self.sockets.iter().enumerate().find(|(_, slot)| {
            slot.record
                .as_ref()
                .is_some_and(|record| record.closed_completion == Some(completion))
        })?;
        let socket = SocketId {
            slot: index as u32,
            generation: slot.generation,
        };
        Some(
            self.retire_socket(socket)
                .and_then(|()| deliver(SocketEvent::Closed { socket })),
        )
    }
    #[inline(always)]
    fn link_op(&mut self, key: OperationKey, socket: SocketId) -> Result<()> {
        let record = Self::record_mut(&mut self.sockets, socket)?;
        let head = record.head_op;
        self.operations.get_mut(key)?.next_op = head;
        if let Some(head) = head {
            self.operations.get_mut(head)?.prev_op = Some(key);
        }
        record.head_op = Some(key);
        record.active += 1;
        Ok(())
    }
    #[inline(always)]
    fn unlink_op(&mut self, operation: SocketOperation) -> Result<()> {
        if let Some(prev) = operation.prev_op {
            self.operations.get_mut(prev)?.next_op = operation.next_op;
        } else {
            Self::record_mut(&mut self.sockets, operation.socket)?.head_op = operation.next_op;
        }
        if let Some(next) = operation.next_op {
            self.operations.get_mut(next)?.prev_op = operation.prev_op;
        }
        Ok(())
    }
    #[inline]
    fn record(&self, id: SocketId) -> Result<&SocketRecord> {
        self.sockets
            .get(id.slot as usize)
            .filter(|slot| slot.generation == id.generation)
            .and_then(|slot| slot.record.as_ref())
            .ok_or(UringError::InvalidPayload(id.raw()))
    }
    #[inline]
    fn record_mut(sockets: &mut [SocketSlot], id: SocketId) -> Result<&mut SocketRecord> {
        sockets
            .get_mut(id.slot as usize)
            .filter(|slot| slot.generation == id.generation)
            .and_then(|slot| slot.record.as_mut())
            .ok_or(UringError::InvalidPayload(id.raw()))
    }
    #[cold]
    #[inline(never)]
    fn rollback(&mut self, key: OperationKey) -> Result<()> {
        // SAFETY: The preparation returned an error before publishing this key.
        let _removed = unsafe { self.operations.discard_unsubmitted(key) }?;
        Ok(())
    }
    #[inline]
    fn retire_socket(&mut self, id: SocketId) -> Result<()> {
        if self.record(id)?.active != 0 {
            return Err(socket_error("socket still has DMA operations"));
        }
        let slot = &mut self.sockets[id.slot as usize];
        drop(slot.record.take());
        if let Some(next) = slot.generation.checked_add(1) {
            slot.generation = next;
            self.free.push(id.slot as usize);
        }
        Ok(())
    }
}
#[cold]
#[inline(never)]
fn socket_error(message: &'static str) -> UringError {
    UringError::InvalidConfig(message)
}

impl Drop for CompletionSocketIo {
    fn drop(&mut self) {
        for slot in &self.sockets {
            if let Some(record) = &slot.record {
                // SAFETY: The descriptor is owned here or retained by Proactor's
                // tracked metadata. Shutdown wakes pending I/O without fd reuse.
                unsafe { libc::shutdown(record.fd.as_raw_fd(), libc::SHUT_RDWR) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::unix::net::UnixStream,
        time::{Duration, Instant},
    };

    use super::*;
    use crate::ProactorConfig;

    #[test]
    fn negative_selection_preserves_inventory() -> Result<()> {
        let mut proactor = Proactor::new(ProactorConfig {
            entries: 16,
            ..ProactorConfig::default()
        })?;
        let mut io = CompletionSocketIo::new(
            &mut proactor,
            SocketIoConfig {
                sockets: 1,
                operations: 8,
                receive_buffers: 2,
                send_buffers: 1,
                buffer_len: 64,
                ..SocketIoConfig::default()
            },
        )?;
        let (receiver, mut sender) = UnixStream::pair()?;
        let socket = io.insert(receiver.into())?;
        let receive = io.receive(&mut proactor, socket, ReceiveMode::Once)?;
        sender.write_all(b"selected")?;
        let mut observed = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !observed {
            assert!(Instant::now() < deadline, "receive timeout");
            proactor.wait_completions(
                1,
                Some(Duration::from_millis(20)),
                &mut |actual: Completion, context: &mut SubmissionContext<'_>| {
                    assert_eq!(actual.operation_id, receive);
                    assert_eq!(actual.result, 8);
                    assert_ne!(actual.flags & backend::IORING_CQE_F_BUFFER, 0);
                    assert_eq!(actual.flags & backend::IORING_CQE_F_MORE, 0);
                    // The real selecting CQE above already transferred this buffer
                    // out of kernel ownership. Only its result is fault-injected;
                    // unread or still kernel-owned storage is never fabricated.
                    let negative = Completion {
                        result: -libc::EIO,
                        ..actual
                    };
                    context.current_completion = Some(negative);
                    let returned = context.buffer_ring(BufferGroupId(1))?.returned_count();
                    let mut errors = 0;
                    io.on_completion(negative, context, |event| {
                        if let SocketEvent::Error { errno, .. } = event {
                            assert_eq!(errno, libc::EIO);
                            errors += 1;
                        } else {
                            assert!(!matches!(event, SocketEvent::Received { .. }));
                        }
                        Ok(())
                    })?;
                    assert_eq!(errors, 1);
                    assert_eq!(
                        context.buffer_ring(BufferGroupId(1))?.returned_count(),
                        returned + 1
                    );
                    assert_eq!(io.operation_count(), 0);
                    observed = true;
                    Ok(())
                },
            )?;
        }
        io.close(&mut proactor, socket)?;
        assert_eq!(io.socket_count(), 0);
        proactor.shutdown()
    }
}
