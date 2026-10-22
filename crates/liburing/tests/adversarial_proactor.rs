//! Completion routing and kernel scenarios for reentrant I/O and resource recovery.
#![cfg(target_os = "linux")]

use std::{
    cell::RefCell,
    collections::HashSet,
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    rc::Rc,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

use liburing::{
    Completion, CrossThreadCommandQueue, OpId, OpPayload, Proactor, ProactorConfig,
    SubmissionContext, SubsystemHandler, SubsystemId, UringError,
};
use liburing_sys as sys;

const SQ_DEPTH: u32 = 16;
const REENTRANT_OPERATIONS: usize = 128;
const COMMAND_THREADS: usize = 4;
const COMMANDS_PER_THREAD: usize = 2_500;
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(15);

fn blocking_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: pipe2 initializes both writable slots; O_CLOEXEC leaves reads blocking.
    let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Each distinct descriptor from pipe2 transfers ownership exactly once.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn assert_before_deadline(started: Instant, scenario: &str) {
    assert!(
        started.elapsed() < SCENARIO_TIMEOUT,
        "{scenario} did not finish before the deadline"
    );
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn kernel_proactor(waker: bool) -> Result<Proactor, UringError> {
    Proactor::new(ProactorConfig {
        entries: SQ_DEPTH,
        staged_capacity: 1024,
        max_cqe_batch: 256,
        enable_waker: waker,
        ..ProactorConfig::default()
    })
}

fn route(id: u8) -> SubsystemId {
    SubsystemId::new(id).expect("test uses a nonzero routing ID")
}

fn operation(id: SubsystemId, payload: u64) -> OpId {
    OpId::pack(
        id,
        OpPayload::new(payload).expect("test payload fits 56 bits"),
    )
}

#[derive(Clone)]
struct Recorder(Rc<RefCell<Vec<Completion>>>);

impl SubsystemHandler for Recorder {
    fn on_completion(
        &mut self,
        completion: Completion,
        _: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        self.0.borrow_mut().push(completion);
        Ok(())
    }
}

#[test]
fn integration_scenario_reentrant_sq_saturation_preserves_all_128_operations() -> TestResult {
    static BYTES: [u8; REENTRANT_OPERATIONS] = [0x5a; REENTRANT_OPERATIONS];
    let (read_end, write_end) = blocking_pipe()?;
    let write_fd = write_end.as_raw_fd();
    let mut proactor = kernel_proactor(false)?;
    let id = route(1);
    let observed = Rc::new(RefCell::new(Vec::new()));
    proactor.register_subsystem(id, Recorder(Rc::clone(&observed)))?;
    proactor.alloc_sqe(operation(id, 0))?;
    let started = Instant::now();
    let mut staged = false;
    let mut checked_fifo = false;
    while observed.borrow().len() < REENTRANT_OPERATIONS + 1 {
        assert_before_deadline(started, "reentrant SQ saturation");
        proactor.wait_completions(1, Some(Duration::from_millis(20)), |completion, context| {
            let seed = completion.op_id.payload().raw() == 0;
            assert_eq!(completion.result, if seed { 0 } else { 1 });
            if seed {
                assert!(!staged, "seed CQE was dispatched twice");
                for sequence in 1..=REENTRANT_OPERATIONS {
                    context.prepare_sqe_with(operation(id, sequence as u64), |sqe| {
                        // SAFETY: Exclusive SQE storage references immutable static
                        // bytes; the pipe stays open through every final CQE.
                        unsafe {
                            let byte = &BYTES[sequence - 1] as *const u8;
                            sys::uring_shim_prep_write(sqe, write_fd, byte.cast(), 1, 0);
                        }
                    })?;
                }
                staged = true;
            }
            Ok(())
        })?;
        if staged && !checked_fifo {
            // SAFETY: Only this thread owns the live non-SQPOLL ring. Read only
            // initialized unpublished SQEs; no submission or CQ mutation occurs.
            let sq = unsafe { &(*proactor.ring_mut()).sq };
            assert_eq!(sq.sqe_tail.wrapping_sub(sq.sqe_head), SQ_DEPTH);
            for offset in 0..SQ_DEPTH {
                let index = sq.sqe_head.wrapping_add(offset) & sq.ring_mask;
                // SAFETY: The masked index identifies an initialized SQE above.
                let raw = unsafe { (*sq.sqes.add(index as usize)).user_data };
                assert_eq!(raw, operation(id, u64::from(offset + 1)).raw());
            }
            checked_fifo = true;
        }
    }
    assert!(staged);
    let completions = observed.borrow();
    assert_eq!(completions.len(), REENTRANT_OPERATIONS + 1);
    let unique: HashSet<_> = completions.iter().map(|c| c.op_id.raw()).collect();
    assert_eq!(unique.len(), REENTRANT_OPERATIONS + 1);
    for sequence in 0..=REENTRANT_OPERATIONS {
        assert!(unique.contains(&operation(id, sequence as u64).raw()));
    }
    let mut actual = [0; REENTRANT_OPERATIONS];
    std::fs::File::from(read_end).read_exact(&mut actual)?;
    assert_eq!(actual, BYTES, "every staged write must complete");
    assert_eq!(
        proactor.tick()?,
        0,
        "completed operations must not be dispatched again"
    );
    Ok(())
}

#[test]
fn integration_scenario_three_subsystems_reuse_56_bit_payloads_without_crosstalk() -> TestResult {
    const PER_SUBSYSTEM: usize = 32;
    const OPERATIONS: usize = PER_SUBSYSTEM * 2;
    let pipes = [blocking_pipe()?, blocking_pipe()?, blocking_pipe()?];
    let mut proactor = kernel_proactor(false)?;
    let mut inbound = std::mem::ManuallyDrop::new([
        Box::new([0_u8; PER_SUBSYSTEM]),
        Box::new([0; PER_SUBSYSTEM]),
        Box::new([0; PER_SUBSYSTEM]),
    ]);
    let mut outbound = std::mem::ManuallyDrop::new([
        Box::new([0x31_u8; PER_SUBSYSTEM]),
        Box::new([0x72; PER_SUBSYSTEM]),
        Box::new([0xb4; PER_SUBSYSTEM]),
    ]);
    // Failure retains DMA storage; success frees it only after final CQEs and shutdown.
    let records: Vec<_> = (0..3).map(|_| Rc::new(RefCell::new(Vec::new()))).collect();
    for (index, record) in records.iter().enumerate() {
        proactor.register_subsystem(route(index as u8 + 1), Recorder(Rc::clone(record)))?;
    }
    for sequence in 0..PER_SUBSYSTEM {
        for subsystem in 0..3 {
            let id = route(subsystem as u8 + 1);
            let payload = 0x00ff_ffff_ffff_0000 | sequence as u64;
            let read_ptr = (&mut inbound[subsystem][sequence]) as *mut u8;
            let write_ptr = (&outbound[subsystem][sequence]) as *const u8;
            let read_fd = pipes[subsystem].0.as_raw_fd();
            let write_fd = pipes[subsystem].1.as_raw_fd();
            proactor.prepare_sqe_with(operation(id, payload), |sqe| {
                // SAFETY: Each read owns a disjoint byte in stable storage.
                // ManuallyDrop retains the allocations on every failure path;
                // success releases them only after all final CQEs and shutdown.
                unsafe { sys::uring_shim_prep_read(sqe, read_fd, read_ptr.cast(), 1, 0) };
            })?;
            proactor.prepare_sqe_with(operation(id, payload + 0x8000), |sqe| {
                // SAFETY: Each write references an immutable stable byte.
                // Storage is retained on errors and freed only after shutdown
                // confirms that every submitted operation has retired.
                unsafe { sys::uring_shim_prep_write(sqe, write_fd, write_ptr.cast(), 1, 0) };
            })?;
        }
    }
    let started = Instant::now();
    while records
        .iter()
        .any(|record| record.borrow().len() < OPERATIONS)
    {
        assert_before_deadline(started, "multi-subsystem pipe I/O");
        proactor.wait_completions(1, Some(Duration::from_millis(20)), |_, _| Ok(()))?;
    }
    for (subsystem, record) in records.iter().enumerate() {
        let completions = record.borrow();
        assert_eq!(completions.len(), OPERATIONS);
        let mut unique = HashSet::new();
        for completion in completions.iter() {
            assert_eq!(completion.op_id.subsystem_id(), route(subsystem as u8 + 1));
            assert_eq!(completion.result, 1);
            assert!(unique.insert(completion.op_id.payload().raw()));
        }
        let expected: HashSet<_> = (0..PER_SUBSYSTEM as u64)
            .flat_map(|n| [0x00ff_ffff_ffff_0000 | n, 0x00ff_ffff_ffff_8000 | n])
            .collect();
        assert_eq!(unique, expected, "full-width read/write payloads");
        assert_eq!(*inbound[subsystem], *outbound[subsystem]);
    }
    proactor.shutdown()?;
    // SAFETY: Every read/write delivered its final CQE, and successful shutdown
    // confirms no submitted operation still references these allocations.
    unsafe {
        std::mem::ManuallyDrop::drop(&mut inbound);
        std::mem::ManuallyDrop::drop(&mut outbound);
    }
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_waker_flood_delivers_10000_unique_commands() -> TestResult {
    let mut proactor = kernel_proactor(true)?;
    let waker = proactor.waker().expect("waker was explicitly enabled");
    let total = COMMAND_THREADS * COMMANDS_PER_THREAD;
    let commands = CrossThreadCommandQueue::new(total, waker);
    let gate = Arc::new(Barrier::new(COMMAND_THREADS + 1));
    let mut workers = Vec::new();
    for producer in 0..COMMAND_THREADS {
        let queue = commands.clone();
        let gate = Arc::clone(&gate);
        workers.push(thread::spawn(move || -> liburing::Result<()> {
            gate.wait();
            // This delay lets the consumer enter its blocking kernel wait. All
            // producers then race on one eventfd; wakes may legally coalesce.
            thread::sleep(Duration::from_millis(25));
            for sequence in 0..COMMANDS_PER_THREAD {
                queue.push(producer * COMMANDS_PER_THREAD + sequence)?;
            }
            Ok(())
        }));
    }
    let mut seen = vec![false; total];
    let mut received = 0;
    let started = Instant::now();
    gate.wait();
    while received < total {
        assert_before_deadline(started, "cross-thread wakeup flood");
        // A missing eventfd wake is a failure, rather than a periodic timeout
        // allowing queued commands to be consumed without a corresponding CQE.
        let harvested =
            proactor.wait_completions(1, Some(Duration::from_secs(2)), |_, _| Ok(()))?;
        assert!(
            harvested > 0,
            "accepted commands did not wake the sleeping proactor"
        );
        while let Some(command) = commands.pop()? {
            assert!(command < total);
            assert!(
                !seen[command],
                "command {command} was delivered more than once"
            );
            seen[command] = true;
            received += 1;
        }
    }
    for worker in workers {
        worker.join().expect("command producer panicked")?;
    }
    assert_eq!(received, total);
    assert!(seen.iter().all(|delivered| *delivered));
    assert!(commands.is_empty()?);
    drop(proactor);
    assert!(matches!(commands.push(total), Err(UringError::WakerClosed)));
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_fixed_read_cancellation_quarantines_until_target_cqe()
-> TestResult {
    const BUFFER_COUNT: u16 = 16;
    let (read_end, _writer_kept_open) = blocking_pipe()?;
    let mut proactor = kernel_proactor(false)?;
    let records = Rc::new(RefCell::new(Vec::new()));
    let id = route(1);
    proactor.register_subsystem(id, Recorder(Rc::clone(&records)))?;
    // SAFETY: This is the only fixed-buffer registration on this live ring.
    // Pool and waiting handles drop before proactor, including during unwinding.
    let mut pool = unsafe {
        liburing::fixed_buffers::FixedBufferPool::new(proactor.ring_mut(), BUFFER_COUNT, 64)?
    };
    let mut waiting = Vec::new();
    for sequence in 0..BUFFER_COUNT {
        let mut buffer = pool.checkout()?;
        let buffer_id = buffer.id();
        let address = buffer.as_mut_ptr();
        waiting.push(Some(buffer.into_in_flight()));
        proactor.prepare_sqe_with(operation(id, u64::from(sequence)), |sqe| {
            // SAFETY: The transferred waiting token retains registered stable
            // storage without user access until this read's own final CQE.
            unsafe {
                sys::uring_shim_prep_read_fixed(
                    sqe,
                    read_end.as_raw_fd(),
                    address.cast(),
                    64,
                    0,
                    i32::from(buffer_id.0),
                );
            }
        })?;
    }
    proactor.submit()?;
    assert_eq!(pool.available(), 0);
    assert!(matches!(
        pool.checkout(),
        Err(UringError::FixedBuffersExhausted)
    ));
    for sequence in 0..BUFFER_COUNT {
        waiting[usize::from(sequence)]
            .as_mut()
            .expect("waiting token exists")
            .quarantine()?;
        proactor.prepare_sqe_with(operation(id, 0x1000 + u64::from(sequence)), |sqe| {
            // SAFETY: Cancellation uses the exact read user_data, not its buffer
            // address; it does not grant access to the target's DMA storage.
            unsafe {
                sys::uring_shim_prep_cancel64(sqe, operation(id, u64::from(sequence)).raw(), 0)
            };
        })?;
    }
    proactor.submit()?;
    assert_eq!(
        pool.available(),
        0,
        "even kernel-completed requests await CQE handoff"
    );
    assert!(matches!(
        pool.checkout(),
        Err(UringError::FixedBuffersExhausted)
    ));
    let mut target_seen = [false; BUFFER_COUNT as usize];
    let mut control_seen = [false; BUFFER_COUNT as usize];
    let started = Instant::now();
    while target_seen.iter().any(|seen| !seen) || control_seen.iter().any(|seen| !seen) {
        assert_before_deadline(started, "fixed-buffer cancellation quarantine");
        proactor.wait_completions(1, Some(Duration::from_millis(20)), |completion, _| {
            let payload = completion.op_id.payload().raw();
            assert_eq!(completion.flags & sys::IORING_CQE_F_MORE, 0);
            if payload < u64::from(BUFFER_COUNT) {
                let index = payload as usize;
                assert!(!target_seen[index]);
                assert_eq!(completion.result, -libc::ECANCELED);
                target_seen[index] = true;
                let token = waiting[index].take().expect("target owns a waiting buffer");
                // SAFETY: This exact read's final CQE was copied and acknowledged
                // before dispatch. ECANCELED means it cannot perform more DMA.
                let completed = unsafe { token.complete()? };
                drop(completed);
            } else {
                let index = (payload - 0x1000) as usize;
                assert!(index < usize::from(BUFFER_COUNT));
                assert!(!control_seen[index]);
                control_seen[index] = true;
                assert!([0, -libc::ENOENT, -libc::EALREADY].contains(&completion.result));
                if !target_seen[index] {
                    assert!(waiting[index].is_some(), "cancel CQE released target DMA");
                }
            }
            assert_eq!(
                pool.available(),
                target_seen.iter().filter(|seen| **seen).count()
            );
            Ok(())
        })?;
    }
    assert_eq!(records.borrow().len(), usize::from(BUFFER_COUNT) * 2);
    assert_eq!(pool.available(), pool.capacity());
    let recovered: Vec<_> = (0..BUFFER_COUNT)
        .map(|_| pool.checkout())
        .collect::<liburing::Result<_>>()?;
    let ids: HashSet<_> = recovered.iter().map(|buffer| buffer.id()).collect();
    assert_eq!(ids.len(), usize::from(BUFFER_COUNT));
    drop(recovered);
    assert_eq!(pool.available(), usize::from(BUFFER_COUNT));
    pool.unregister()?;
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_provided_ring_exhaustion_recovers_after_lease_return()
-> TestResult {
    use std::{mem::ManuallyDrop, net::UdpSocket};

    use liburing::pbuf_ring::ProvidedBufRing;

    const DATAGRAMS: u8 = 64;
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.connect(receiver.local_addr()?)?;
    receiver.set_nonblocking(true)?;
    let mut proactor = kernel_proactor(false)?;
    let id = route(1);
    let receive = operation(id, 0x100);
    let cancel = operation(id, 0x200);
    let records = Rc::new(RefCell::new(Vec::new()));
    proactor.register_subsystem(id, Recorder(Rc::clone(&records)))?;
    // SAFETY: The group is exclusively registered on this live ring. Successful
    // cleanup below drains the receive's final CQE before unregistration. During
    // failure unwinding ManuallyDrop retains the DMA allocations until process
    // exit, while the proactor first tears down its kernel ring.
    let mut buffers = ManuallyDrop::new(unsafe {
        ProvidedBufRing::new(proactor.ring_mut(), 2, 64, liburing::BufGroupId(7))?
    });
    proactor.prepare_sqe_with(receive, |sqe| {
        // SAFETY: The selected group remains registered and its allocations
        // remain stable until the final receive CQE, including cancellation.
        unsafe {
            liburing::ops::net::prep_recv_multishot(
                sqe,
                receiver.as_raw_fd(),
                buffers.group_id(),
                0,
            );
        }
    })?;
    for sequence in 0..DATAGRAMS {
        assert_eq!(sender.send(&[sequence, sequence ^ 0xa5])?, 2);
    }
    let mut held = Vec::new();
    let mut seen = [false; DATAGRAMS as usize];
    let mut received = 0;
    let mut depleted = false;
    let mut active = true;
    let mut exhaustions = 0;
    let mut rearms = 0;
    let started = Instant::now();
    while received < usize::from(DATAGRAMS) {
        assert_before_deadline(started, "provided-ring exhaustion recovery");
        proactor.wait_completions(1, Some(Duration::from_millis(20)), |completion, _| {
            assert_eq!(completion.op_id, receive);
            if completion.result == -libc::ENOBUFS {
                assert_eq!(completion.flags & sys::IORING_CQE_F_MORE, 0);
                assert_eq!(
                    held.len(),
                    2,
                    "depletion requires both buffers to be leased"
                );
                buffers.mark_depleted_recv(receiver.as_raw_fd(), 0, receive)?;
                active = false;
                depleted = true;
                exhaustions += 1;
            } else {
                assert_eq!(completion.result, 2, "multishot receive failed");
                assert_ne!(completion.flags & sys::IORING_CQE_F_MORE, 0);
                // SAFETY: This successful CQE selects this exact group and is
                // consumed once. No incremental-buffer mode was requested.
                let lease = unsafe { buffers.lease_from_cqe(completion.flags, completion.result)? };
                let sequence = usize::from(lease[0]);
                assert!(sequence < usize::from(DATAGRAMS));
                assert_eq!(lease[1], lease[0] ^ 0xa5);
                assert!(!seen[sequence], "datagram {sequence} was delivered twice");
                seen[sequence] = true;
                received += 1;
                held.push(lease);
            }
            Ok(())
        })?;
        if depleted {
            let unchanged = buffers.rearm_depleted_recvs(|_, _, _, _| {
                panic!("receive rearmed before a buffer lease was returned");
            })?;
            assert_eq!(unchanged, 0);
            let returned_before = buffers.returned_count();
            held.clear();
            assert_eq!(buffers.returned_count(), returned_before + 2);
            if received < usize::from(DATAGRAMS) {
                let rearmed = buffers.rearm_depleted_recvs(|fd, flags, op_id, group| {
                    proactor.prepare_sqe_with(op_id, |sqe| {
                        // SAFETY: The library requests a rearm only after lease
                        // return republishes descriptors in this live group.
                        unsafe { liburing::ops::net::prep_recv_multishot(sqe, fd, group, flags) };
                    })
                })?;
                assert_eq!(rearmed, 1);
                rearms += rearmed;
                active = true;
            }
            depleted = false;
        }
    }
    assert!(
        exhaustions > 0,
        "the burst never exhausted the two-buffer ring"
    );
    assert!(
        rearms > 0,
        "returned leases never restored a depleted receive"
    );
    assert!(seen.iter().all(|delivered| *delivered));
    drop(held);
    if active {
        proactor.prepare_sqe_with(cancel, |sqe| {
            // SAFETY: This exact live receive owns the group; cancellation must
            // still be followed by its own final CQE before freeing the group.
            unsafe { sys::uring_shim_prep_cancel64(sqe, receive.raw(), 0) };
        })?;
        let mut target_final = false;
        let mut control_final = false;
        while !target_final || !control_final {
            assert_before_deadline(started, "provided-ring receive teardown");
            proactor.wait_completions(1, Some(Duration::from_millis(20)), |completion, _| {
                if completion.op_id == receive {
                    assert_eq!(completion.flags & sys::IORING_CQE_F_MORE, 0);
                    assert!([-libc::ECANCELED, -libc::ENOBUFS].contains(&completion.result));
                    assert!(!target_final);
                    target_final = true;
                } else {
                    assert_eq!(completion.op_id, cancel);
                    assert!([0, -libc::ENOENT, -libc::EALREADY].contains(&completion.result));
                    assert!(!control_final);
                    control_final = true;
                }
                Ok(())
            })?;
        }
    }
    assert_eq!(buffers.returned_count(), u64::from(DATAGRAMS));
    // SAFETY: All leases were returned and every submitted receive delivered its
    // final CQE. The proactor is still alive for unregistration and destruction.
    unsafe {
        buffers.unregister()?;
        ManuallyDrop::drop(&mut buffers);
    }
    Ok(())
}

use liburing::socket_bridge::{
    BridgeOpKind, BridgeSubmission, SocketInterest, UringSocketBridge, UringSocketOps,
};

type BridgeQueue = Rc<RefCell<std::collections::VecDeque<(OpId, BridgeSubmission<OpId>)>>>;

struct KernelBridgeOps {
    id: SubsystemId,
    queue: BridgeQueue,
}

impl UringSocketOps for KernelBridgeOps {
    type OpId = OpId;
    type Error = UringError;

    fn subsystem_id(&self) -> SubsystemId {
        self.id
    }

    fn submit(&mut self, token: u64, submission: BridgeSubmission<OpId>) -> liburing::Result<OpId> {
        let id = operation(self.id, token);
        self.queue.borrow_mut().push_back((id, submission));
        Ok(id)
    }
}

fn flush_bridge_queue(proactor: &mut Proactor, queue: &BridgeQueue) -> liburing::Result<()> {
    while let Some((id, submission)) = queue.borrow_mut().pop_front() {
        if matches!(submission, BridgeSubmission::Connect { .. }) {
            return Err(UringError::InvalidConfig(
                "connection is outside this readiness scenario",
            ));
        }
        proactor.prepare_sqe_with(id, |sqe| {
            // SAFETY: Preparation owns initialized SQE storage. Poll and control
            // operations retain no DMA pointers; descriptor ownership stays with
            // the bridge until its final Close CQE. Target IDs are native keys.
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
                    BridgeSubmission::Close { fd } => sys::uring_shim_prep_close(sqe, fd),
                    BridgeSubmission::Connect { .. } => unreachable!("rejected before staging"),
                }
            }
        })?;
    }
    proactor.submit()?;
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_socket_bridge_maps_native_poll_and_close_operations() -> TestResult
{
    use std::os::{fd::IntoRawFd, unix::net::UnixDatagram};

    let (socket, _peer_kept_open) = UnixDatagram::pair()?;
    socket.set_nonblocking(true)?;
    let mut proactor = kernel_proactor(false)?;
    let id = route(3);
    let records = Rc::new(RefCell::new(Vec::new()));
    proactor.register_subsystem(id, Recorder(Rc::clone(&records)))?;
    let queue = Rc::new(RefCell::new(std::collections::VecDeque::new()));
    let mut bridge = UringSocketBridge::new(
        id,
        KernelBridgeOps {
            id,
            queue: Rc::clone(&queue),
        },
        1,
    )?;
    // Ownership transfers exactly once. The bridge submits the only close; on
    // failure the raw descriptor is retained rather than racing kernel teardown.
    let fd = socket.into_raw_fd();
    bridge.register(fd)?;
    bridge.set_interest(fd, SocketInterest::READABLE)?;
    let original = queue.borrow().front().expect("initial poll is staged").0;
    flush_bridge_queue(&mut proactor, &queue)?;
    bridge.set_interest(fd, SocketInterest::WRITABLE)?;
    assert!(
        matches!(queue.borrow().front(), Some((_, BridgeSubmission::PollRemove { target, .. })) if *target == original)
    );
    flush_bridge_queue(&mut proactor, &queue)?;
    let mut old_final = false;
    let mut removal_final = false;
    let started = Instant::now();
    while !old_final || !removal_final {
        assert_before_deadline(started, "socket bridge interest replacement");
        proactor.wait_completions(1, Some(Duration::from_millis(20)), |completion, _| {
            let event = bridge
                .on_completion(completion)
                .expect("native bridge token routes");
            assert_eq!(event.fd, fd);
            assert!(event.interest.is_empty());
            assert_eq!(completion.flags & sys::IORING_CQE_F_MORE, 0);
            match event.kind {
                BridgeOpKind::PollAdd => {
                    assert_eq!(completion.op_id, original);
                    assert_eq!(event.result, -libc::ECANCELED);
                    assert!(!old_final);
                    old_final = true;
                }
                BridgeOpKind::PollRemove => {
                    assert_eq!(event.result, 0);
                    assert!(!removal_final);
                    removal_final = true;
                }
                other => panic!("unexpected replacement event {other:?}"),
            }
            bridge.drive().expect("bridge drive succeeds");
            assert!(
                queue.borrow().is_empty() || (old_final && removal_final),
                "replacement rearmed before both CQEs retired"
            );
            Ok(())
        })?;
    }
    assert_eq!(queue.borrow().len(), 1);
    flush_bridge_queue(&mut proactor, &queue)?;
    let mut writable = false;
    while !writable {
        assert_before_deadline(started, "socket bridge writable readiness");
        proactor.wait_completions(1, Some(Duration::from_millis(20)), |completion, _| {
            let event = bridge
                .on_completion(completion)
                .expect("writable token routes");
            assert_eq!(event.fd, fd);
            assert_eq!(event.kind, BridgeOpKind::PollAdd);
            assert_eq!(event.interest, SocketInterest::WRITABLE);
            assert_ne!(event.result & i32::from(libc::POLLOUT), 0);
            writable = true;
            Ok(())
        })?;
    }
    bridge.set_interest(fd, SocketInterest::READABLE)?;
    let closing_target = queue.borrow().front().expect("readable poll is staged").0;
    flush_bridge_queue(&mut proactor, &queue)?;
    bridge.close(fd)?;
    assert!(
        matches!(queue.borrow().front(), Some((_, BridgeSubmission::Cancel { target, .. })) if *target == closing_target)
    );
    flush_bridge_queue(&mut proactor, &queue)?;
    let mut poll_final = false;
    let mut cancel_final = false;
    while !poll_final || !cancel_final {
        assert_before_deadline(started, "socket bridge close cancellation");
        proactor.wait_completions(1, Some(Duration::from_millis(20)), |completion, _| {
            let event = bridge
                .on_completion(completion)
                .expect("closing token routes");
            assert!(event.interest.is_empty());
            match event.kind {
                BridgeOpKind::PollAdd => {
                    assert_eq!(completion.op_id, closing_target);
                    assert_eq!(event.result, -libc::ECANCELED);
                    poll_final = true;
                }
                BridgeOpKind::Cancel => {
                    assert_eq!(event.result, 0);
                    cancel_final = true;
                }
                other => panic!("unexpected closing event {other:?}"),
            }
            bridge.drive().expect("close drive succeeds");
            assert!(
                queue.borrow().is_empty() || (poll_final && cancel_final),
                "descriptor close raced target/control retirement"
            );
            Ok(())
        })?;
    }
    assert!(
        matches!(queue.borrow().front(), Some((_, BridgeSubmission::Close { fd: closing })) if *closing == fd)
    );
    flush_bridge_queue(&mut proactor, &queue)?;
    let mut closed = false;
    while !closed {
        assert_before_deadline(started, "socket bridge final close");
        proactor.wait_completions(1, Some(Duration::from_millis(20)), |completion, _| {
            let event = bridge
                .on_completion(completion)
                .expect("close token routes");
            assert_eq!(event.fd, fd);
            assert_eq!(event.kind, BridgeOpKind::Close);
            assert_eq!(event.result, 0);
            closed = true;
            Ok(())
        })?;
    }
    assert!(matches!(
        bridge.close(fd),
        Err(liburing::socket_bridge::BridgeError::UnknownFd)
    ));
    assert_eq!(records.borrow().len(), 6);
    assert!(queue.borrow().is_empty());
    proactor.shutdown()?;
    Ok(())
}

#[test]
fn unit_lifecycle_scenario_bridge_multishot_routing_and_interest_aba() -> TestResult {
    let id = route(3);
    let queue = Rc::new(RefCell::new(std::collections::VecDeque::new()));
    let ops = KernelBridgeOps {
        id,
        queue: Rc::clone(&queue),
    };
    let mut bridge = UringSocketBridge::new(id, ops, 1)?;
    bridge.register(7)?;
    bridge.set_interest(7, SocketInterest::READABLE)?;
    let op_id = queue.borrow()[0].0;
    let cqe = |op_id, result, flags| Completion {
        op_id,
        result,
        flags,
    };
    let foreign = OpId::pack(route(2), op_id.payload());
    assert_eq!(bridge.on_completion(cqe(foreign, 1, 0)), None);
    for result in [1, 0x10, -libc::ECONNRESET] {
        let event = bridge
            .on_completion(cqe(op_id, result, sys::IORING_CQE_F_MORE))
            .expect("active multishot token routes");
        assert_eq!((event.fd, event.result), (7, result));
        assert!(event.interest.contains(SocketInterest::READABLE));
        assert_eq!(
            event.interest.contains(SocketInterest::WRITABLE),
            result != 1
        );
        bridge.drive()?;
        assert_eq!(queue.borrow().len(), 1);
    }
    assert!(bridge.on_completion(cqe(op_id, 1, 0)).is_some());
    bridge.drive()?;
    let replacement = queue.borrow()[1].0;
    bridge.set_interest(7, SocketInterest::WRITABLE)?;
    bridge.set_interest(7, SocketInterest::READABLE)?;
    let removal = queue.borrow()[2].0;
    bridge
        .on_completion(cqe(removal, -libc::ENOMEM, 0))
        .expect("failed removal retires its control");
    bridge.drive()?;
    assert_eq!(queue.borrow().len(), 4);
    let stale = bridge
        .on_completion(cqe(replacement, i32::from(libc::POLLIN), 0))
        .expect("superseded poll retires");
    assert!(
        stale.interest.is_empty(),
        "superseded poll signalled after interest ABA"
    );
    Ok(())
}
