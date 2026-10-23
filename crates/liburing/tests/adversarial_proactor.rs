//! Completion routing and kernel scenarios for reentrant I/O and resource recovery.
#![cfg(target_os = "linux")]

use std::{
    collections::HashSet,
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use io_uring::{opcode, types};
use liburing::{
    Completion, OperationId, OperationPayload, Proactor, ProactorConfig, SubmissionContext,
    SubsystemId, UringError, backend as sys,
};

const SQ_DEPTH: u32 = 16;
const REENTRANT_OPERATIONS: usize = 128;
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

fn kernel_proactor() -> Result<Proactor, UringError> {
    Proactor::new(ProactorConfig {
        entries: SQ_DEPTH,
        staged_capacity: 1024,
        max_cqe_batch: 256,
        ..ProactorConfig::default()
    })
}

fn route(id: u8) -> SubsystemId {
    SubsystemId::new_unchecked(id)
}

fn operation(id: SubsystemId, payload: u64) -> OperationId {
    OperationId::pack(id, OperationPayload::new_unchecked(payload))
}

#[test]
fn integration_scenario_reentrant_sq_saturation_preserves_all_128_operations() -> TestResult {
    static BYTES: [u8; REENTRANT_OPERATIONS] = [0x5a; REENTRANT_OPERATIONS];
    let (read_end, write_end) = blocking_pipe()?;
    let write_fd = write_end.as_raw_fd();
    let mut proactor = kernel_proactor()?;
    let id = route(1);
    let mut observed = Vec::new();
    proactor.alloc_sqe(operation(id, 0))?;
    let started = Instant::now();
    let mut staged = false;
    while observed.len() < REENTRANT_OPERATIONS + 1 {
        assert_before_deadline(started, "reentrant SQ saturation");
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |completion: Completion, context: &mut SubmissionContext<'_>| {
                observed.push(completion);
                let seed = completion.operation_id.payload().raw() == 0;
                assert_eq!(completion.result, if seed { 0 } else { 1 });
                if seed {
                    assert!(!staged, "seed CQE was dispatched twice");
                    for sequence in 1..=REENTRANT_OPERATIONS {
                        context.prepare_sqe_with(operation(id, sequence as u64), |sqe| {
                            // SAFETY: Exclusive SQE storage references immutable static
                            // bytes; the pipe stays open through every final CQE.
                            unsafe {
                                let byte = &BYTES[sequence - 1] as *const u8;
                                prepare_write(sqe, write_fd, byte.cast(), 1, 0);
                            }
                        })?;
                    }
                    staged = true;
                }
                Ok(())
            },
        )?;
    }
    assert!(staged);
    let completions = &observed;
    assert_eq!(completions.len(), REENTRANT_OPERATIONS + 1);
    let unique: HashSet<_> = completions.iter().map(|c| c.operation_id.raw()).collect();
    assert_eq!(unique.len(), REENTRANT_OPERATIONS + 1);
    for sequence in 0..=REENTRANT_OPERATIONS {
        assert!(unique.contains(&operation(id, sequence as u64).raw()));
    }
    let mut actual = [0; REENTRANT_OPERATIONS];
    std::fs::File::from(read_end).read_exact(&mut actual)?;
    assert_eq!(actual, BYTES, "every staged write must complete");
    assert_eq!(
        proactor.tick(&mut |_: Completion, _: &mut SubmissionContext<'_>| Ok(()))?,
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
    let mut proactor = kernel_proactor()?;
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
    let mut records: [Vec<Completion>; 3] = std::array::from_fn(|_| Vec::new());
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
                unsafe { prepare_read(sqe, read_fd, read_ptr.cast(), 1, 0) };
            })?;
            proactor.prepare_sqe_with(operation(id, payload + 0x8000), |sqe| {
                // SAFETY: Each write references an immutable stable byte.
                // Storage is retained on errors and freed only after shutdown
                // confirms that every submitted operation has retired.
                unsafe { prepare_write(sqe, write_fd, write_ptr.cast(), 1, 0) };
            })?;
        }
    }
    let started = Instant::now();
    while records.iter().any(|record| record.len() < OPERATIONS) {
        assert_before_deadline(started, "multi-subsystem pipe I/O");
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |completion: Completion, _: &mut SubmissionContext<'_>| {
                records[usize::from(completion.operation_id.subsystem_id().raw() - 1)]
                    .push(completion);
                Ok(())
            },
        )?;
    }
    for (subsystem, record) in records.iter().enumerate() {
        let completions = record;
        assert_eq!(completions.len(), OPERATIONS);
        let mut unique = HashSet::new();
        for completion in completions.iter() {
            assert_eq!(
                completion.operation_id.subsystem_id(),
                route(subsystem as u8 + 1)
            );
            assert_eq!(completion.result, 1);
            assert!(unique.insert(completion.operation_id.payload().raw()));
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
fn integration_lifecycle_scenario_fixed_read_cancellation_quarantines_until_target_cqe()
-> TestResult {
    const BUFFER_COUNT: u16 = 16;
    let (read_end, _writer_kept_open) = blocking_pipe()?;
    let mut proactor = kernel_proactor()?;
    let id = route(1);
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
                prepare_read_fixed(
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
            .ok_or("waiting token exists")?
            .quarantine()?;
        proactor.prepare_sqe_with(operation(id, 0x1000 + u64::from(sequence)), |sqe| {
            // SAFETY: Cancellation uses the exact read user_data, not its buffer
            // address; it does not grant access to the target's DMA storage.
            unsafe { prepare_cancel(sqe, operation(id, u64::from(sequence)).raw(), 0) };
        })?;
    }
    proactor.submit()?;
    assert_eq!(
        pool.available(),
        0,
        "even kernel-completed requests require CQE handoff"
    );
    assert!(matches!(
        pool.checkout(),
        Err(UringError::FixedBuffersExhausted)
    ));
    let mut completion_count = 0;
    let mut target_seen = [false; BUFFER_COUNT as usize];
    let mut control_seen = [false; BUFFER_COUNT as usize];
    let started = Instant::now();
    while target_seen.iter().any(|seen| !seen) || control_seen.iter().any(|seen| !seen) {
        assert_before_deadline(started, "fixed-buffer cancellation quarantine");
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |completion: Completion, _: &mut SubmissionContext<'_>| {
                completion_count += 1;
                let payload = completion.operation_id.payload().raw();
                assert_eq!(completion.flags & sys::IORING_CQE_F_MORE, 0);
                if payload < u64::from(BUFFER_COUNT) {
                    let index = payload as usize;
                    assert!(!target_seen[index]);
                    assert_eq!(completion.result, -libc::ECANCELED);
                    target_seen[index] = true;
                    let token = waiting[index]
                        .take()
                        .ok_or(UringError::InvalidConfig("target waiting buffer missing"))?;
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
            },
        )?;
    }
    assert_eq!(completion_count, usize::from(BUFFER_COUNT) * 2);
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

    use liburing::buffer_ring::BufferRing;

    const DATAGRAMS: u8 = 64;
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.connect(receiver.local_addr()?)?;
    receiver.set_nonblocking(true)?;
    let mut proactor = kernel_proactor()?;
    let id = route(1);
    let receive = operation(id, 0x100);
    let cancel = operation(id, 0x200);
    // SAFETY: The group is exclusively registered on this live ring. Successful
    // cleanup below drains the receive's final CQE before unregistration. During
    // failure unwinding ManuallyDrop retains the DMA allocations until process
    // exit, while the proactor first tears down its kernel ring.
    let mut buffers = ManuallyDrop::new(unsafe {
        BufferRing::new(proactor.ring_mut(), 2, 64, liburing::BufferGroupId(7))?
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
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |completion: Completion, _: &mut SubmissionContext<'_>| {
                assert_eq!(completion.operation_id, receive);
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
                    let lease =
                        unsafe { buffers.lease_from_cqe(completion.flags, completion.result)? };
                    let sequence = usize::from(lease[0]);
                    assert!(sequence < usize::from(DATAGRAMS));
                    assert_eq!(lease[1], lease[0] ^ 0xa5);
                    assert!(!seen[sequence], "datagram {sequence} was delivered twice");
                    seen[sequence] = true;
                    received += 1;
                    held.push(lease);
                }
                Ok(())
            },
        )?;
        if depleted {
            let unchanged = buffers.rearm_depleted_recvs(|_, _, _, _| {
                panic!("receive rearmed before a buffer lease was returned");
            })?;
            assert_eq!(unchanged, 0);
            let returned_before = buffers.returned_count();
            held.clear();
            assert_eq!(buffers.returned_count(), returned_before + 2);
            if received < usize::from(DATAGRAMS) {
                let rearmed = buffers.rearm_depleted_recvs(|fd, flags, operation_id, group| {
                    proactor.prepare_sqe_with(operation_id, |sqe| {
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
            unsafe { prepare_cancel(sqe, receive.raw(), 0) };
        })?;
        let mut target_final = false;
        let mut control_final = false;
        while !target_final || !control_final {
            assert_before_deadline(started, "provided-ring receive teardown");
            proactor.wait_completions(
                1,
                Some(Duration::from_millis(20)),
                &mut |completion: Completion, _: &mut SubmissionContext<'_>| {
                    if completion.operation_id == receive {
                        assert_eq!(completion.flags & sys::IORING_CQE_F_MORE, 0);
                        assert!([-libc::ECANCELED, -libc::ENOBUFS].contains(&completion.result));
                        assert!(!target_final);
                        target_final = true;
                    } else {
                        assert_eq!(completion.operation_id, cancel);
                        assert!([0, -libc::ENOENT, -libc::EALREADY].contains(&completion.result));
                        assert!(!control_final);
                        control_final = true;
                    }
                    Ok(())
                },
            )?;
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

unsafe fn prepare_write(
    sqe: *mut sys::RawSqe,
    fd: i32,
    bytes: *const libc::c_void,
    len: u32,
    offset: u64,
) {
    // SAFETY: Callers retain exclusive SQE storage and immutable bytes through final CQE.
    unsafe {
        *sqe = sys::RawSqe::from_entry(
            opcode::Write::new(types::Fd(fd), bytes.cast(), len)
                .offset(offset)
                .build(),
        );
    }
}
unsafe fn prepare_read(
    sqe: *mut sys::RawSqe,
    fd: i32,
    bytes: *mut libc::c_void,
    len: u32,
    offset: u64,
) {
    // SAFETY: Callers retain exclusive SQE storage and writable bytes through final CQE.
    unsafe {
        *sqe = sys::RawSqe::from_entry(
            opcode::Read::new(types::Fd(fd), bytes.cast(), len)
                .offset(offset)
                .build(),
        );
    }
}
unsafe fn prepare_read_fixed(
    sqe: *mut sys::RawSqe,
    fd: i32,
    bytes: *mut libc::c_void,
    len: u32,
    offset: u64,
    index: i32,
) {
    // SAFETY: Callers retain the registered destination and exclusive SQE through final CQE.
    unsafe {
        *sqe = sys::RawSqe::from_entry(
            opcode::ReadFixed::new(types::Fd(fd), bytes.cast(), len, index as u16)
                .offset(offset)
                .build(),
        );
    }
}
unsafe fn prepare_cancel(sqe: *mut sys::RawSqe, target: u64, flags: i32) {
    // SAFETY: Callers provide exclusive SQE storage; cancellation holds no DMA pointer.
    unsafe {
        *sqe = sys::RawSqe::from_entry(opcode::AsyncCancel::new(target).build());
        (*sqe).operation_flags = flags as u32;
    }
}

#[test]
fn lifecycle_stale_cancel_key_cannot_cancel_a_reused_caller_identity() -> TestResult {
    use std::io::Write;

    let (reader, writer) = blocking_pipe()?;
    let mut writer = std::fs::File::from(writer);
    let mut byte = Box::new([0_u8]);
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 2,
        staged_capacity: 2,
        operation_capacity: 1,
        ..ProactorConfig::default()
    })?;
    let identity = operation(route(1), 17);
    let pointer = byte.as_mut_ptr();
    let prepare = |sqe| {
        // SAFETY: The box and pipe precede the ring and remain valid until each
        // generation's final CQE. No byte is read while the kernel can write it.
        unsafe { prepare_read(sqe, reader.as_raw_fd(), pointer.cast(), 1, 0) };
    };
    proactor.prepare_sqe_with(identity, prepare)?;
    let old_key = proactor.operation_key(identity)?;
    proactor.submit()?;
    assert!(proactor.cancel_key(old_key)?);
    let mut canceled = false;
    let deadline = Instant::now() + SCENARIO_TIMEOUT;
    while !canceled && Instant::now() < deadline {
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |completion: Completion, _: &mut SubmissionContext<'_>| {
                assert_eq!(completion.operation_id, identity);
                assert_eq!(completion.result, -libc::ECANCELED);
                assert!(!canceled, "cancel target dispatched twice");
                canceled = true;
                Ok(())
            },
        )?;
    }
    assert!(canceled);
    assert_eq!(proactor.operation_count(), 0);
    proactor.prepare_sqe_with(identity, prepare)?;
    let current_key = proactor.operation_key(identity)?;
    assert_eq!(old_key.slot(), current_key.slot());
    assert_ne!(old_key.generation(), current_key.generation());
    proactor.submit()?;
    assert!(!proactor.cancel_key(old_key)?);
    assert_eq!(
        proactor.operation_state(identity)?,
        liburing::operation_slab::OperationState::InFlight
    );
    writer.write_all(&[0x5a])?;
    let mut received = false;
    while !received && Instant::now() < deadline {
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |completion: Completion, context: &mut SubmissionContext<'_>| {
                assert_eq!(completion.operation_id, identity);
                assert_eq!(completion.result, 1, "stale cancellation hit new DMA");
                assert!(!context.cancel_key(old_key)?);
                received = true;
                Ok(())
            },
        )?;
    }
    assert!(received);
    assert_eq!(*byte, [0x5a]);
    assert_eq!(proactor.operation_count(), 0);
    proactor.shutdown()?;
    Ok(())
}
