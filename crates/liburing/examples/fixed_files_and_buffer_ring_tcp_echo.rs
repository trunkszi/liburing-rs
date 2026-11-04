//! Loopback TCP echo with growing fixed files and leased receive buffers.
//!
//! `with_group_recovery` below is an example helper composing the public
//! lease-return and depleted-receive APIs; it is not a library method.

use std::{
    collections::VecDeque,
    io::{self, Read},
    mem::ManuallyDrop,
    net::{TcpListener, TcpStream},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use liburing::{
    BufferGroupId, Completion, CompletionDispatcher, OperationId, OperationPayload, Proactor,
    SubmissionContext, SubsystemId, UringFileSlot, backend as sys,
    buffer_ring::{BufferLease, BufferRing},
    fixed_buffers::FixedBufferPool,
    fixed_files::FixedFileTable,
    ops::net,
};

type ExampleResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const RECEIVE: u64 = 1;
const SEND: u64 = 2;
const CLOSE: u64 = 4;
const WAIT: Duration = Duration::from_millis(50);

struct Recorder {
    completions: VecDeque<Completion>,
    receiving: bool,
}

impl CompletionDispatcher for Recorder {
    fn dispatch(
        &mut self,
        completion: Completion,
        _: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        if completion.operation_id == operation(RECEIVE)
            && completion.flags & sys::IORING_CQE_F_MORE == 0
        {
            self.receiving = false;
        }
        self.completions.push_back(completion);
        Ok(())
    }
}

fn operation(payload: u64) -> OperationId {
    OperationId::pack(
        SubsystemId::new_unchecked(1),
        OperationPayload::new_unchecked(payload),
    )
}

fn next(
    proactor: &mut Proactor,
    recorder: &mut Recorder,
    wanted: u64,
) -> ExampleResult<Completion> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(index) = recorder
            .completions
            .iter()
            .position(|cqe| cqe.operation_id == operation(wanted))
        {
            return recorder
                .completions
                .remove(index)
                .ok_or_else(|| io::Error::other("missing CQE").into());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "TCP echo CQE timed out").into());
        }
        proactor.wait_completions(1, Some(WAIT), recorder)?;
    }
}

fn check_result(completion: Completion) -> ExampleResult<usize> {
    if completion.result < 0 {
        return Err(io::Error::from_raw_os_error(-completion.result).into());
    }
    Ok(completion.result as usize)
}

fn stage_receive(
    proactor: &mut Proactor,
    fd: i32,
    group: BufferGroupId,
    recorder: &mut Recorder,
) -> liburing::Result<()> {
    proactor.prepare_sqe_with(operation(RECEIVE), |sqe| {
        // SAFETY: The accepted socket and registered group outlive the target's
        // final CQE. The kernel selects storage; user access occurs via leases.
        unsafe { net::prep_recv_multishot(sqe, fd, group, 0) };
    })?;
    recorder.receiving = true;
    Ok(())
}

fn with_group_recovery(
    group: &BufferRing,
    lease: BufferLease<'_>,
    proactor: &mut Proactor,
    recorder: &mut Recorder,
) -> ExampleResult {
    let returned = group.returned_count();
    lease.release();
    assert_eq!(group.returned_count(), returned + 1);
    let rearmed = group.rearm_depleted_recvs(|fd, flags, id, group_id| {
        assert_eq!((flags, id), (0, operation(RECEIVE)));
        stage_receive(proactor, fd, group_id, recorder)
    })?;
    assert_eq!(
        rearmed, 1,
        "one returned lease restarts one depleted receive"
    );
    println!("Returned one receive lease and automatically rearmed the depleted TCP receive");
    Ok(())
}

fn send_fixed(
    proactor: &mut Proactor,
    recorder: &mut Recorder,
    pool: &FixedBufferPool,
    slot: UringFileSlot,
    bytes: &[u8],
) -> ExampleResult {
    let mut buffer = pool.checkout()?;
    buffer.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
    let mut offset = 0;
    while offset < bytes.len() {
        let address = buffer.as_ptr();
        let buffer_id = buffer.id();
        let waiting = buffer.into_in_flight();
        proactor.prepare_sqe_with(operation(SEND), |sqe| {
            // SAFETY: This live fixed-file slot references a connected TCP
            // socket. The in-flight token retains these registered immutable
            // bytes through the write's final CQE, with no zero-copy extension.
            unsafe {
                net::prep_write_fixed(
                    sqe,
                    slot.raw() as i32,
                    address.add(offset),
                    (bytes.len() - offset) as u32,
                    0,
                    buffer_id,
                );
                (*sqe).flags = sys::IOSQE_FIXED_FILE as u8;
            }
        })?;
        let completion = next(proactor, recorder, SEND)?;
        if completion.flags & sys::IORING_CQE_F_MORE != 0 {
            return Err(
                io::Error::other(format!("non-final fixed write CQE: {completion:?}")).into(),
            );
        }
        // SAFETY: This exact write's final CQE ends all kernel reads of its
        // registered allocation, including when the write reports an error.
        buffer = unsafe { waiting.complete()? };
        let written = check_result(completion)?;
        if written == 0 {
            return Err(
                io::Error::new(io::ErrorKind::WriteZero, "TCP write made no progress").into(),
            );
        }
        offset += written;
    }
    Ok(())
}

fn main() -> ExampleResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    let (accepted, _) = listener.accept()?;
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    accepted.set_nonblocking(true)?;
    // Socket owners precede the proactor so their descriptors also survive
    // ring teardown if an operation fails and the example returns early.
    let mut proactor = Proactor::builder().entries(16).build()?;
    let mut recorder = Recorder {
        completions: VecDeque::new(),
        receiving: false,
    };
    // SAFETY: This thread owns the live, stable ring, and exclusively registers
    // its fixed-file table. Explicit cleanup below precedes successful shutdown.
    let mut files = ManuallyDrop::new(unsafe { FixedFileTable::new(proactor.ring_mut(), 1)? });
    let listener_slot = files.insert(listener.as_raw_fd())?;
    let client_slot = files.insert(client.as_raw_fd())?;
    assert_eq!(files.capacity(), 2);
    files.grow(4)?;
    let accepted_slot = files.insert(accepted.as_raw_fd())?;
    assert_eq!(files.get(listener_slot), Some(listener.as_raw_fd()));
    assert_eq!(files.get(client_slot), Some(client.as_raw_fd()));
    println!(
        "Registered listener, client and accepted TCP socket; fixed-file capacity grew 1 -> 2 -> 4"
    );
    // SAFETY: This is the ring's sole fixed-buffer registration. In-flight
    // handles retain allocation storage until their own target final CQEs.
    let mut pool = ManuallyDrop::new(unsafe { FixedBufferPool::new(proactor.ring_mut(), 1, 256)? });
    // SAFETY: Group 1 is exclusively owned here. One 64-byte buffer forces real
    // depletion while receiving the 128-byte stream. ManuallyDrop quarantines
    // registered memory on every early return/unwind until ring teardown.
    let mut group = ManuallyDrop::new(unsafe {
        BufferRing::new(proactor.ring_mut(), 1, 64, BufferGroupId(1))?
    });
    let payload: Vec<u8> = (0..128).map(|index| b'a' + (index % 26) as u8).collect();
    stage_receive(
        &mut proactor,
        accepted.as_raw_fd(),
        group.group_id(),
        &mut recorder,
    )?;
    send_fixed(&mut proactor, &mut recorder, &pool, client_slot, &payload)?;
    let mut received = Vec::new();
    let mut recoveries = 0;
    while received.len() < payload.len() {
        let completion = next(&mut proactor, &mut recorder, RECEIVE)?;
        let length = check_result(completion)?;
        if length == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected TCP EOF").into());
        }
        // SAFETY: This genuine unconsumed CQE selects an in-bounds buffer from
        // this exact group. The lease exclusively owns its reported payload.
        let lease = unsafe { group.lease_from_cqe(completion.flags, completion.result)? };
        received.extend_from_slice(&lease);
        if received.len() < payload.len() {
            if completion.flags & sys::IORING_CQE_F_MORE == 0 {
                return Err(io::Error::other(format!(
                    "receive ended before payload: {completion:?}"
                ))
                .into());
            }
            // Keep the sole selected buffer leased until the terminal CQE;
            // returning it earlier could conceal the exhaustion being shown.
            let depleted = next(&mut proactor, &mut recorder, RECEIVE)?;
            if depleted.result != -libc::ENOBUFS || depleted.flags & sys::IORING_CQE_F_MORE != 0 {
                return Err(io::Error::other(format!(
                    "expected terminal ENOBUFS CQE: {depleted:?}"
                ))
                .into());
            }
            group.mark_depleted_recv(accepted.as_raw_fd(), 0, operation(RECEIVE))?;
            with_group_recovery(&group, lease, &mut proactor, &mut recorder)?;
            recoveries += 1;
        } else {
            lease.release();
        }
    }
    assert_eq!(received, payload);
    assert!(recoveries > 0);
    if recorder.receiving {
        proactor.cancel(operation(RECEIVE))?;
        let terminal = next(&mut proactor, &mut recorder, RECEIVE)?;
        if terminal.flags & sys::IORING_CQE_F_MORE != 0
            || ![-libc::ECANCELED, -libc::ENOBUFS].contains(&terminal.result)
        {
            return Err(io::Error::other(format!(
                "unexpected receive retirement CQE: {terminal:?}"
            ))
            .into());
        }
    }
    assert!(!recorder.receiving);
    group.forget_depleted_recv(operation(RECEIVE))?;
    send_fixed(
        &mut proactor,
        &mut recorder,
        &pool,
        accepted_slot,
        &received,
    )?;
    let mut echoed = vec![0; payload.len()];
    client.read_exact(&mut echoed)?;
    assert_eq!(echoed, payload);
    println!(
        "Echoed {} exact TCP bytes using fixed-buffer writes and leased multishot reads",
        echoed.len()
    );
    proactor.prepare_sqe_with(operation(CLOSE), |sqe| {
        // SAFETY: All accepted-socket I/O has delivered final CQEs. This slot
        // remains registered and is reclaimed only after its exact close CQE.
        unsafe { net::prep_close_direct(sqe, accepted_slot) };
    })?;
    let closed = next(&mut proactor, &mut recorder, CLOSE)?;
    if closed.result != 0 || closed.flags != 0 {
        return Err(io::Error::other(format!("CLOSE_DIRECT failed: {closed:?}")).into());
    }
    // SAFETY: This exact direct-close target succeeded finally, with no pending
    // I/O or future SQEs referencing the accepted socket's fixed-file slot.
    let reclaimed_fd = unsafe { files.reclaim_direct_close(accepted_slot)? };
    assert_eq!(reclaimed_fd, accepted.as_raw_fd());
    println!("CLOSE_DIRECT completed and its fixed-file slot was reclaimed");
    // SAFETY: The receive target is final, all leases ended, and all fixed
    // writes completed. Unregister and destroy each owner before ring shutdown.
    unsafe {
        group.unregister()?;
        ManuallyDrop::drop(&mut group);
    }
    pool.unregister()?;
    files.unregister()?;
    // SAFETY: Both registrations are inactive and this is their sole drop.
    unsafe {
        ManuallyDrop::drop(&mut pool);
        ManuallyDrop::drop(&mut files);
    }
    proactor.shutdown()?;
    println!("All registrations released; proactor shut down cleanly");
    Ok(())
}
