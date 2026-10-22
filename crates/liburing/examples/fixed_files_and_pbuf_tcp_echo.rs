//! Loopback TCP echo with growing fixed files and leased receive buffers.
//!
//! `with_group_recovery` below is an example helper composing the public
//! lease-return and depleted-receive APIs; it is not a library method.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io::{self, Read},
    mem::ManuallyDrop,
    net::{TcpListener, TcpStream},
    os::fd::AsRawFd,
    rc::Rc,
    time::{Duration, Instant},
};

use liburing::{
    BufGroupId, Completion, OpId, OpPayload, Proactor, SubmissionContext, SubsystemHandler,
    SubsystemId, UringFileSlot,
    fixed_buffers::FixedBufferPool,
    fixed_files::FixedFileTable,
    ops::net,
    pbuf_ring::{PbufLease, ProvidedBufRing},
};
use liburing_sys as sys;

type ExampleResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const RECEIVE: u64 = 1;
const SEND: u64 = 2;
const CANCEL: u64 = 3;
const CLOSE: u64 = 4;
const WAIT: Duration = Duration::from_millis(50);

struct Recorder {
    completions: Rc<RefCell<VecDeque<Completion>>>,
    receiving: Rc<Cell<bool>>,
}

impl SubsystemHandler for Recorder {
    fn on_completion(
        &mut self,
        completion: Completion,
        _: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        if completion.op_id == op(RECEIVE) && completion.flags & sys::IORING_CQE_F_MORE == 0 {
            self.receiving.set(false);
        }
        self.completions.borrow_mut().push_back(completion);
        Ok(())
    }
}

fn op(payload: u64) -> OpId {
    OpId::pack(
        SubsystemId::new_unchecked(1),
        OpPayload::new_unchecked(payload),
    )
}

fn next(
    proactor: &mut Proactor,
    completions: &RefCell<VecDeque<Completion>>,
    wanted: u64,
) -> ExampleResult<Completion> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut queue = completions.borrow_mut();
        if let Some(index) = queue.iter().position(|cqe| cqe.op_id == op(wanted)) {
            return queue
                .remove(index)
                .ok_or_else(|| io::Error::other("missing CQE").into());
        }
        drop(queue);
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "TCP echo CQE timed out").into());
        }
        proactor.wait_completions(1, Some(WAIT), |_, _| Ok(()))?;
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
    group: BufGroupId,
    receiving: &Cell<bool>,
) -> liburing::Result<()> {
    proactor.prepare_sqe_with(op(RECEIVE), |sqe| {
        // SAFETY: The accepted socket and registered group outlive the target's
        // final CQE. The kernel selects storage; user access occurs via leases.
        unsafe { net::prep_recv_multishot(sqe, fd, group, 0) };
    })?;
    receiving.set(true);
    Ok(())
}

fn with_group_recovery(
    group: &ProvidedBufRing,
    lease: PbufLease<'_>,
    proactor: &mut Proactor,
    receiving: &Cell<bool>,
) -> ExampleResult {
    let returned = group.returned_count();
    lease.release();
    assert_eq!(group.returned_count(), returned + 1);
    let rearmed = group.rearm_depleted_recvs(|fd, flags, id, group_id| {
        assert_eq!((flags, id), (0, op(RECEIVE)));
        stage_receive(proactor, fd, group_id, receiving)
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
    completions: &RefCell<VecDeque<Completion>>,
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
        proactor.prepare_sqe_with(op(SEND), |sqe| {
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
                sys::uring_shim_sqe_set_flags(sqe, sys::IOSQE_FIXED_FILE);
            }
        })?;
        let completion = next(proactor, completions, SEND)?;
        assert_eq!(completion.flags & sys::IORING_CQE_F_MORE, 0);
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
    let mut proactor = Proactor::builder()
        .entries(16)
        .enable_waker(false)
        .build()?;
    let completions = Rc::new(RefCell::new(VecDeque::new()));
    let receiving = Rc::new(Cell::new(false));
    proactor.register_subsystem(
        SubsystemId::new_unchecked(1),
        Recorder {
            completions: Rc::clone(&completions),
            receiving: Rc::clone(&receiving),
        },
    )?;
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
        ProvidedBufRing::new(proactor.ring_mut(), 1, 64, BufGroupId(1))?
    });
    let payload: Vec<u8> = (0..128).map(|index| b'a' + (index % 26) as u8).collect();
    stage_receive(
        &mut proactor,
        accepted.as_raw_fd(),
        group.group_id(),
        &receiving,
    )?;
    send_fixed(&mut proactor, &completions, &pool, client_slot, &payload)?;
    let mut received = Vec::new();
    let mut recoveries = 0;
    while received.len() < payload.len() {
        let completion = next(&mut proactor, &completions, RECEIVE)?;
        let length = check_result(completion)?;
        assert!(length > 0, "unexpected TCP EOF");
        // SAFETY: This genuine unconsumed CQE selects an in-bounds buffer from
        // this exact group. The lease exclusively owns its reported payload.
        let lease = unsafe { group.lease_from_cqe(completion.flags, completion.result)? };
        received.extend_from_slice(&lease);
        if received.len() < payload.len() {
            assert_ne!(completion.flags & sys::IORING_CQE_F_MORE, 0);
            // Keep the sole selected buffer leased until the terminal CQE;
            // returning it earlier could conceal the exhaustion being shown.
            let depleted = next(&mut proactor, &completions, RECEIVE)?;
            assert_eq!(depleted.result, -libc::ENOBUFS);
            assert_eq!(depleted.flags & sys::IORING_CQE_F_MORE, 0);
            group.mark_depleted_recv(accepted.as_raw_fd(), 0, op(RECEIVE))?;
            with_group_recovery(&group, lease, &mut proactor, &receiving)?;
            recoveries += 1;
        } else {
            lease.release();
        }
    }
    assert_eq!(received, payload);
    assert!(recoveries > 0);
    if receiving.get() {
        proactor.prepare_sqe_with(op(CANCEL), |sqe| {
            // SAFETY: This identifies the sole live receive. Its registered
            // storage remains alive through the target's own final CQE.
            unsafe { net::prep_cancel(sqe, op(RECEIVE), 0) };
        })?;
        let cancel = next(&mut proactor, &completions, CANCEL)?;
        assert!([0, -libc::ENOENT, -libc::EALREADY].contains(&cancel.result));
        let terminal = next(&mut proactor, &completions, RECEIVE)?;
        assert_eq!(terminal.flags & sys::IORING_CQE_F_MORE, 0);
        assert!([-libc::ECANCELED, -libc::ENOBUFS].contains(&terminal.result));
    }
    assert!(!receiving.get());
    group.forget_depleted_recv(op(RECEIVE))?;
    send_fixed(&mut proactor, &completions, &pool, accepted_slot, &received)?;
    let mut echoed = vec![0; payload.len()];
    client.read_exact(&mut echoed)?;
    assert_eq!(echoed, payload);
    println!(
        "Echoed {} exact TCP bytes using fixed-buffer writes and leased multishot reads",
        echoed.len()
    );
    proactor.prepare_sqe_with(op(CLOSE), |sqe| {
        // SAFETY: All accepted-socket I/O has delivered final CQEs. This slot
        // remains registered and is reclaimed only after its exact close CQE.
        unsafe { net::prep_close_direct(sqe, accepted_slot) };
    })?;
    let closed = next(&mut proactor, &completions, CLOSE)?;
    assert_eq!((closed.result, closed.flags), (0, 0));
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
