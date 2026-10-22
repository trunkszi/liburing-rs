//! Real-kernel resource lifecycle scenarios; no external service is substituted.

use std::{
    cell::Cell,
    fs::File,
    io::{self, Read},
    mem::{ManuallyDrop, MaybeUninit},
    net::{TcpListener, TcpStream, UdpSocket},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::FileExt, net::UnixStream},
    },
    rc::Rc,
    time::Duration,
};

use liburing::{
    ProactorConfig, UringError,
    fixed_buffers::FixedBufferPool,
    fixed_files::FixedFileTable,
    id::{BufGroupId, OpId, OpPayload, SubsystemId},
    ops::net,
    pbuf_ring::ProvidedBufRing,
    proactor::Proactor,
    subsystem::{Completion, SubmissionContext, SubsystemHandler},
};

struct KernelRing {
    ring: Box<liburing_sys::io_uring>,
}

struct Cqe {
    id: u64,
    result: i32,
    flags: u32,
}

impl KernelRing {
    fn new() -> io::Result<Self> {
        // SAFETY: io_uring and its parameters are C storage whose all-zero state
        // is valid as input to queue_init_params, which initializes the ring.
        let (mut ring, mut params) = unsafe {
            (
                Box::new(MaybeUninit::<liburing_sys::io_uring>::zeroed().assume_init()),
                MaybeUninit::<liburing_sys::io_uring_params>::zeroed().assume_init(),
            )
        };
        // SAFETY: Both pointers refer to writable, stable initialized storage;
        // no other owner accesses this ring during initialization.
        let result =
            unsafe { liburing_sys::uring_shim_queue_init_params(16, ring.as_mut(), &mut params) };
        check(result)?;
        Ok(Self { ring })
    }

    fn pointer(&mut self) -> *mut liburing_sys::io_uring {
        self.ring.as_mut()
    }

    fn sqe(&mut self, id: u64) -> *mut liburing_sys::io_uring_sqe {
        // SAFETY: This test is the sole thread and submission owner of the ring.
        let sqe = unsafe { liburing_sys::uring_shim_get_sqe(self.pointer()) };
        assert!(!sqe.is_null(), "test queue unexpectedly exhausted");
        // SAFETY: get_sqe returned an exclusively owned writable SQE; user_data
        // is copied by value and has no external pointer lifetime.
        unsafe { liburing_sys::uring_shim_sqe_set_data64(sqe, id) };
        sqe
    }

    fn submit(&mut self) -> io::Result<()> {
        // SAFETY: All prepared SQEs have their DMA storage retained by the test.
        check(unsafe { liburing_sys::uring_shim_submit(self.pointer()) })?;
        Ok(())
    }

    fn completion(&mut self) -> io::Result<Cqe> {
        let mut cqe = std::ptr::null_mut();
        let mut timeout = liburing_sys::__kernel_timespec {
            tv_sec: 3,
            tv_nsec: 0,
        };
        // SAFETY: The initialized ring is exclusively driven here, the output
        // pointer and relative timeout remain writable for the blocking call.
        check(unsafe {
            liburing_sys::uring_shim_wait_cqe_timeout(self.pointer(), &mut cqe, &mut timeout)
        })?;
        assert!(!cqe.is_null(), "successful wait returned no CQE");
        // SAFETY: Successful wait grants access to one live CQE until cqe_seen;
        // all observable fields are copied before returning it to the kernel.
        let result = unsafe {
            Cqe {
                id: liburing_sys::uring_shim_cqe_get_data64(cqe),
                result: (*cqe).res,
                flags: (*cqe).flags,
            }
        };
        // SAFETY: This is the single consumption of the CQE obtained above.
        unsafe { liburing_sys::uring_shim_cqe_seen(self.pointer(), cqe) };
        Ok(result)
    }
}

impl Drop for KernelRing {
    fn drop(&mut self) {
        // SAFETY: This is the unique initialized ring owner. Resource owners are
        // declared after the ring in each test and are dropped before queue exit.
        unsafe { liburing_sys::uring_shim_queue_exit(self.pointer()) };
    }
}

fn check(result: i32) -> io::Result<i32> {
    if result < 0 {
        Err(io::Error::from_raw_os_error(-result))
    } else {
        Ok(result)
    }
}

fn anonymous_file() -> io::Result<File> {
    // SAFETY: The constant name is NUL terminated; memfd_create retains no name
    // pointer and returns a newly owned descriptor on success.
    let fd = unsafe { libc::memfd_create(c"uring-fixed-resources".as_ptr(), libc::MFD_CLOEXEC) };
    check(fd)?;
    // SAFETY: The successful syscall returned unique descriptor ownership.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[test]
fn integration_lifecycle_fixed_file_read_write_and_direct_close()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ring = KernelRing::new()?;
    let file = anonymous_file()?;
    // SAFETY: The boxed ring remains at a stable address and outlives both
    // registration owners; the test exclusively manages its registrations.
    let mut files = unsafe { FixedFileTable::new(ring.pointer(), 1)? };
    // SAFETY: No competing fixed-buffer registration exists, and all operations
    // below deliver final CQEs before this pool and its boxed ring are dropped.
    let mut buffers = unsafe { FixedBufferPool::new(ring.pointer(), 1, 64)? };
    let slot = files.insert(file.as_raw_fd())?;
    let mut bytes = buffers.checkout()?;
    let payload = b"registered file and buffer payload";
    bytes.as_mut_slice()[..payload.len()].copy_from_slice(payload);
    let id = bytes.id();
    let address = bytes.as_mut_ptr();
    let waiting = bytes.into_in_flight();
    let sqe = ring.sqe(1);
    // SAFETY: Slot is registered and its index fits i32. The retained waiting
    // token owns the stable registered bytes until this write's final CQE.
    unsafe {
        net::prep_write_fixed(sqe, slot.raw() as i32, address, payload.len() as u32, 0, id);
        liburing_sys::uring_shim_sqe_set_flags(sqe, 1_u32 << liburing_sys::IOSQE_FIXED_FILE_BIT);
    }
    ring.submit()?;
    let cqe = ring.completion()?;
    assert_eq!((cqe.id, cqe.result), (1, payload.len() as i32));
    assert_eq!(cqe.flags & liburing_sys::IORING_CQE_F_MORE, 0);
    // SAFETY: The write's own final CQE above proves the kernel released bytes.
    let mut bytes = unsafe { waiting.complete()? };
    bytes.as_mut_slice().fill(0);
    let address = bytes.as_mut_ptr();
    let waiting = bytes.into_in_flight();
    let sqe = ring.sqe(2);
    // SAFETY: The slot remains registered and the waiting token retains an
    // exclusive writable registered allocation through the read final CQE.
    unsafe {
        net::prep_read_fixed(sqe, slot.raw() as i32, address, payload.len() as u32, 0, id);
        liburing_sys::uring_shim_sqe_set_flags(sqe, 1_u32 << liburing_sys::IOSQE_FIXED_FILE_BIT);
    }
    ring.submit()?;
    let cqe = ring.completion()?;
    assert_eq!((cqe.id, cqe.result), (2, payload.len() as i32));
    assert_eq!(cqe.flags & liburing_sys::IORING_CQE_F_MORE, 0);
    // SAFETY: The read's own final CQE proves exclusive user-space access.
    let bytes = unsafe { waiting.complete()? };
    assert_eq!(&bytes.as_slice()[..payload.len()], payload);
    drop(bytes);
    let sqe = ring.sqe(3);
    // SAFETY: Both prior slot operations completed; this SQE uniquely closes its
    // registered reference while File retains ownership of the original fd.
    unsafe { net::prep_close_direct(sqe, slot) };
    ring.submit()?;
    let cqe = ring.completion()?;
    assert_eq!((cqe.id, cqe.result), (3, 0));
    // SAFETY: The successful direct-close CQE is for exactly this occupied slot,
    // and every earlier operation referring to it has retired above.
    unsafe { files.reclaim_direct_close(slot)? };
    assert_eq!(files.available(), 1);
    let mut actual = vec![0; payload.len()];
    assert_eq!(file.read_at(&mut actual, 0)?, payload.len());
    assert_eq!(actual, payload);
    assert_eq!(files.insert(file.as_raw_fd())?, slot);
    files.remove(slot)?;
    buffers.unregister()?;
    files.unregister()?;
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_cancel_retains_dma_until_target_final_cqe()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ring = KernelRing::new()?;
    let (reader, _writer) = UnixStream::pair()?;
    // SAFETY: The ring is stable and outlives the pool and tokens; no other
    // buffer registration exists, and the target is drained before teardown.
    let mut pool = unsafe { FixedBufferPool::new(ring.pointer(), 1, 64)? };
    let mut bytes = pool.checkout()?;
    let id = bytes.id();
    let address = bytes.as_mut_ptr();
    let mut waiting = bytes.into_in_flight();
    let generation = waiting.generation();
    let sqe = ring.sqe(11);
    // SAFETY: The registered buffer is exclusively retained by waiting; the
    // socket is kept open and empty to leave this read pending until cancellation.
    unsafe { net::prep_read_fixed(sqe, reader.as_raw_fd(), address, 64, 0, id) };
    ring.submit()?;
    waiting.quarantine()?;
    assert!(pool.checkout().is_err());
    assert!(pool.unregister().is_err());
    let sqe = ring.sqe(12);
    // SAFETY: User data 11 uniquely names the pending read. Its buffer remains
    // retained across both the cancel CQE and the target's final CQE.
    unsafe { net::prep_cancel(sqe, OpId::from_raw(11), 0) };
    ring.submit()?;
    let mut target_final = false;
    let mut cancel_completed = false;
    for _ in 0..2 {
        let cqe = ring.completion()?;
        assert!(
            pool.checkout().is_err(),
            "CQE receipt alone must not recycle DMA"
        );
        assert_eq!(pool.available(), 0);
        match cqe.id {
            11 => {
                assert!(!target_final, "duplicate target completion");
                assert_eq!(cqe.result, -libc::ECANCELED);
                assert_eq!(cqe.flags & liburing_sys::IORING_CQE_F_MORE, 0);
                target_final = true;
            }
            12 => {
                assert!(!cancel_completed, "duplicate cancellation completion");
                assert_eq!(cqe.result, 0);
                cancel_completed = true;
            }
            id => panic!("unexpected completion user_data {id}"),
        }
    }
    assert!(target_final && cancel_completed);
    // SAFETY: Both CQEs were observed, including the original read's final
    // -ECANCELED CQE; no notification or further DMA can follow this read.
    unsafe { pool.reclaim_completed_generation(id, generation)? };
    let bytes = pool.checkout()?;
    assert_eq!(bytes.id(), id);
    drop(waiting);
    assert_eq!(
        pool.available(),
        0,
        "stale token must not free a new checkout"
    );
    drop(bytes);
    assert_eq!(pool.available(), 1);
    pool.unregister()?;
    Ok(())
}

#[test]
fn unit_scenario_multishot_preparation_preserves_existing_flags() {
    // SAFETY: SQEs are plain C storage; this one is never submitted to a kernel.
    let mut sqe: liburing_sys::io_uring_sqe = unsafe { std::mem::zeroed() };
    let original =
        liburing_sys::IOSQE_FIXED_FILE | liburing_sys::IOSQE_IO_LINK | liburing_sys::IOSQE_ASYNC;
    sqe.flags = original as u8;
    // SAFETY: The writable SQE is private and never submitted, so no descriptor
    // or group is accessed by the kernel during this preparation-only test.
    unsafe { net::prep_recv_multishot(&mut sqe, 0, BufGroupId(9), 0) };
    assert_eq!(
        u32::from(sqe.flags),
        original | liburing_sys::IOSQE_BUFFER_SELECT
    );
}

struct ShutdownAcceptHandler {
    calls: Rc<Cell<usize>>,
    blocked: Rc<Cell<bool>>,
}

impl SubsystemHandler for ShutdownAcceptHandler {
    fn on_completion(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        assert!(
            completion.result >= 0,
            "accept must complete before shutdown"
        );
        // SAFETY: This accept CQE transfers unique ownership of its returned fd.
        let accepted = unsafe { TcpStream::from_raw_fd(completion.result) };
        drop(accepted);
        self.calls.set(self.calls.get() + 1);
        assert_eq!(submissions.remaining_capacity(), 0);
        let prepared = Cell::new(false);
        let result = submissions.prepare_sqe_with(completion.op_id, |_| prepared.set(true));
        assert_eq!(result, Err(UringError::SqRingFull));
        self.blocked.set(!prepared.get());
        Ok(())
    }
}

#[test]
fn integration_lifecycle_shutdown_delivers_accepted_fd_and_blocks_followups()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 8,
        enable_optimizations: false,
        enable_waker: false,
        ..ProactorConfig::default()
    })?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(Duration::from_secs(2)))?;
    let calls = Rc::new(Cell::new(0));
    let blocked = Rc::new(Cell::new(false));
    let subsystem = SubsystemId::new_unchecked(37);
    proactor.register_subsystem(
        subsystem,
        ShutdownAcceptHandler {
            calls: Rc::clone(&calls),
            blocked: Rc::clone(&blocked),
        },
    )?;
    let id = OpId::pack(subsystem, OpPayload::new_unchecked(1));
    proactor.prepare_sqe_with(id, |sqe| {
        // SAFETY: The listener outlives shutdown; null address outputs are legal
        // for accept and the handler takes ownership of every successful result.
        unsafe {
            net::prep_accept(
                sqe,
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
    })?;
    proactor.submit()?;
    // SAFETY: The initialized ring is exclusively owned; reading its descriptor
    // does not submit or consume operations or change proactor accounting.
    let fd = unsafe { (*proactor.ring_mut()).ring_fd };
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll borrows one initialized descriptor record. This bounded wait
    // is test-only and guarantees an accept CQE is ready before shutdown starts.
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 2000) }, 1);
    proactor.shutdown()?;
    assert_eq!(calls.get(), 1);
    assert!(blocked.get());
    assert_eq!(
        client.read(&mut [0_u8; 1])?,
        0,
        "accepted socket must close"
    );
    proactor.shutdown()?;
    assert_eq!(calls.get(), 1, "shutdown must not redeliver a completion");
    Ok(())
}

#[test]
fn integration_scenario_oversized_selected_completion_republishes_buffer()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ring = KernelRing::new()?;
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.connect(receiver.local_addr()?)?;
    // SAFETY: This stable ring exclusively owns group 9. ManuallyDrop retains
    // storage on early failure; successful teardown follows both final CQEs.
    let mut group =
        ManuallyDrop::new(unsafe { ProvidedBufRing::new(ring.pointer(), 1, 8, BufGroupId(9))? });
    for (id, payload) in [(41, b"one".as_slice()), (42, b"two".as_slice())] {
        sender.send(payload)?;
        let sqe = ring.sqe(id);
        // SAFETY: The live socket and registered group outlive this one-shot
        // receive. BUFFER_SELECT makes the null user buffer pointer unused.
        unsafe {
            liburing_sys::uring_shim_prep_recv(
                sqe,
                receiver.as_raw_fd(),
                std::ptr::null_mut(),
                8,
                0,
            );
            liburing_sys::uring_shim_sqe_set_flags(sqe, liburing_sys::IOSQE_BUFFER_SELECT);
            liburing_sys::uring_shim_sqe_set_buf_group(sqe, 9);
        }
        ring.submit()?;
        let cqe = ring.completion()?;
        assert_eq!((cqe.id, cqe.result), (id, 3));
        assert_eq!(cqe.flags & liburing_sys::IORING_CQE_F_BUF_MORE, 0);
        if id == 41 {
            // SAFETY: This genuine CQE transfers exclusive ownership of the
            // selected buffer. Only its reported size is fault-injected; the
            // defensive branch must reject it without accessing that range.
            let result = unsafe { group.lease_from_cqe(cqe.flags, 9) };
            assert!(matches!(result, Err(UringError::InvalidConfig(_))));
            assert_eq!(group.returned_count(), 1);
        } else {
            // SAFETY: This unconsumed final CQE grants exclusive ownership of
            // the republished buffer; its real payload fits the allocation.
            let lease = unsafe { group.lease_from_cqe(cqe.flags, cqe.result)? };
            assert_eq!(&*lease, payload);
            lease.release();
        }
    }
    // SAFETY: Both one-shot receives delivered final CQEs and no lease remains.
    unsafe {
        group.unregister()?;
        ManuallyDrop::drop(&mut group);
    }
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_pbuf_leases_replenish_after_enobufs()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ring = KernelRing::new()?;
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.connect(receiver.local_addr()?)?;
    // On an early error or assertion panic the registration is deliberately
    // retained: the ring exits before retained storage could be freed while a
    // multishot receive still owns it. Successful teardown explicitly drops it.
    // SAFETY: The test owns the stable ring and this unique group. The owner is
    // dropped only after every receive final CQE and lease return below.
    let mut group =
        ManuallyDrop::new(unsafe { ProvidedBufRing::new(ring.pointer(), 2, 128, BufGroupId(7))? });
    let sqe = ring.sqe(21);
    // SAFETY: The group is registered and all descriptors were published at
    // creation. Group and socket remain alive through the multishot final CQE.
    unsafe { net::prep_recv_multishot(sqe, receiver.as_raw_fd(), group.group_id(), 0) };
    ring.submit()?;
    sender.send(b"first")?;
    let cqe = ring.completion()?;
    assert_eq!((cqe.id, cqe.result), (21, 5));
    assert_ne!(cqe.flags & liburing_sys::IORING_CQE_F_MORE, 0);
    // SAFETY: This genuine CQE selects this group exactly once and does not use
    // incremental buffers, so its selected payload is exclusively user-owned.
    let first = unsafe { group.lease_from_cqe(cqe.flags, cqe.result)? };
    assert_eq!(&*first, b"first");
    sender.send(b"second")?;
    let cqe = ring.completion()?;
    assert_eq!((cqe.id, cqe.result), (21, 6));
    assert_ne!(cqe.flags & liburing_sys::IORING_CQE_F_MORE, 0);
    // SAFETY: The second unconsumed CQE selects a different, exclusively owned
    // group buffer; the first lease remains alive and cannot be reselected.
    let second = unsafe { group.lease_from_cqe(cqe.flags, cqe.result)? };
    assert_eq!(&*second, b"second");
    assert_ne!(first.buffer_id(), second.buffer_id());
    sender.send(b"after-pressure")?;
    let cqe = ring.completion()?;
    assert_eq!((cqe.id, cqe.result), (21, -libc::ENOBUFS));
    assert_eq!(cqe.flags & liburing_sys::IORING_CQE_F_MORE, 0);
    assert_eq!(group.returned_count(), 0);
    group.mark_depleted_recv(receiver.as_raw_fd(), 0, OpId::from_raw(21))?;
    assert_eq!(
        group.rearm_depleted_recvs(|_, _, _, _| panic!("buffers remain exhausted"))?,
        0
    );
    drop(first);
    assert_eq!(group.returned_count(), 1);
    second.release();
    assert_eq!(group.returned_count(), 2);
    assert!(
        group
            .rearm_depleted_recvs(|_, _, _, _| {
                Err(liburing::UringError::InvalidConfig("submission queue full"))
            })
            .is_err()
    );
    assert_eq!(
        group.rearm_depleted_recvs(|fd, flags, op_id, buffer_group| {
            assert_eq!(fd, receiver.as_raw_fd());
            assert_eq!(flags, 0);
            assert_eq!(op_id, OpId::from_raw(21));
            assert_eq!(buffer_group, group.group_id());
            let sqe = ring.sqe(op_id.raw());
            // SAFETY: Replenishment republished both buffers, the previous
            // receive ended with ENOBUFS, and the callback retains its original
            // live descriptor, user data, flags, and registered group.
            unsafe { net::prep_recv_multishot(sqe, fd, buffer_group, flags) };
            Ok(())
        })?,
        1
    );
    assert_eq!(
        group.rearm_depleted_recvs(|_, _, _, _| panic!("already rearmed"))?,
        0
    );
    ring.submit()?;
    let cqe = ring.completion()?;
    assert_eq!((cqe.id, cqe.result), (21, 14));
    assert_ne!(cqe.flags & liburing_sys::IORING_CQE_F_MORE, 0);
    // SAFETY: The CQE belongs to the new group-select receive and has not been
    // leased before; its selected buffer is exclusively handed to user space.
    let recovered = unsafe { group.lease_from_cqe(cqe.flags, cqe.result)? };
    assert_eq!(&*recovered, b"after-pressure");
    recovered.release();
    // Harvest a whole exhausted batch first. Its data buffers can be returned
    // before the owner dispatches the already queued terminal ENOBUFS CQE.
    for payload in [b"early-one".as_slice(), b"early-two", b"early-after"] {
        sender.send(payload)?;
    }
    let batch = [ring.completion()?, ring.completion()?, ring.completion()?];
    for (cqe, payload) in batch[..2].iter().zip([b"early-one", b"early-two"]) {
        assert_eq!((cqe.id, cqe.result), (21, payload.len() as i32));
        // SAFETY: Each genuine, unconsumed selected-buffer CQE transfers a
        // distinct buffer; this receive uses no incremental-buffer mode.
        let lease = unsafe { group.lease_from_cqe(cqe.flags, cqe.result)? };
        assert_eq!(&*lease, payload);
        lease.release();
    }
    assert_eq!((batch[2].id, batch[2].result), (21, -libc::ENOBUFS));
    assert_eq!(batch[2].flags & liburing_sys::IORING_CQE_F_MORE, 0);
    let returned_before_mark = group.returned_count();
    group.mark_depleted_recv(receiver.as_raw_fd(), 0, OpId::from_raw(21))?;
    assert_eq!(
        group.rearm_depleted_recvs(|fd, flags, op_id, buffer_group| {
            let sqe = ring.sqe(op_id.raw());
            // SAFETY: The prior multishot ended, its buffers were returned
            // before depletion dispatch, and the live group owns their storage.
            unsafe { net::prep_recv_multishot(sqe, fd, buffer_group, flags) };
            Ok(())
        })?,
        1,
        "already returned buffers must allow recovery without another lease drop"
    );
    assert_eq!(group.returned_count(), returned_before_mark);
    ring.submit()?;
    let cqe = ring.completion()?;
    assert_eq!((cqe.id, cqe.result), (21, 11));
    // SAFETY: This unconsumed CQE grants exclusive access to a selected buffer
    // of the rearmed receive, whose registration remains live below.
    let lease = unsafe { group.lease_from_cqe(cqe.flags, cqe.result)? };
    assert_eq!(&*lease, b"early-after");
    lease.release();
    let sqe = ring.sqe(23);
    // SAFETY: User data 21 uniquely identifies the still-live multishot receive;
    // the group remains registered through the following final completion.
    unsafe { net::prep_cancel(sqe, OpId::from_raw(21), 0) };
    ring.submit()?;
    let mut target_final = false;
    let mut cancel_completed = false;
    for _ in 0..2 {
        let cqe = ring.completion()?;
        match cqe.id {
            21 => {
                assert_eq!(cqe.result, -libc::ECANCELED);
                assert_eq!(cqe.flags & liburing_sys::IORING_CQE_F_MORE, 0);
                target_final = true;
            }
            23 => {
                assert_eq!(cqe.result, 0);
                cancel_completed = true;
            }
            id => panic!("unexpected completion user_data {id}"),
        }
    }
    assert!(target_final && cancel_completed);
    // SAFETY: The only operation selecting this group has delivered its final
    // CQE and all three payload leases have been released.
    unsafe { group.unregister()? };
    // SAFETY: Successful unregistration follows the target final CQE and every
    // lease return; this is the sole destruction of the retained group owner.
    unsafe { ManuallyDrop::drop(&mut group) };
    Ok(())
}

#[test]
fn integration_lifecycle_scenario_fixed_file_boundaries_preserve_free_slots()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ring = KernelRing::new()?;
    let file = anonymous_file()?;
    let raw = file.as_raw_fd();
    // SAFETY: The stable ring outlives the table, this test exclusively owns
    // registration, and the dense input contains a valid fd plus empty slots.
    let mut files = unsafe { FixedFileTable::register(ring.pointer(), &[-1, raw, -1])? };
    assert_eq!((files.len(), files.available()), (1, 2));
    assert!(files.insert(i32::MAX).is_err());
    assert!(files.insert(-2).is_err());
    assert_eq!((files.len(), files.available()), (1, 2));
    for index in [3, u32::MAX] {
        let slot = liburing::UringFileSlot(index);
        assert_eq!(files.get(slot), None);
        assert!(matches!(
            files.remove(slot),
            Err(liburing::UringError::InvalidFileSlot(_))
        ));
    }
    assert_eq!(files.insert(raw)?, liburing::UringFileSlot(0));
    assert_eq!(files.insert(raw)?, liburing::UringFileSlot(2));
    assert!(matches!(
        files.insert(raw),
        Err(liburing::UringError::FixedFileSlotsExhausted)
    ));
    let middle = liburing::UringFileSlot(1);
    assert_eq!(files.remove(middle)?, raw);
    assert!(matches!(
        files.remove(middle),
        Err(liburing::UringError::InvalidFileSlot(1))
    ));
    assert_eq!(files.available(), 1);
    assert_eq!(files.insert(raw)?, middle);
    files.unregister()?;
    files.unregister()?;
    assert!(files.insert(raw).is_err());
    assert!(files.remove(middle).is_err());
    assert_eq!((files.len(), files.available()), (0, 0));
    Ok(())
}
