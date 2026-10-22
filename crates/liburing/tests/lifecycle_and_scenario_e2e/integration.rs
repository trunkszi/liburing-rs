//! Component composition against one real kernel ring, without fallback paths.

use std::{
    cell::RefCell,
    fs::File,
    io::{self, Write},
    mem::ManuallyDrop,
    net::UdpSocket,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::FileExt, net::UnixStream},
    },
    rc::Rc,
    time::{Duration, Instant},
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

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

fn proactor() -> liburing::Result<(Proactor, Rc<RefCell<Vec<Completion>>>)> {
    let mut proactor = Proactor::new(ProactorConfig {
        entries: 16,
        max_cqe_batch: 1,
        enable_optimizations: false,
        enable_waker: false,
        ..ProactorConfig::default()
    })?;
    let completions = Rc::new(RefCell::new(Vec::new()));
    proactor.register_subsystem(
        SubsystemId::new_unchecked(70),
        Recorder(Rc::clone(&completions)),
    )?;
    Ok((proactor, completions))
}

fn op(payload: u64) -> OpId {
    OpId::pack(
        SubsystemId::new_unchecked(70),
        OpPayload::new_unchecked(payload),
    )
}

fn next(
    proactor: &mut Proactor,
    completions: &RefCell<Vec<Completion>>,
) -> Result<Completion, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if !completions.borrow().is_empty() {
            return Ok(completions.borrow_mut().remove(0));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "component CQE timed out").into());
        }
        proactor.wait_completions(1, Some(Duration::from_millis(50)), |_, _| Ok(()))?;
    }
}

fn file() -> io::Result<File> {
    // SAFETY: This constant C string is readable for the syscall, which retains
    // no pointer and returns a newly owned descriptor on success.
    let fd = unsafe { libc::memfd_create(c"uring-component".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned this unique, live descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[test]
fn proactor_composes_growing_fixed_files_fixed_buffers_and_selected_udp() -> TestResult {
    let _serial = crate::kernel_test_lock();
    let (mut proactor, completions) = proactor()?;
    let original = file()?;
    let replacement = file()?;
    original.write_all_at(b"original", 0)?;
    replacement.write_all_at(b"second!!", 0)?;
    // SAFETY: The boxed ring address stays stable, outlives both registration
    // owners, and is driven only on this thread with no competing registration.
    let mut files = unsafe { FixedFileTable::new(proactor.ring_mut(), 1)? };
    // SAFETY: This is the ring's sole fixed-buffer pool; waiting tokens retain
    // storage even on failure and no completed buffer is reused before its CQE.
    let mut buffers = unsafe { FixedBufferPool::new(proactor.ring_mut(), 1, 64)? };
    let first = files.insert(original.as_raw_fd())?;
    let old_fd = original.as_raw_fd();
    // SAFETY: Both descriptors belong to this test. Replacing its original fd
    // verifies that table growth uses the retained file identity, not fd number.
    let duplicated = unsafe { libc::dup2(replacement.as_raw_fd(), old_fd) };
    assert_eq!(duplicated, old_fd);
    drop(original);
    let second = files.insert(replacement.as_raw_fd())?;
    assert_eq!((first.raw(), second.raw(), files.capacity()), (0, 1, 2));
    assert_eq!(files.get(first), Some(old_fd));
    assert_eq!(files.get(second), Some(replacement.as_raw_fd()));
    for (index, slot, expected) in [(1, first, b"original"), (2, second, b"second!!")] {
        let mut buffer = buffers.checkout()?;
        let id = buffer.id();
        let address = buffer.as_mut_ptr();
        let waiting = buffer.into_in_flight();
        proactor.prepare_sqe_with(op(index), |sqe| {
            // SAFETY: The slot remains registered, and waiting owns the stable
            // exclusive writable allocation until this read's final completion.
            unsafe {
                net::prep_read_fixed(sqe, slot.raw() as i32, address, 8, 0, id);
                liburing_sys::uring_shim_sqe_set_flags(sqe, liburing_sys::IOSQE_FIXED_FILE);
            }
        })?;
        let cqe = next(&mut proactor, &completions)?;
        assert_eq!((cqe.op_id, cqe.result, cqe.flags), (op(index), 8, 0));
        // SAFETY: This exact read delivered its final CQE, with no continuation
        // or zero-copy notification, ending kernel access to the buffer.
        let mut buffer = unsafe { waiting.complete()? };
        assert_eq!(&buffer.as_slice()[..8], expected);
        buffer.as_mut_slice()[..8].copy_from_slice(b"updated!");
        let address = buffer.as_ptr();
        let waiting = buffer.into_in_flight();
        proactor.prepare_sqe_with(op(index + 10), |sqe| {
            // SAFETY: The same fixed-file index remains live. The waiting token
            // retains the registered immutable bytes through the write CQE.
            unsafe {
                net::prep_write_fixed(sqe, slot.raw() as i32, address, 8, 0, id);
                liburing_sys::uring_shim_sqe_set_flags(sqe, liburing_sys::IOSQE_FIXED_FILE);
            }
        })?;
        let cqe = next(&mut proactor, &completions)?;
        assert_eq!((cqe.op_id, cqe.result, cqe.flags), (op(index + 10), 8, 0));
        // SAFETY: The write's own final CQE ends all access to these bytes.
        drop(unsafe { waiting.complete()? });
        let mut buffer = buffers.checkout()?;
        let address = buffer.as_mut_ptr();
        let waiting = buffer.into_in_flight();
        proactor.prepare_sqe_with(op(index + 20), |sqe| {
            // SAFETY: This live slot and registered writable buffer outlive the
            // read, with no user access until its own final completion below.
            unsafe {
                net::prep_read_fixed(sqe, slot.raw() as i32, address, 8, 0, id);
                liburing_sys::uring_shim_sqe_set_flags(sqe, liburing_sys::IOSQE_FIXED_FILE);
            }
        })?;
        let cqe = next(&mut proactor, &completions)?;
        assert_eq!((cqe.op_id, cqe.result, cqe.flags), (op(index + 20), 8, 0));
        // SAFETY: The read's final CQE grants exclusive user access again.
        let buffer = unsafe { waiting.complete()? };
        assert_eq!(&buffer.as_slice()[..8], b"updated!");
        drop(buffer);
    }
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    // SAFETY: The live ring exclusively owns group 70. ManuallyDrop retains
    // kernel-visible storage on every early exit, including assertion unwinding.
    let mut group = ManuallyDrop::new(unsafe {
        ProvidedBufRing::new(proactor.ring_mut(), 2, 64, BufGroupId(70))?
    });
    sender.send_to(b"composed udp", receiver.local_addr()?)?;
    proactor.prepare_sqe_with(op(30), |sqe| {
        // SAFETY: The socket and registered group remain live until this
        // one-shot receive's final CQE. Buffer selection ignores the null ptr.
        unsafe {
            liburing_sys::uring_shim_prep_recv(
                sqe,
                receiver.as_raw_fd(),
                std::ptr::null_mut(),
                64,
                0,
            );
            liburing_sys::uring_shim_sqe_set_flags(sqe, liburing_sys::IOSQE_BUFFER_SELECT);
            liburing_sys::uring_shim_sqe_set_buf_group(sqe, group.group_id().0);
        }
    })?;
    let cqe = next(&mut proactor, &completions)?;
    assert_eq!((cqe.op_id, cqe.result), (op(30), 12));
    assert_eq!(cqe.flags & liburing_sys::IORING_CQE_F_MORE, 0);
    // SAFETY: This genuine, unleased selected-buffer CQE transfers exclusive
    // ownership of a buffer from this group, whose reported size is in bounds.
    let lease = unsafe { group.lease_from_cqe(cqe.flags, cqe.result)? };
    assert_eq!(&*lease, b"composed udp");
    assert_eq!(group.returned_count(), 0);
    lease.release();
    assert_eq!(group.returned_count(), 1);
    // SAFETY: The group's only receive completed finally and its lease ended;
    // unregistration and this sole explicit drop cannot race any kernel access.
    unsafe {
        group.unregister()?;
        ManuallyDrop::drop(&mut group);
    }
    buffers.unregister()?;
    files.unregister()?;
    proactor.shutdown()?;
    Ok(())
}

#[test]
fn target_and_cancel_cqes_preserve_checked_buffer_generations() -> TestResult {
    let _serial = crate::kernel_test_lock();
    let (mut proactor, completions) = proactor()?;
    let (reader, mut writer) = UnixStream::pair()?;
    // SAFETY: The stable owner-thread ring outlives this sole buffer pool.
    // Tokens retain allocations on error until no kernel access can remain.
    let mut pool = unsafe { FixedBufferPool::new(proactor.ring_mut(), 1, 64)? };
    let mut buffer = pool.checkout()?;
    let id = buffer.id();
    let address = buffer.as_mut_ptr();
    let mut old = buffer.into_in_flight();
    let old_generation = old.generation();
    proactor.prepare_sqe_with(op(40), |sqe| {
        // SAFETY: The live empty socket leaves the read pending. The waiting
        // token retains exclusive registered storage through the target CQE.
        unsafe { net::prep_read_fixed(sqe, reader.as_raw_fd(), address, 1, 0, id) };
    })?;
    proactor.submit()?;
    old.quarantine()?;
    proactor.prepare_sqe_with(op(41), |sqe| {
        // SAFETY: This ID identifies the pending read, whose storage remains
        // quarantined through both independent control and target completions.
        unsafe { net::prep_cancel(sqe, op(40), 0) };
    })?;
    let mut target_seen = false;
    let mut cancel_seen = false;
    for _ in 0..2 {
        let cqe = next(&mut proactor, &completions)?;
        assert_eq!(pool.available(), 0, "neither CQE automatically frees DMA");
        assert!(matches!(
            pool.checkout(),
            Err(UringError::FixedBuffersExhausted)
        ));
        match cqe.op_id {
            value if value == op(40) => {
                assert!(!target_seen);
                assert_eq!((cqe.result, cqe.flags), (-libc::ECANCELED, 0));
                target_seen = true;
            }
            value if value == op(41) => {
                assert!(!cancel_seen);
                assert_eq!((cqe.result, cqe.flags), (0, 0));
                cancel_seen = true;
            }
            value => panic!("unexpected completion {value:?}"),
        }
    }
    assert!(target_seen && cancel_seen);
    // SAFETY: The original read's own final -ECANCELED CQE is observed, not
    // merely the cancellation acknowledgement. No DMA or notification remains.
    unsafe { pool.reclaim_completed_generation(id, old_generation)? };
    let mut replacement = pool.checkout()?;
    assert_eq!(replacement.id(), id);
    let address = replacement.as_mut_ptr();
    let current = replacement.into_in_flight();
    assert_ne!(current.generation(), old_generation);
    proactor.prepare_sqe_with(op(42), |sqe| {
        // SAFETY: The new generation exclusively retains this registered byte
        // and the socket remains live through the final CQE below.
        unsafe { net::prep_read_fixed(sqe, reader.as_raw_fd(), address, 1, 0, id) };
    })?;
    proactor.submit()?;
    // SAFETY: The old generation's own final completion was observed. Supplying
    // its stale identity must fail without reclaiming the new operation's DMA.
    let stale_reclaim = unsafe { pool.reclaim_completed_generation(id, old_generation) };
    assert!(matches!(
        stale_reclaim,
        Err(UringError::BufferNotInFlight(_))
    ));
    drop(old);
    assert_eq!(pool.available(), 0);
    assert!(pool.unregister().is_err());
    writer.write_all(b"x")?;
    let cqe = next(&mut proactor, &completions)?;
    assert_eq!((cqe.op_id, cqe.result, cqe.flags), (op(42), 1, 0));
    // SAFETY: The replacement read's own final CQE excludes further kernel
    // access to this generation and permits exclusive user-space byte access.
    let replacement = unsafe { current.complete()? };
    assert_eq!(replacement.as_slice()[0], b'x');
    drop(replacement);
    assert_eq!(pool.available(), 1);
    pool.unregister()?;
    proactor.shutdown()?;
    Ok(())
}
