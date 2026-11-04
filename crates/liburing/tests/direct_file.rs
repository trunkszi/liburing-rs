//! Aligned fixed buffers and `O_DIRECT` file I/O against a real kernel ring.
//!
//! Reads run only after `fallocate` and a direct write have allocated blocks.
//! A sparse hole is never the read target.

use std::{
    io,
    os::fd::{AsRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use liburing::{
    Completion, DirectAccess, DirectFile, OperationId, Proactor, ProactorConfig, Result,
    SubmissionContext, SubsystemId, UringError,
    backend::RawSqe,
    fixed_buffers::{FixedBufferPool, InFlightWaitingBuffer},
    ops::prep_read_fixed,
};

const SUBSYSTEM: SubsystemId = SubsystemId::new_unchecked(1);

struct TempFile(PathBuf);

impl TempFile {
    fn create() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(&root)?;
        let path = root.join(format!("liburing-direct-{}-{id}", std::process::id()));
        drop(std::fs::File::create(&path)?);
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        drop(std::fs::remove_file(&self.0));
    }
}

fn new_proactor() -> Result<Proactor> {
    Proactor::new(ProactorConfig {
        entries: 8,
        staged_capacity: 8,
        ..ProactorConfig::default()
    })
}

fn transfer_len(file: &DirectFile) -> usize {
    let step = usize::try_from(file.offset_align().max(1)).unwrap_or(usize::MAX);
    let mut len = file.mem_align().max(step).max(4096);
    let remainder = len % step.max(1);
    if remainder != 0 {
        len = len.saturating_add(step - remainder);
    }
    len
}

fn buffer_align(file: &DirectFile) -> usize {
    file.mem_align().max(4096)
}

fn pattern_byte(index: usize) -> u8 {
    (index as u8).wrapping_mul(31).wrapping_add(17)
}

fn zero_byte(_index: usize) -> u8 {
    0
}

fn result_len(len: usize) -> Result<i32> {
    i32::try_from(len).map_err(|_| UringError::InvalidConfig("transfer exceeds i32"))
}

fn assert_config(error: UringError, text: &str) {
    match error {
        UringError::InvalidConfig(message) => assert!(message.contains(text), "{message}"),
        other => panic!("expected invalid configuration, observed {other}"),
    }
}

fn file_stat(fd: std::os::fd::RawFd) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `stat` is writable zeroed storage and `fd` is open for this call.
    let rc = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fstat` succeeded and wrote a plain integer `stat`.
    Ok(unsafe { stat.assume_init() })
}

fn assert_blocks(fd: std::os::fd::RawFd) -> io::Result<()> {
    let stat = file_stat(fd)?;
    if stat.st_blocks <= 0 {
        return Err(io::Error::other("file has no allocated blocks"));
    }
    Ok(())
}

fn assert_allocated(fd: std::os::fd::RawFd, len: usize) -> io::Result<()> {
    let stat = file_stat(fd)?;
    if stat.st_blocks <= 0 {
        return Err(io::Error::other("file has no allocated blocks"));
    }
    if stat.st_size < i64::try_from(len).unwrap_or(i64::MAX) {
        return Err(io::Error::other("file size is below the direct transfer"));
    }
    Ok(())
}

fn fallocate(fd: std::os::fd::RawFd, len: usize) -> io::Result<()> {
    let Some(bytes) = libc::off_t::try_from(len).ok() else {
        return Err(io::Error::other("length exceeds off_t"));
    };
    // SAFETY: `fd` is open. Mode 0 allocates backing blocks for 0..bytes and
    // extends the file size to bytes, so a later read does not target a hole.
    let rc = unsafe { libc::fallocate(fd, 0, 0, bytes) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn reserve_blocks(path: &Path, direct: std::os::fd::RawFd, len: usize) -> io::Result<()> {
    match fallocate(direct, len) {
        Ok(()) => assert_blocks(direct),
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            let file = std::fs::OpenOptions::new().write(true).open(path)?;
            fallocate(file.as_raw_fd(), len)?;
            assert_blocks(direct)
        }
        Err(error) => Err(error),
    }
}

fn queue_poll_oracle(fd: std::os::fd::RawFd) -> io::Result<bool> {
    let stat = file_stat(fd)?;
    let major = libc::major(stat.st_dev);
    let minor = libc::minor(stat.st_dev);
    for path in [
        format!("/sys/dev/block/{major}:{minor}/queue/io_poll"),
        format!("/sys/dev/block/{major}:{minor}/../queue/io_poll"),
    ] {
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let value: u32 = text
                    .trim()
                    .parse()
                    .map_err(|_| io::Error::other("unreadable io_poll sysfs value"))?;
                return Ok(value > 0);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn take_buffer(proactor: &Proactor, fill: fn(usize) -> u8) -> Result<InFlightWaitingBuffer> {
    // SAFETY: The checkout token is the only pool borrow. It does not outlive the ring.
    let pool = unsafe { proactor.fixed_buffers() }?;
    let mut handle = pool.checkout()?;
    for (index, byte) in handle.as_mut_slice().iter_mut().enumerate() {
        *byte = fill(index);
    }
    Ok(handle.into_in_flight())
}

fn wait_one(proactor: &mut Proactor) -> Result<Completion> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut observed = Vec::new();
    while observed.is_empty() {
        if Instant::now() >= deadline {
            return Err(UringError::Wait(libc::ETIMEDOUT));
        }
        proactor.wait_completions(
            1,
            Some(Duration::from_millis(100)),
            &mut |completion: Completion, _context: &mut SubmissionContext<'_>| {
                observed.push(completion);
                Ok(())
            },
        )?;
    }
    match observed.as_slice() {
        [completion] => Ok(*completion),
        _ => Err(UringError::InvalidConfig(
            "unexpected direct I/O completion count",
        )),
    }
}

fn write_pattern(file: &DirectFile, proactor: &mut Proactor, len: usize) -> Result<()> {
    let buffer = take_buffer(proactor, pattern_byte)?;
    let key = file.write_fixed(proactor, SUBSYSTEM, buffer, len, 0)?;
    let completion = wait_one(proactor)?;
    assert_eq!(
        completion.operation_id,
        OperationId::pack(SUBSYSTEM, key.payload())
    );
    assert_eq!(completion.result, result_len(len)?);
    Ok(())
}

fn read_pattern(file: &DirectFile, proactor: &mut Proactor, len: usize) -> Result<Vec<u8>> {
    let buffer = take_buffer(proactor, zero_byte)?;
    let key = file.read_fixed(proactor, SUBSYSTEM, buffer, len, 0)?;
    let completion = wait_one(proactor)?;
    assert_eq!(
        completion.operation_id,
        OperationId::pack(SUBSYSTEM, key.payload())
    );
    assert_eq!(completion.result, result_len(len)?);
    // SAFETY: The final CQE already returned this allocation to the free stack.
    let pool = unsafe { proactor.fixed_buffers() }?;
    let handle = pool.checkout()?;
    let copied = handle.as_slice()[..len].to_vec();
    drop(handle);
    Ok(copied)
}

fn reap_direct(ring: &mut io_uring::IoUring) -> io::Result<i32> {
    let timeout = io_uring::types::Timespec::new().nsec(50_000_000);
    let args = io_uring::types::SubmitArgs::new().timespec(&timeout);
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        // IOPOLL can consume the SQE in one enter and publish the CQE from a
        // later poll. An empty poll list returns immediately, so retry until
        // the completion is visible or the bound expires.
        match ring.submitter().submit_with_args(1, &args) {
            Ok(_) => {}
            Err(error) if error.raw_os_error() == Some(libc::ETIME) => {}
            Err(error) => return Err(error),
        }
        let mut completion = ring.completion();
        if let Some(cqe) = completion.next() {
            let result = cqe.result();
            completion.sync();
            return Ok(result);
        }
        let overflow = completion.overflow();
        completion.sync();
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "missing direct I/O completion overflow={overflow}"
            )));
        }
        core::hint::spin_loop();
    }
}

fn read_fixed_once(
    file: &DirectFile,
    len: usize,
    iopoll: bool,
    sqpoll: bool,
) -> io::Result<(i32, Vec<u8>)> {
    let encoded_len = u32::try_from(len).map_err(|_| io::Error::other("length exceeds u32"))?;
    let mut builder = io_uring::IoUring::builder();
    if iopoll {
        builder.setup_iopoll();
    }
    if sqpoll {
        builder.setup_sqpoll(1_000);
    }
    let mut ring = Box::new(builder.build(8)?);
    // SAFETY: The boxed ring stays put and outlives this pool. The test thread
    // is the only registrant, and the buffer token is completed before unregister.
    let mut pool = unsafe {
        FixedBufferPool::with_alignment(ring.as_mut(), 1, len, buffer_align(file))
            .map_err(|error| io::Error::other(error.to_string()))?
    };
    let waiting = {
        let mut handle = pool
            .checkout()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let address = handle.as_mut_ptr();
        let index = handle.id();
        let waiting = handle.into_in_flight();
        let mut sqe = RawSqe::default();
        // SAFETY: The in-flight token retains the registered allocation. The SQE
        // is copied into the ring before this stack slot is reused. SQPOLL may
        // read the descriptor and pointer after submit returns.
        unsafe {
            prep_read_fixed(
                std::ptr::from_mut(&mut sqe),
                file.as_raw_fd(),
                address,
                encoded_len,
                0,
                index,
            );
        }
        let entry = sqe.into_entry();
        {
            let mut queue = ring.submission();
            // SAFETY: The queue copies the entry. Operand owners stay alive until
            // the final CQE is observed below.
            unsafe { queue.push(&entry) }.map_err(|_| io::Error::other("submission queue full"))?;
        }
        waiting
    };
    // IOPOLL posts the CQE from the poll enter. One submit can consume the SQE
    // before that completion is visible, so reap until it appears or the bound expires.
    let result = reap_direct(&mut ring)?;
    // SAFETY: The CQE is the final completion of this one read, including when
    // the kernel reports an error. No later SQE names the buffer.
    let handle =
        unsafe { waiting.complete() }.map_err(|error| io::Error::other(error.to_string()))?;
    let contents = handle.as_slice()[..len].to_vec();
    drop(handle);
    pool.unregister()
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok((result, contents))
}

fn polled_device_path() -> PathBuf {
    match std::env::var("LIBURING_IOPOLL_TEST_PATH") {
        Ok(path) if !path.is_empty() => PathBuf::from(path),
        _ => panic!("LIBURING_IOPOLL_TEST_PATH is required for this ignored test"),
    }
}

fn read_polled_device(sqpoll: bool) -> Result<()> {
    let file = DirectFile::open(polled_device_path().as_path(), DirectAccess::ReadOnly)?;
    assert!(
        file.supports_polled_io()?,
        "LIBURING_IOPOLL_TEST_PATH is not on a polled queue"
    );
    let len = transfer_len(&file);
    let (result, _) = read_fixed_once(&file, len, true, sqpoll).expect("polled device read");
    assert_eq!(result, result_len(len)?);
    Ok(())
}

#[test]
fn direct_buffers_honor_alignment() -> Result<()> {
    let mut proactor = new_proactor()?;
    match proactor.configure_direct_buffers(1, 4096, 24) {
        Err(error) => assert_config(error, "power of two"),
        Ok(()) => panic!("non power-of-two alignment was accepted"),
    }
    // SAFETY: Registration was rejected, so this only observes an absent table.
    assert!(unsafe { proactor.fixed_buffers() }.is_err());
    proactor.configure_direct_buffers(2, 8192, 8192)?;
    let (first, second) = {
        // SAFETY: Both handles are dropped before the next proactor borrow.
        let pool = unsafe { proactor.fixed_buffers() }?;
        let mut left = pool.checkout()?;
        let mut right = pool.checkout()?;
        let left_addr = left.as_mut_ptr() as usize;
        let right_addr = right.as_mut_ptr() as usize;
        assert_eq!(left.as_slice().len(), 8192);
        assert_eq!(right.as_slice().len(), 8192);
        drop(left);
        drop(right);
        (left_addr, right_addr)
    };
    assert_eq!(first % 8192, 0);
    assert_eq!(second % 8192, 0);
    assert_ne!(first, second);
    proactor.shutdown()?;

    let mut proactor = new_proactor()?;
    proactor.configure_fixed_buffers(1, 128)?;
    {
        // SAFETY: The handle ends before shutdown.
        let pool = unsafe { proactor.fixed_buffers() }?;
        let mut handle = pool.checkout()?;
        assert_eq!(handle.as_mut_ptr() as usize % 4096, 0);
        assert_eq!(handle.as_slice().len(), 128);
        drop(handle);
    }
    proactor.shutdown()?;
    Ok(())
}

#[test]
fn direct_file_rejects_misaligned_requests() -> Result<()> {
    let temp = TempFile::create()?;
    let plain = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(temp.path())?;
    match DirectFile::from_owned_fd(OwnedFd::from(plain)) {
        Err(error) => assert_config(error, "O_DIRECT"),
        Ok(_) => panic!("descriptor without O_DIRECT was accepted"),
    }
    let file = DirectFile::open(temp.path(), DirectAccess::ReadWrite)?;
    let step = file.offset_align();
    assert!(
        step > 1,
        "offset alignment {step} cannot express a short length"
    );
    let len = transfer_len(&file);
    let mut proactor = new_proactor()?;
    proactor.configure_direct_buffers(1, len, buffer_align(&file))?;
    let buffer = take_buffer(&proactor, zero_byte)?;
    match file.read_fixed(&mut proactor, SUBSYSTEM, buffer, len, 1) {
        Err(error) => assert_config(error, "offset"),
        Ok(_) => panic!("misaligned offset was accepted"),
    }
    assert_eq!(proactor.operation_count(), 0);
    // SAFETY: The rejected token was completed and dropped, so the pool is idle.
    assert_eq!(unsafe { proactor.fixed_buffers() }?.available(), 1);

    let short = usize::try_from(step / 2).unwrap_or(0);
    assert!(short > 0 && short < len);
    let buffer = take_buffer(&proactor, zero_byte)?;
    match file.write_fixed(&mut proactor, SUBSYSTEM, buffer, short, 0) {
        Err(error) => assert_config(error, "length"),
        Ok(_) => panic!("misaligned length was accepted"),
    }
    assert_eq!(proactor.operation_count(), 0);
    // SAFETY: Same idle pool as above; the second rejection returned its buffer.
    assert_eq!(unsafe { proactor.fixed_buffers() }?.available(), 1);
    proactor.shutdown()?;
    Ok(())
}

#[test]
fn event_ring_reads_allocated_direct_block() -> Result<()> {
    let temp = TempFile::create()?;
    let file = DirectFile::open(temp.path(), DirectAccess::ReadWrite)?;
    let len = transfer_len(&file);
    reserve_blocks(temp.path(), file.as_raw_fd(), len)?;
    let mut proactor = new_proactor()?;
    proactor.configure_direct_buffers(1, len, buffer_align(&file))?;
    write_pattern(&file, &mut proactor, len)?;
    assert_allocated(file.as_raw_fd(), len)?;
    let actual = read_pattern(&file, &mut proactor, len)?;
    let expected: Vec<u8> = (0..len).map(pattern_byte).collect();
    assert_eq!(actual, expected);
    assert_eq!(
        file.supports_polled_io()?,
        queue_poll_oracle(file.as_raw_fd())?
    );
    proactor.shutdown()?;
    Ok(())
}

#[test]
fn iopoll_without_poll_queue_reports_unsupported() -> Result<()> {
    let temp = TempFile::create()?;
    let file = DirectFile::open(temp.path(), DirectAccess::ReadWrite)?;
    let len = transfer_len(&file);
    reserve_blocks(temp.path(), file.as_raw_fd(), len)?;
    {
        let mut proactor = new_proactor()?;
        proactor.configure_direct_buffers(1, len, buffer_align(&file))?;
        write_pattern(&file, &mut proactor, len)?;
        proactor.shutdown()?;
    }
    assert_allocated(file.as_raw_fd(), len)?;
    let (result, contents) = read_fixed_once(&file, len, true, false).expect("iopoll read");
    if file.supports_polled_io()? {
        assert_eq!(result, result_len(len)?);
        let expected: Vec<u8> = (0..len).map(pattern_byte).collect();
        assert_eq!(contents, expected);
    } else {
        assert_eq!(result, -libc::EOPNOTSUPP);
    }
    Ok(())
}

#[test]
#[ignore = "requires LIBURING_IOPOLL_TEST_PATH on a polled queue"]
fn iopoll_reads_real_polled_device() -> Result<()> {
    read_polled_device(false)
}

#[test]
#[ignore = "requires LIBURING_IOPOLL_TEST_PATH on a polled queue"]
fn sqpoll_iopoll_reads_real_polled_device() -> Result<()> {
    read_polled_device(true)
}

#[test]
fn fs_ops_roundtrip_contiguous_and_vectored() -> Result<()> {
    use std::os::unix::fs::FileExt;

    use liburing::ops::fs;
    let temp = TempFile::create()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(temp.path())?;
    // Descriptor storage precedes the proactor so it survives error-path teardown.
    // Only the payload ranges belong to registered memory, not this stack array.
    let mut vectors = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 32,
    }; 2];
    let mut proactor = new_proactor()?;
    proactor.configure_fixed_buffers(1, 64)?;
    for step in 0..6 {
        let write = step % 2 == 0;
        let offset = 7 + (step / 2) as u64 * 4096;
        let expected: Vec<u8> = (0..64)
            .map(|i| pattern_byte(i).wrapping_add((step / 2) as u8))
            .collect();
        // SAFETY: The handle is transferred into the tracked operation before
        // the next proactor borrow and cannot outlive its owning ring.
        let pool = unsafe { proactor.fixed_buffers() }?;
        let mut handle = pool.checkout()?;
        if write {
            handle.as_mut_slice().copy_from_slice(&expected);
        } else {
            handle.as_mut_slice().fill(0);
        }
        let address = handle.as_mut_ptr();
        let index = handle.id();
        vectors[0].iov_base = address.cast();
        // SAFETY: The registered allocation spans 64 bytes; offset 32 is inside it.
        vectors[1].iov_base = unsafe { address.add(32) }.cast();
        let iov = vectors.as_ptr();
        let waiting = handle.into_in_flight();
        let key = proactor.prepare_keyed_buffer_sqe_with(SUBSYSTEM, waiting, |sqe| {
            // SAFETY: The SQE is exclusive initialized storage. file and ordinary
            // stack iovecs outlive the ring, and both disjoint payload ranges lie
            // inside registered buffer index. The tracked token retains those
            // bytes through the final CQE, exclusively for read destinations.
            unsafe {
                match step {
                    0 => fs::prep_write(sqe, file.as_raw_fd(), address, 64, offset),
                    1 => fs::prep_read(sqe, file.as_raw_fd(), address, 64, offset),
                    2 => fs::prep_writev(sqe, file.as_raw_fd(), iov, 2, offset),
                    3 => fs::prep_readv(sqe, file.as_raw_fd(), iov, 2, offset),
                    4 => fs::prep_writev_fixed(sqe, file.as_raw_fd(), iov, 2, offset, index),
                    _ => fs::prep_readv_fixed(sqe, file.as_raw_fd(), iov, 2, offset, index),
                }
                if step >= 4 {
                    let expected_opcode = if write {
                        io_uring::opcode::WritevFixed::CODE
                    } else {
                        io_uring::opcode::ReadvFixed::CODE
                    };
                    assert_eq!((*sqe).opcode, expected_opcode);
                    assert_eq!((*sqe).buf_index, index.raw());
                }
            }
        })?;
        let cqe = wait_one(&mut proactor)?;
        assert_eq!(
            cqe.operation_id,
            OperationId::pack(SUBSYSTEM, key.payload())
        );
        assert_eq!(cqe.result, 64, "file helper step {step}");
        if write {
            let mut actual = [0u8; 64];
            file.read_exact_at(&mut actual, offset)?;
            assert_eq!(actual.as_slice(), expected);
        } else {
            // SAFETY: The terminal CQE returned the only token to the idle pool.
            let handle = unsafe { proactor.fixed_buffers() }?.checkout()?;
            assert_eq!(handle.as_slice(), expected);
            drop(handle);
        }
    }
    proactor.shutdown()?;
    Ok(())
}
