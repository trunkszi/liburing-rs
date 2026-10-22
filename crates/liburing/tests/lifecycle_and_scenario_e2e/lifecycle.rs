use std::{
    cell::{Cell, RefCell},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixStream,
    },
    rc::Rc,
    time::{Duration, Instant},
};

use liburing::{
    BufGroupId, Completion, OpId, OpPayload, Proactor, ProactorBuilder, Result, SubmissionContext,
    SubsystemHandler, SubsystemId, UringError, fixed_buffers::FixedBufferPool,
    fixed_files::FixedFileTable, ops::net, pbuf_ring::ProvidedBufRing,
};
use liburing_sys as sys;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

const STORAGE: SubsystemId = SubsystemId::new_unchecked(61);
const CONTROL: SubsystemId = SubsystemId::new_unchecked(62);
const WRITE: u64 = 1;
const DIRECT_CLOSE: u64 = 2;
const PENDING_READ: u64 = 3;
const READY_NOP: u64 = 4;

fn operation(subsystem: SubsystemId, payload: u64) -> OpId {
    OpId::pack(subsystem, OpPayload::new_unchecked(payload))
}

struct Registrations {
    files: FixedFileTable,
    buffers: FixedBufferPool,
    provided: ProvidedBufRing,
    reader: UnixStream,
    _writer: UnixStream,
    receive: Box<[u8; 8]>,
    drops: Rc<Cell<usize>>,
}

impl Drop for Registrations {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[derive(Default)]
struct Observations {
    completions: Vec<Completion>,
    shutdown_started: bool,
    rejected_followups: usize,
    handler_drops: usize,
}

struct LifecycleHandler {
    registrations: Rc<RefCell<Option<Registrations>>>,
    observed: Rc<RefCell<Observations>>,
}

impl SubsystemHandler for LifecycleHandler {
    fn on_completion(
        &mut self,
        cqe: Completion,
        context: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        let mut observed = self.observed.borrow_mut();
        observed.completions.push(cqe);
        if observed.shutdown_started {
            assert_eq!(context.remaining_capacity(), 0);
            let prepared = Cell::new(false);
            assert_eq!(
                context.prepare_sqe_with(operation(CONTROL, 99), |_| prepared.set(true)),
                Err(UringError::SqRingFull)
            );
            assert!(!prepared.get(), "shutdown invoked a rejected SQE preparer");
            observed.rejected_followups += 1;
        }
        if cqe.op_id == operation(STORAGE, PENDING_READ) {
            assert!(observed.shutdown_started);
            assert_eq!(cqe.result, -libc::ECANCELED);
            assert_eq!(cqe.flags & sys::IORING_CQE_F_MORE, 0);
            let mut registrations = self.registrations.borrow_mut();
            let owners = registrations.as_mut().expect("live registration owners");
            owners.buffers.unregister()?;
            owners.files.unregister()?;
            // SAFETY: No receive ever selected this group, and every fixed I/O
            // operation retired before shutdown. The sole pending ordinary read
            // delivered its own final CQE above. Ring teardown has not run yet.
            unsafe { owners.provided.unregister()? };
            drop(registrations.take());
        }
        Ok(())
    }
}

impl Drop for LifecycleHandler {
    fn drop(&mut self) {
        self.observed.borrow_mut().handler_drops += 1;
    }
}

fn wait_for(
    proactor: &mut Proactor,
    observed: &RefCell<Observations>,
    target: OpId,
) -> Result<Completion> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(completion) = observed
            .borrow()
            .completions
            .iter()
            .find(|c| c.op_id == target)
        {
            return Ok(*completion);
        }
        assert!(
            Instant::now() < deadline,
            "target completion did not arrive"
        );
        proactor.wait_completions(1, Some(Duration::from_millis(100)), |_, _| Ok(()))?;
    }
}

#[test]
fn builder_registrations_growth_direct_close_shutdown_and_drop() -> TestResult {
    let _serial = crate::kernel_test_lock();
    let mut proactor = ProactorBuilder::new()
        .entries(32)
        .max_cqe_batch(32)
        .enable_optimizations(false)
        .build()?;
    let observed = Rc::new(RefCell::new(Observations::default()));
    let drops = Rc::new(Cell::new(0));
    let (reader, writer) = UnixStream::pair()?;
    // SAFETY: The proactor's ring has a stable boxed address and stays alive
    // until the shutdown callback explicitly unregisters all resource owners.
    // Only this test accesses registrations, on the ring's creating thread.
    let files = unsafe { FixedFileTable::new(proactor.ring_mut(), 1)? };
    // SAFETY: This is the ring's sole fixed-buffer owner; submitted buffers stay
    // alive in retained tokens until their own final CQEs have been dispatched.
    let buffers = unsafe { FixedBufferPool::new(proactor.ring_mut(), 1, 64)? };
    // SAFETY: Group 61 is exclusively owned and all group operations (none in
    // this lifecycle test) finish before unregister in the shutdown callback.
    let provided = unsafe { ProvidedBufRing::new(proactor.ring_mut(), 2, 64, BufGroupId(61))? };
    let registrations = Rc::new(RefCell::new(Some(Registrations {
        files,
        buffers,
        provided,
        reader,
        _writer: writer,
        receive: Box::new([0; 8]),
        drops: Rc::clone(&drops),
    })));
    for subsystem in [STORAGE, CONTROL] {
        proactor.register_subsystem(
            subsystem,
            LifecycleHandler {
                registrations: Rc::clone(&registrations),
                observed: Rc::clone(&observed),
            },
        )?;
    }
    // SAFETY: The name is NUL terminated and retained only during memfd_create.
    // A nonnegative result transfers ownership of a new descriptor to this test.
    let fd = unsafe { libc::memfd_create(c"lifecycle-fixed-file".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: Successful memfd_create returned a uniquely owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let (slot, mut bytes) = {
        let mut owners = registrations.borrow_mut();
        let owners = owners.as_mut().expect("registered owners");
        (
            owners.files.insert(file.as_raw_fd())?,
            owners.buffers.checkout()?,
        )
    };
    let payload = b"full lifecycle fixed I/O";
    bytes.as_mut_slice()[..payload.len()].copy_from_slice(payload);
    let buffer_id = bytes.id();
    let address = bytes.as_mut_ptr();
    let waiting = bytes.into_in_flight();
    proactor.prepare_sqe_with(operation(STORAGE, WRITE), |sqe| {
        // SAFETY: The slot is registered and the token retains stable DMA bytes
        // through the write's final CQE. Preparation exclusively owns this SQE.
        unsafe {
            net::prep_write_fixed(
                sqe,
                slot.raw() as i32,
                address,
                payload.len() as u32,
                0,
                buffer_id,
            );
            sys::uring_shim_sqe_set_flags(sqe, sys::IOSQE_FIXED_FILE);
        }
    })?;
    proactor.submit()?;
    let written = wait_for(&mut proactor, &observed, operation(STORAGE, WRITE))?;
    assert_eq!(written.result, payload.len() as i32);
    assert_eq!(written.flags & sys::IORING_CQE_F_MORE, 0);
    // SAFETY: The exact write's final CQE establishes no further DMA access.
    drop(unsafe { waiting.complete()? });
    {
        let mut owners = registrations.borrow_mut();
        let owners = owners.as_mut().expect("registered owners");
        owners.files.grow(2)?;
        assert_eq!(owners.files.capacity(), 2);
        assert_eq!(owners.files.get(slot), Some(file.as_raw_fd()));
        assert_eq!(owners.buffers.available(), 1);
    }
    proactor.prepare_sqe_with(operation(STORAGE, DIRECT_CLOSE), |sqe| {
        // SAFETY: The slot's prior write retired above. This unique direct-close
        // SQE removes its kernel reference; the original File remains owned.
        unsafe { net::prep_close_direct(sqe, slot) };
    })?;
    let closed = wait_for(&mut proactor, &observed, operation(STORAGE, DIRECT_CLOSE))?;
    assert_eq!(closed.result, 0);
    assert_eq!(closed.flags & sys::IORING_CQE_F_MORE, 0);
    {
        let mut owners = registrations.borrow_mut();
        let owners = owners.as_mut().expect("registered owners");
        // SAFETY: This exact slot's successful final direct-close CQE was
        // delivered above, and all earlier operations using it have retired.
        let reclaimed = unsafe { owners.files.reclaim_direct_close(slot)? };
        assert_eq!(reclaimed, file.as_raw_fd());
        assert_eq!(owners.files.available(), 2);
        assert_eq!(owners.files.insert(file.as_raw_fd())?, slot);
    }
    let (reader_fd, receive) = {
        let mut owners = registrations.borrow_mut();
        let owners = owners.as_mut().expect("registered owners");
        (owners.reader.as_raw_fd(), owners.receive.as_mut_ptr())
    };
    proactor.prepare_sqe_with(operation(STORAGE, PENDING_READ), |sqe| {
        // SAFETY: Handler-owned boxed bytes and the stream remain alive until
        // this read's own final CQE. The peer stays open and sends no bytes.
        unsafe { sys::uring_shim_prep_read(sqe, reader_fd, receive.cast(), 8, 0) };
    })?;
    proactor.alloc_sqe(operation(CONTROL, READY_NOP))?;
    let ring = proactor.ring_mut();
    proactor.submit()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut cqe = std::ptr::null_mut();
        // SAFETY: This non-consuming readiness check borrows the initialized
        // owner-thread ring exclusively. It neither prepares nor consumes work,
        // so the proactor's pending-operation accounting remains unchanged.
        let ready = unsafe { sys::uring_shim_peek_cqe(ring, &mut cqe) };
        if ready >= 0 && !cqe.is_null() {
            // SAFETY: The successful peek retains this CQE until consumption;
            // the proactor has not advanced its CQ head during this check.
            let completed_id = unsafe { (*cqe).user_data };
            assert_eq!(completed_id, operation(CONTROL, READY_NOP).raw());
            break;
        }
        assert_eq!(ready, -libc::EAGAIN);
        assert!(
            Instant::now() < deadline,
            "NOP CQE was not ready before shutdown"
        );
        std::thread::yield_now();
    }
    assert_eq!(observed.borrow().completions.len(), 2);
    assert_eq!(drops.get(), 0);
    observed.borrow_mut().shutdown_started = true;
    proactor.shutdown()?;
    let observations = observed.borrow();
    let ready = observations
        .completions
        .iter()
        .find(|c| c.op_id == operation(CONTROL, READY_NOP))
        .expect("completed NOP delivered during shutdown");
    assert_eq!(ready.result, 0);
    assert_eq!(observations.completions.len(), 4);
    assert_eq!(observations.rejected_followups, 2);
    assert_eq!(observations.handler_drops, 0);
    drop(observations);
    assert_eq!(
        drops.get(),
        1,
        "registration owners dropped before ring exit"
    );
    assert!(registrations.borrow().is_none());
    assert!(proactor.ring_mut().is_null());
    let prepared = Cell::new(false);
    assert!(matches!(
        proactor.prepare_sqe_with(operation(CONTROL, 99), |_| prepared.set(true)),
        Err(UringError::InvalidConfig(_))
    ));
    assert!(!prepared.get());
    assert!(proactor.alloc_sqe(operation(CONTROL, 100)).is_err());
    assert!(proactor.submit().is_err());
    proactor.shutdown()?;
    drop(proactor);
    assert_eq!(observed.borrow().handler_drops, 2);
    assert_eq!(drops.get(), 1);
    Ok(())
}
