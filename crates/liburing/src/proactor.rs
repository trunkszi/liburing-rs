//! Thread-local ring ownership, bounded submission staging, and completion dispatch.

use std::{
    collections::VecDeque,
    marker::PhantomData,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    rc::Rc,
    time::Duration,
};

use liburing_sys as sys;

use crate::{
    config::{KernelFeatures, ProactorConfig},
    error::{Result, UringError},
    id::{OpId, OpPayload, SubsystemId},
    subsystem::{
        Completion, StagedSqe, SubmissionContext, SubsystemHandler, SubsystemRegistry,
        validate_prepared_sqe,
    },
    waker::ProactorWaker,
};

const INTERNAL_POLL: OpId = OpId::pack(SubsystemId::INTERNAL, OpPayload::new_unchecked(1));
const INTERNAL_CANCEL: u64 = 2;

/// One ring driven exclusively by the constructing thread.
///
/// SQEs staged by callbacks retain FIFO order and are never submitted while a
/// completion callback is active. Raw SQE resources remain the submitter's
/// responsibility until their final completion or successful ring shutdown.
///
/// Drop attempts bounded cancellation and draining. If draining fails, it
/// preserves registered handlers rather than releasing potentially referenced
/// resources. Call [`Self::shutdown`] explicitly to observe shutdown failures.
pub struct Proactor {
    ring: Box<sys::io_uring>,
    config: ProactorConfig,
    features: KernelFeatures,
    registry: SubsystemRegistry,
    waker: Option<ProactorWaker>,
    waker_poll_armed: bool,
    in_cqe_dispatch: bool,
    staged_sqes: VecDeque<StagedSqe>,
    pending_operations: usize,
    shutdown_started: bool,
    ring_closed: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Proactor {
    /// Creates a ring, retrying unsupported optional setup flags individually.
    ///
    /// # Errors
    /// Returns an initialization, configuration, or eventfd setup error.
    ///
    /// # Panics
    /// Does not panic except if allocating initialization storage fails.
    pub fn new(config: ProactorConfig) -> Result<Self> {
        config.validate()?;
        let incompatible = sys::IORING_SETUP_SQE128
            | sys::IORING_SETUP_CQE32
            | sys::IORING_SETUP_IOPOLL
            | sys::IORING_SETUP_SQPOLL
            | sys::IORING_SETUP_NO_MMAP
            | sys::IORING_SETUP_REGISTERED_FD_ONLY;
        if config.setup_flags & incompatible != 0 {
            return Err(UringError::InvalidConfig(
                "unsupported ring layout or I/O mode",
            ));
        }
        // SAFETY: The C ring and parameter structures consist of integer and pointer fields.
        let mut ring = Box::new(unsafe { std::mem::zeroed::<sys::io_uring>() });
        let optimizations = sys::IORING_SETUP_SINGLE_ISSUER
            | sys::IORING_SETUP_COOP_TASKRUN
            | sys::IORING_SETUP_DEFER_TASKRUN;
        let mut flags = config.setup_flags;
        if config.enable_optimizations {
            flags |= optimizations;
        }
        let features;
        loop {
            // SAFETY: A zeroed parameter structure requests the documented defaults.
            let mut params = unsafe { std::mem::zeroed::<sys::io_uring_params>() };
            params.flags = flags;
            if let Some(entries) = config.cq_entries {
                params.flags |= sys::IORING_SETUP_CQSIZE;
                params.cq_entries = entries;
            }
            // SAFETY: Both output pointers are exclusive, aligned, and live for this call.
            let result = unsafe {
                sys::uring_shim_queue_init_params(config.entries, ring.as_mut(), &mut params)
            };
            if result >= 0 {
                features = KernelFeatures {
                    setup_flags: params.flags,
                    features: params.features,
                };
                break;
            }
            if result != -libc::EINVAL || !config.enable_optimizations {
                return Err(UringError::RingInit(-result));
            }
            let removable = [
                sys::IORING_SETUP_DEFER_TASKRUN,
                sys::IORING_SETUP_COOP_TASKRUN,
                sys::IORING_SETUP_SINGLE_ISSUER,
            ]
            .into_iter()
            .find(|flag| flags & flag != 0 && config.setup_flags & flag == 0);
            match removable {
                Some(flag) => flags &= !flag,
                None => return Err(UringError::RingInit(-result)),
            }
        }
        let capacity = config.staged_capacity;
        let mut proactor = Self {
            ring,
            config,
            features,
            registry: SubsystemRegistry::new(),
            waker: None,
            waker_poll_armed: false,
            in_cqe_dispatch: false,
            staged_sqes: VecDeque::with_capacity(capacity),
            pending_operations: 0,
            shutdown_started: false,
            ring_closed: false,
            _thread_bound: PhantomData,
        };
        if proactor.config.enable_waker {
            proactor.waker = Some(ProactorWaker::new()?);
            proactor.arm_waker()?;
        }
        Ok(proactor)
    }

    /// Returns the owned ring pointer for explicit FFI integration.
    ///
    /// Returns null after shutdown starts. Dereferencing a nonnull pointer
    /// requires preserving exclusive ring access and
    /// keeping every submitted resource alive until its final completion.
    /// Use this pointer for resource registration only. Preparing, submitting,
    /// or consuming operations through it bypasses lifecycle accounting and
    /// invalidates the proactor's resource-retention guarantees.
    ///
    /// # Panics
    /// Does not panic.
    pub fn ring_mut(&mut self) -> *mut sys::io_uring {
        if self.shutdown_started {
            std::ptr::null_mut()
        } else {
            self.ring.as_mut()
        }
    }

    /// Returns the setup flags and kernel feature bits negotiated at creation.
    ///
    /// # Panics
    /// Does not panic.
    pub fn kernel_features(&self) -> KernelFeatures {
        self.features
    }

    /// Returns a cloneable cross-thread notification endpoint, when enabled.
    ///
    /// # Panics
    /// Does not panic.
    pub fn waker(&self) -> Option<ProactorWaker> {
        self.waker.clone()
    }

    /// Registers a handler for one application subsystem identifier.
    ///
    /// # Errors
    /// Returns an error for an internal or already occupied identifier, or after
    /// shutdown starts.
    ///
    /// # Panics
    /// Does not panic.
    pub fn register_subsystem<H: SubsystemHandler + 'static>(
        &mut self,
        id: SubsystemId,
        handler: H,
    ) -> Result<()> {
        self.ensure_open()?;
        self.registry.register(id, handler)
    }

    /// Prepares an SQE and assigns its canonical completion identifier.
    ///
    /// `prepare` receives a pointer to temporary initialized SQE storage. It must
    /// not retain that pointer. Any unsafe preparation involving DMA, file
    /// descriptors, or external pointers must keep those resources valid until
    /// the operation's final CQE, including during cancellation and shutdown.
    ///
    /// # Errors
    /// Returns `SqRingFull` when both the SQ and bounded staging queue are full,
    /// rejects internal identifiers and the reserved `u64::MAX` timeout sentinel,
    /// completion-skipping and message-ring operations, and shutting-down rings.
    ///
    /// # Panics
    /// Propagates a panic from `prepare` without publishing its partial SQE.
    pub fn prepare_sqe_with<F>(&mut self, op_id: OpId, prepare: F) -> Result<()>
    where
        F: FnOnce(*mut sys::io_uring_sqe),
    {
        if op_id.subsystem_id() == SubsystemId::INTERNAL {
            return Err(UringError::InvalidSubsystemId(0));
        }
        if op_id.raw() == u64::MAX {
            return Err(UringError::InvalidPayload(op_id.raw()));
        }
        self.prepare_internal(op_id, prepare)
    }

    fn prepare_internal<F>(&mut self, op_id: OpId, prepare: F) -> Result<()>
    where
        F: FnOnce(*mut sys::io_uring_sqe),
    {
        self.ensure_open()?;
        if self.staged_sqes.len() == self.config.staged_capacity {
            return Err(UringError::SqRingFull);
        }
        // SAFETY: A zeroed SQE is initialized C storage; the callback sets its operation.
        let mut sqe = unsafe { std::mem::zeroed::<sys::io_uring_sqe>() };
        prepare(&mut sqe);
        validate_prepared_sqe(&sqe)?;
        sqe.user_data = op_id.raw();
        if !self.in_cqe_dispatch && self.staged_sqes.is_empty() && self.copy_to_sq(&sqe) {
            return Ok(());
        }
        if self.staged_sqes.len() == self.config.staged_capacity {
            return Err(UringError::SqRingFull);
        }
        self.staged_sqes.push_back(StagedSqe { sqe });
        Ok(())
    }

    /// Reserves a NOP SQE for later submission.
    ///
    /// # Errors
    /// Returns `SqRingFull` when no submission credit remains.
    ///
    /// # Panics
    /// Does not panic.
    pub fn alloc_sqe(&mut self, op_id: OpId) -> Result<()> {
        self.prepare_sqe_with(op_id, |sqe| {
            // SAFETY: The preparation callback owns initialized, exclusive SQE storage.
            unsafe { sys::uring_shim_prep_nop(sqe) };
        })
    }

    /// Publishes currently available SQEs without waiting for completion.
    ///
    /// Returns the number accepted across bounded kernel enter operations. It
    /// drains available staged work before waiting so an internal poll cannot
    /// strand application submissions behind a full hardware SQ. Kernel CQ
    /// backpressure stops submission so callers can harvest available CQEs.
    ///
    /// # Errors
    /// Returns a submission error or rejects submission during CQE dispatch.
    ///
    /// # Panics
    /// Does not panic.
    pub fn submit(&mut self) -> Result<usize> {
        self.ensure_open()?;
        if self.in_cqe_dispatch {
            return Err(UringError::ReentrantDispatch);
        }
        let mut submitted = 0;
        loop {
            self.flush_staged();
            self.arm_waker()?;
            // SAFETY: The initialized ring is exclusively owned by this thread.
            let result = unsafe { sys::uring_shim_submit(self.ring.as_mut()) };
            if result == -libc::EBUSY || result == -libc::EAGAIN {
                return Ok(submitted);
            }
            if result < 0 {
                return Err(UringError::Submit(-result));
            }
            submitted += result as usize;
            if self.staged_sqes.is_empty() || result == 0 {
                return Ok(submitted);
            }
        }
    }

    /// Harvests up to `max_batch` completions and dispatches registered handlers.
    ///
    /// The observer receives application CQEs after their subsystem handler.
    /// Callback submissions are staged and become eligible after this call.
    /// Internal eventfd completions are consumed without invoking the observer.
    ///
    /// # Errors
    /// Returns dispatch or callback errors, or rejects nested completion dispatch.
    ///
    /// # Panics
    /// Propagates callback panics after restoring the dispatch guard.
    pub fn poll_completions<F>(&mut self, max_batch: usize, mut on_cqe: F) -> Result<usize>
    where
        F: FnMut(Completion, &mut SubmissionContext<'_>) -> Result<()>,
    {
        self.ensure_open()?;
        if self.in_cqe_dispatch {
            return Err(UringError::ReentrantDispatch);
        }
        if self.features.defer_taskrun() {
            // SAFETY: GETEVENTS runs deferred task work on this ring's issuing thread.
            let result = unsafe { sys::io_uring_get_events(self.ring.as_mut()) };
            if result < 0 && result != -libc::EINTR {
                return Err(UringError::Wait(-result));
            }
        }
        self.in_cqe_dispatch = true;
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let mut harvested = 0;
            while harvested < max_batch {
                let mut cqe = std::ptr::null_mut();
                // SAFETY: The ring is initialized and the CQE output pointer is valid.
                let result = unsafe { sys::uring_shim_peek_cqe(self.ring.as_mut(), &mut cqe) };
                if result == -libc::EAGAIN {
                    break;
                }
                if result < 0 {
                    return Err(UringError::Wait(-result));
                }
                if cqe.is_null() {
                    break;
                }
                // SAFETY: A successful peek returns a live CQE until cqe_seen advances it.
                let completion = unsafe {
                    Completion {
                        op_id: OpId::from_raw((*cqe).user_data),
                        result: (*cqe).res,
                        flags: (*cqe).flags,
                    }
                };
                // SAFETY: This CQE belongs to this ring and has been fully copied above.
                unsafe { sys::uring_shim_cqe_seen(self.ring.as_mut(), cqe) };
                if completion.op_id.raw() == u64::MAX {
                    continue;
                }
                harvested += 1;
                if completion.flags & sys::IORING_CQE_F_MORE == 0 {
                    self.pending_operations = self.pending_operations.saturating_sub(1);
                }
                if completion.op_id == INTERNAL_POLL {
                    self.waker_poll_armed = false;
                    if completion.result < 0 {
                        return Err(UringError::Wait(-completion.result));
                    }
                    if let Some(waker) = &self.waker {
                        waker.drain()?;
                    }
                    continue;
                }
                let mut context =
                    SubmissionContext::new(&mut self.staged_sqes, self.config.staged_capacity);
                if self.registry.contains(completion.op_id.subsystem_id()) {
                    self.registry.dispatch(completion, &mut context)?;
                }
                on_cqe(completion, &mut context)?;
            }
            Ok(harvested)
        }));
        self.in_cqe_dispatch = false;
        let result = match outcome {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        };
        self.flush_staged();
        self.arm_waker()?;
        result
    }

    /// Submits pending SQEs and blocks for completion or an optional relative timeout.
    ///
    /// `min_complete` cannot exceed the configured completion batch. Timeout and
    /// interrupted waits still harvest any CQEs already available.
    ///
    /// # Errors
    /// Returns invalid minimum counts, submission, wait, or callback errors.
    ///
    /// # Panics
    /// Propagates callback panics after restoring the dispatch guard.
    pub fn wait_completions<F>(
        &mut self,
        min_complete: u32,
        timeout: Option<Duration>,
        on_cqe: F,
    ) -> Result<usize>
    where
        F: FnMut(Completion, &mut SubmissionContext<'_>) -> Result<()>,
    {
        if min_complete as usize > self.config.max_cqe_batch {
            return Err(UringError::InvalidConfig(
                "minimum completions exceeds batch capacity",
            ));
        }
        self.submit()?;
        let mut cqe = std::ptr::null_mut();
        let mut timespec = timeout.map(|duration| sys::__kernel_timespec {
            tv_sec: duration.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: i64::from(duration.subsec_nanos()),
        });
        let timespec_ptr = timespec
            .as_mut()
            .map_or(std::ptr::null_mut(), |value| value as *mut _);
        // SAFETY: Ring, CQE output, and optional timespec remain valid for this call.
        let result = unsafe {
            sys::uring_shim_submit_and_wait_timeout(
                self.ring.as_mut(),
                &mut cqe,
                min_complete,
                timespec_ptr,
                std::ptr::null_mut(),
            )
        };
        if result < 0
            && result != -libc::ETIME
            && result != -libc::EINTR
            && result != -libc::EAGAIN
            && result != -libc::EBUSY
        {
            return Err(UringError::Wait(-result));
        }
        self.poll_completions(self.config.max_cqe_batch, on_cqe)
    }

    /// Submits and non-blockingly dispatches one configured completion batch.
    ///
    /// # Errors
    /// Returns a submission or registered-handler error.
    ///
    /// # Panics
    /// Propagates a handler panic after restoring the dispatch guard.
    pub fn tick(&mut self) -> Result<usize> {
        self.submit()?;
        self.poll_completions(self.config.max_cqe_batch, |_, _| Ok(()))
    }

    /// Cancels outstanding operations and waits for their own final completions.
    ///
    /// Staged operations are discarded without entering the kernel. Shutdown
    /// never invokes subsystem callbacks. It performs at most 32 bounded waits
    /// of ten milliseconds; retrying after an error continues draining. Once
    /// shutdown starts, application submissions and completion dispatch stop.
    ///
    /// # Errors
    /// Returns cancellation, submission, or drain errors. A failed shutdown does
    /// not establish permission to free externally submitted DMA resources.
    ///
    /// # Panics
    /// Does not panic.
    pub fn shutdown(&mut self) -> Result<()> {
        if self.in_cqe_dispatch {
            return Err(UringError::ReentrantDispatch);
        }
        if self.ring_closed {
            return Ok(());
        }
        self.shutdown_started = true;
        if let Some(waker) = &self.waker {
            waker.close();
        }
        self.staged_sqes.clear();
        if self.pending_operations != 0 {
            // SAFETY: The ring remains initialized and exclusively owned during teardown.
            let submitted = unsafe { sys::uring_shim_submit(self.ring.as_mut()) };
            if submitted < 0 {
                return Err(UringError::Submit(-submitted));
            }
            // SAFETY: No callback is running and exclusive ring SQ access is retained.
            let cancel = unsafe { sys::uring_shim_get_sqe(self.ring.as_mut()) };
            if cancel.is_null() {
                return Err(UringError::SqRingFull);
            }
            // SAFETY: This SQE is exclusive initialized ring storage; cancellation
            // references operation keys rather than dereferencing external memory.
            unsafe {
                sys::uring_shim_prep_cancel64(
                    cancel,
                    0,
                    (sys::IORING_ASYNC_CANCEL_ANY | sys::IORING_ASYNC_CANCEL_ALL) as i32,
                );
                (*cancel).user_data = INTERNAL_CANCEL;
            }
            // SAFETY: The owned ring and cancellation SQE remain live for this call.
            let submitted = unsafe { sys::uring_shim_submit(self.ring.as_mut()) };
            if submitted < 0 {
                return Err(UringError::Submit(-submitted));
            }
            for _ in 0..32 {
                self.drain_shutdown_batch()?;
                if self.pending_operations == 0 {
                    break;
                }
                let mut cqe = std::ptr::null_mut();
                let mut timeout = sys::__kernel_timespec {
                    tv_sec: 0,
                    tv_nsec: 10_000_000,
                };
                // SAFETY: All pointers reference initialized storage for this bounded wait.
                let result = unsafe {
                    sys::uring_shim_wait_cqe_timeout(self.ring.as_mut(), &mut cqe, &mut timeout)
                };
                if result < 0 && result != -libc::ETIME && result != -libc::EINTR {
                    return Err(UringError::Wait(-result));
                }
            }
            self.drain_shutdown_batch()?;
            if self.pending_operations != 0 {
                return Err(UringError::Wait(libc::EBUSY));
            }
        }
        // SAFETY: All tracked operations have delivered their own final CQEs;
        // no submitted external pointer remains reachable by those operations.
        unsafe { sys::uring_shim_queue_exit(self.ring.as_mut()) };
        self.ring_closed = true;
        Ok(())
    }

    fn drain_shutdown_batch(&mut self) -> Result<()> {
        for _ in 0..self.config.max_cqe_batch {
            let mut cqe = std::ptr::null_mut();
            // SAFETY: The initialized ring remains exclusively owned through shutdown.
            let result = unsafe { sys::uring_shim_peek_cqe(self.ring.as_mut(), &mut cqe) };
            if result == -libc::EAGAIN || (result >= 0 && cqe.is_null()) {
                break;
            }
            if result < 0 {
                return Err(UringError::Wait(-result));
            }
            // SAFETY: Successful peek gives a valid CQE until the following cqe_seen.
            let (id, result, flags) = unsafe { ((*cqe).user_data, (*cqe).res, (*cqe).flags) };
            // SAFETY: The CQE belongs to this ring and all required fields were copied.
            unsafe { sys::uring_shim_cqe_seen(self.ring.as_mut(), cqe) };
            if id == u64::MAX {
                continue;
            }
            if id == INTERNAL_CANCEL {
                if result < 0 && result != -libc::ENOENT && result != -libc::EALREADY {
                    return Err(UringError::Wait(-result));
                }
            } else if flags & sys::IORING_CQE_F_MORE == 0 {
                self.pending_operations = self.pending_operations.saturating_sub(1);
            }
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.shutdown_started {
            return Err(UringError::InvalidConfig("ring shutdown has started"));
        }
        Ok(())
    }

    fn copy_to_sq(&mut self, sqe: &sys::io_uring_sqe) -> bool {
        // SAFETY: The initialized ring is exclusively owned; no callback runs here.
        let destination = unsafe { sys::uring_shim_get_sqe(self.ring.as_mut()) };
        if destination.is_null() {
            return false;
        }
        // SAFETY: Source is initialized and destination is exclusive ring SQE storage.
        unsafe { std::ptr::copy_nonoverlapping(sqe, destination, 1) };
        self.pending_operations = self.pending_operations.saturating_add(1);
        true
    }

    fn flush_staged(&mut self) {
        while let Some(staged) = self.staged_sqes.pop_front() {
            if !self.copy_to_sq(&staged.sqe) {
                self.staged_sqes.push_front(staged);
                break;
            }
        }
    }

    fn arm_waker(&mut self) -> Result<()> {
        if self.waker_poll_armed {
            return Ok(());
        }
        let Some(waker) = &self.waker else {
            return Ok(());
        };
        let fd = waker.raw_fd();
        match self.prepare_internal(INTERNAL_POLL, |sqe| {
            // SAFETY: SQE storage is exclusive; the owned eventfd survives ring shutdown.
            unsafe { sys::uring_shim_prep_poll_add(sqe, fd, libc::POLLIN as u32) };
        }) {
            Ok(()) => {
                self.waker_poll_armed = true;
                Ok(())
            }
            Err(UringError::SqRingFull) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl Drop for Proactor {
    fn drop(&mut self) {
        if self.shutdown().is_err() {
            // Failed cancellation cannot prove that handler-owned resources are
            // no longer referenced by the kernel. Preserve that storage.
            std::mem::forget(std::mem::take(&mut self.registry));
            if !self.ring_closed {
                // SAFETY: This ring was initialized and has not yet been closed.
                // Closing stops further submissions; it is not a DMA drain proof.
                unsafe { sys::uring_shim_queue_exit(self.ring.as_mut()) };
                self.ring_closed = true;
            }
        }
    }
}
