//! Hot-path latency for slab completion, payload packing, leases, and dispatch.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs::File,
    hint::black_box,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use criterion::{Criterion, criterion_group};
use io_uring::IoUring;
use liburing::{
    Completion, OperationId, OperationPayload, Proactor, ProactorConfig, SubmissionContext,
    SubsystemId,
    backend::{IORING_CQE_F_MORE, IORING_CQE_F_NOTIF},
    fixed_buffers::FixedBufferPool,
    fixed_files::FixedFileTable,
    operation_slab::{OperationKind, OperationSlab, OperationState},
    socket_io::{CompletionSocketIo, ReceiveMode, SocketIoConfig},
};

struct CountingAllocator {
    allocations: AtomicUsize,
}

// SAFETY: Each method forwards to the system allocator and only increments an
// atomic counter. Pointers, alignment, and deallocation layouts remain those
// of `System`, so the `GlobalAlloc` contract is preserved.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocations.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller supplies a valid layout for a fresh allocation.
        unsafe { System.alloc(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.allocations.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller retains the pointer previously returned by this allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The caller owns this allocation and passes its original layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator {
    allocations: AtomicUsize::new(0),
};

fn must<T, E: core::fmt::Debug>(value: Result<T, E>) -> T {
    match value {
        Ok(value) => value,
        Err(error) => panic!("hot-path benchmark failed: {error:?}"),
    }
}

fn assert_zero_alloc(label: &str, body: impl FnOnce()) {
    let before = ALLOCATOR.allocations.load(Ordering::Relaxed);
    body();
    let after = ALLOCATOR.allocations.load(Ordering::Relaxed);
    assert_eq!(before, after, "{label} allocated on the hot path");
}

fn preflight_slab() {
    let mut slab = must(OperationSlab::new(8));
    assert_zero_alloc("operation slab single", || {
        let id = must(slab.insert(1_u64, OperationKind::Single));
        assert!(must(slab.complete(id, 0, 0)));
        assert_eq!(must(slab.remove(id)), 1);
    });
    assert_zero_alloc("operation slab multishot", || {
        let id = must(slab.insert(2_u64, OperationKind::Multishot));
        assert!(!must(slab.complete(id, 4, IORING_CQE_F_MORE)));
        assert_eq!(must(slab.state(id)), OperationState::InFlight);
        assert!(must(slab.complete(id, 0, 0)));
        assert_eq!(must(slab.remove(id)), 2);
    });
    assert_zero_alloc("operation slab zero-copy", || {
        let id = must(slab.insert(3_u64, OperationKind::ZeroCopy));
        assert!(!must(slab.complete(id, 8, IORING_CQE_F_MORE)));
        assert_eq!(
            must(slab.state(id)),
            OperationState::AwaitingZeroCopyNotification
        );
        assert!(must(slab.complete(id, 0, IORING_CQE_F_NOTIF)));
        assert_eq!(must(slab.remove(id)), 3);
        let id = must(slab.insert(4_u64, OperationKind::ZeroCopy));
        assert!(!must(slab.complete(id, 0, IORING_CQE_F_NOTIF)));
        assert!(must(slab.complete(id, 8, 0)));
        assert_eq!(must(slab.remove(id)), 4);
    });
    assert_zero_alloc("operation slab cancel", || {
        let id = must(slab.insert(5_u64, OperationKind::Single));
        must(slab.mark_canceling(id));
        assert_eq!(must(slab.state(id)), OperationState::Canceling);
        assert!(must(slab.complete(id, -125, 0)));
        assert_eq!(must(slab.remove(id)), 5);
    });
}

fn preflight_payload() {
    let packed = OperationId::pack(
        SubsystemId::new_unchecked(9),
        OperationPayload::new_unchecked(0x00ab_cdef),
    );
    assert_zero_alloc("operation payload pack", || {
        let encoded = OperationId::pack(packed.subsystem_id(), packed.payload());
        let (subsystem, payload) = encoded.unpack();
        black_box((encoded.raw(), subsystem.raw(), payload.raw()));
    });
}

fn drain_one(proactor: &mut Proactor) {
    let mut seen = 0;
    let deadline = Instant::now() + Duration::from_secs(2);
    while seen == 0 {
        assert!(Instant::now() < deadline, "proactor dispatch timed out");
        must(proactor.poll_completions(
            4,
            &mut |completion: Completion, _context: &mut SubmissionContext<'_>| {
                seen += 1;
                black_box(completion.result);
                Ok(())
            },
        ));
    }
}

fn preflight_proactor() {
    let mut proactor = must(Proactor::new(ProactorConfig {
        entries: 16,
        staged_capacity: 32,
        operation_capacity: 32,
        ..ProactorConfig::default()
    }));
    let id = OperationId::pack(
        SubsystemId::new_unchecked(1),
        OperationPayload::new_unchecked(1),
    );
    assert_zero_alloc("proactor stage", || {
        must(proactor.alloc_sqe(id));
        black_box(must(proactor.operation_key(id)).payload().raw());
    });
    black_box(must(proactor.submit()));
    drain_one(&mut proactor);
    assert_eq!(proactor.operation_count(), 0);
    must(proactor.shutdown());
}

fn preflight_buffers() {
    let mut ring = must(IoUring::new(8));
    // SAFETY: This ring outlives the pool and this thread owns its registration.
    let pool = must(unsafe { FixedBufferPool::new(&mut ring, 4, 32) });
    assert_zero_alloc("fixed buffer lease", || {
        let handle = must(pool.checkout());
        let waiting = handle.into_in_flight();
        // SAFETY: No SQE was published, so the kernel cannot access this buffer.
        let handle = must(unsafe { waiting.complete() });
        drop(handle);
        black_box(pool.available());
    });
}

fn preflight_files() {
    let mut ring = must(IoUring::new(8));
    // SAFETY: This ring outlives the table and this thread owns its registration.
    let mut files = must(unsafe { FixedFileTable::new(&mut ring, 4) });
    let null = must(File::open("/dev/null"));
    assert_zero_alloc("fixed file lease", || {
        let slot = must(files.insert(null.as_raw_fd()));
        black_box(files.get(slot));
        black_box(must(files.remove(slot)));
    });
}

fn socket_io() -> (Proactor, CompletionSocketIo) {
    let mut proactor = must(Proactor::new(ProactorConfig {
        entries: 16,
        ..ProactorConfig::default()
    }));
    let io = must(CompletionSocketIo::new(
        &mut proactor,
        SocketIoConfig {
            sockets: 4,
            operations: 16,
            receive_buffers: 4,
            send_buffers: 2,
            buffer_len: 64,
            ..SocketIoConfig::default()
        },
    ));
    (proactor, io)
}

fn preflight_socket() {
    let (mut proactor, mut io) = socket_io();
    let (local, _peer) = must(UnixStream::pair());
    let idle = must(io.insert(local.into()));
    assert_zero_alloc("socket idle close", || {
        must(io.close(&mut proactor, idle));
    });
    assert_eq!(io.socket_count(), 0);
    let (local, _peer) = must(UnixStream::pair());
    let draining = must(io.insert(local.into()));
    let _receive = must(io.receive(&mut proactor, draining, ReceiveMode::Once));
    assert_zero_alloc("socket drain transition", || {
        must(io.close(&mut proactor, draining));
    });
    assert_eq!(io.socket_count(), 1);
    let deadline = Instant::now() + Duration::from_secs(2);
    while io.operation_count() != 0 {
        assert!(Instant::now() < deadline, "socket drain timed out");
        must(proactor.wait_completions(
            1,
            Some(Duration::from_millis(20)),
            &mut |completion, context: &mut SubmissionContext<'_>| {
                io.on_completion(completion, context, |_| Ok(()))
            },
        ));
    }
    must(proactor.shutdown());
}

fn bench_slab(c: &mut Criterion) {
    let mut slab = must(OperationSlab::<u64>::new(1024));
    c.bench_function("operation_slab_single", |b| {
        b.iter(|| {
            let id = must(slab.insert(black_box(1), OperationKind::Single));
            black_box(must(slab.complete(id, 0, 0)));
            black_box(must(slab.remove(id)));
        });
    });
    c.bench_function("operation_slab_multishot", |b| {
        b.iter(|| {
            let id = must(slab.insert(black_box(1), OperationKind::Multishot));
            black_box(must(slab.complete(id, 4, IORING_CQE_F_MORE)));
            black_box(must(slab.complete(id, 0, 0)));
            black_box(must(slab.remove(id)));
        });
    });
    c.bench_function("operation_slab_zero_copy", |b| {
        b.iter(|| {
            let id = must(slab.insert(black_box(1), OperationKind::ZeroCopy));
            black_box(must(slab.complete(id, 8, IORING_CQE_F_MORE)));
            black_box(must(slab.complete(id, 0, IORING_CQE_F_NOTIF)));
            black_box(must(slab.remove(id)));
        });
    });
    c.bench_function("operation_slab_cancel", |b| {
        b.iter(|| {
            let id = must(slab.insert(black_box(1), OperationKind::Single));
            must(slab.mark_canceling(id));
            black_box(must(slab.state(id)));
            black_box(must(slab.complete(id, -125, 0)));
            black_box(must(slab.remove(id)));
        });
    });
}

fn bench_payload(c: &mut Criterion) {
    c.bench_function("operation_payload_pack", |b| {
        b.iter(|| {
            let id = OperationId::pack(
                SubsystemId::new_unchecked(black_box(4)),
                OperationPayload::new_unchecked(black_box(0x55aa)),
            );
            let (subsystem, payload) = id.unpack();
            black_box((id.raw(), subsystem.raw(), payload.raw()));
        });
    });
}

fn bench_proactor(c: &mut Criterion) {
    let mut proactor = must(Proactor::new(ProactorConfig {
        entries: 32,
        staged_capacity: 64,
        operation_capacity: 64,
        ..ProactorConfig::default()
    }));
    let mut payload = 1_u64;
    c.bench_function("proactor_submit_dispatch", |b| {
        b.iter(|| {
            payload = payload.wrapping_add(1);
            let id = OperationId::pack(
                SubsystemId::new_unchecked(1),
                OperationPayload::new_unchecked(payload),
            );
            must(proactor.alloc_sqe(id));
            black_box(must(proactor.operation_key(id)).payload().raw());
            black_box(must(proactor.submit()));
            drain_one(&mut proactor);
        });
    });
    must(proactor.shutdown());
}

fn bench_buffers(c: &mut Criterion) {
    let mut ring = must(IoUring::new(8));
    // SAFETY: This ring outlives the pool and this thread owns its registration.
    let pool = must(unsafe { FixedBufferPool::new(&mut ring, 8, 64) });
    c.bench_function("fixed_buffer_lease_release", |b| {
        b.iter(|| {
            let handle = must(pool.checkout());
            let waiting = handle.into_in_flight();
            // SAFETY: No SQE was published, so the kernel cannot access this buffer.
            let handle = must(unsafe { waiting.complete() });
            drop(handle);
        });
    });
}

fn bench_files(c: &mut Criterion) {
    let mut ring = must(IoUring::new(8));
    // SAFETY: This ring outlives the table and this thread owns its registration.
    let mut files = must(unsafe { FixedFileTable::new(&mut ring, 8) });
    let null = must(File::open("/dev/null"));
    c.bench_function("fixed_file_lease_release", |b| {
        b.iter(|| {
            let slot = must(files.insert(null.as_raw_fd()));
            black_box(files.get(slot));
            black_box(must(files.remove(slot)));
        });
    });
}

fn bench_socket(c: &mut Criterion) {
    let (mut proactor, mut io) = socket_io();
    c.bench_function("completion_socket_hsm_close", |b| {
        b.iter(|| {
            let (local, _peer) = must(UnixStream::pair());
            let socket = must(io.insert(local.into()));
            must(io.close(&mut proactor, socket));
            black_box(io.socket_count());
        });
    });
    must(proactor.shutdown());
}

fn preflight() {
    preflight_slab();
    preflight_payload();
    preflight_proactor();
    preflight_buffers();
    preflight_files();
    preflight_socket();
}

criterion_group!(
    hotpath,
    bench_slab,
    bench_payload,
    bench_proactor,
    bench_buffers,
    bench_files,
    bench_socket
);

fn main() {
    preflight();
    hotpath();
}
