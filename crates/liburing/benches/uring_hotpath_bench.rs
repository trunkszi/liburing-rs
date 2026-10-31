//! Hot-path latency for slab completion, payload packing, leases, and dispatch.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs::File,
    hint::black_box,
    net::{TcpListener, TcpStream},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use criterion::{Criterion, criterion_group};
use io_uring::IoUring;
use liburing::{
    Completion, OperationId, OperationPayload, Proactor, ProactorBuilder, ProactorConfig,
    ProactorMode, SubmissionContext, SubsystemId,
    backend::{IORING_CQE_F_MORE, IORING_CQE_F_NOTIF},
    fixed_buffers::FixedBufferPool,
    fixed_files::FixedFileTable,
    operation_slab::{OperationKind, OperationSlab, OperationState},
    socket_io::{CompletionSocketIo, ReceiveMode, SocketEvent, SocketId, SocketIoConfig},
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

fn mode_proactor(mode: ProactorMode) -> Proactor {
    must(
        ProactorBuilder::new()
            .entries(128)
            .cq_entries(1024)
            .mode(mode)
            .build(),
    )
}

fn idle_ticks(proactor: &mut Proactor, label: &str) {
    let before_enter = proactor.stats().enter_calls;
    assert_zero_alloc(label, || {
        for _ in 0..1000 {
            black_box(must(proactor.tick(&mut ignore_completion)));
        }
    });
    assert_eq!(
        proactor.stats().enter_calls,
        before_enter,
        "{label} entered the kernel"
    );
}

fn nop_once(proactor: &mut Proactor, spin_wait: bool, payload: u64) {
    let id = OperationId::pack(
        SubsystemId::new_unchecked(1),
        OperationPayload::new_unchecked(payload),
    );
    must(proactor.alloc_sqe(id));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut seen = false;
        let mut dispatch = |completion: Completion, _context: &mut SubmissionContext<'_>| {
            seen = completion.result == 0;
            Ok(())
        };
        if spin_wait {
            must(proactor.tick(&mut dispatch));
        } else {
            must(proactor.wait_completions(1, Some(Duration::from_millis(20)), &mut dispatch));
        }
        if seen {
            return;
        }
        assert!(Instant::now() < deadline, "nop round trip timed out");
        if spin_wait {
            core::hint::spin_loop();
        }
    }
}

fn percentile(samples: &[u128], quantile: f64) -> u128 {
    let index = ((samples.len() - 1) as f64 * quantile).round() as usize;
    samples[index]
}

fn print_percentiles(label: &str, samples: &mut [u128]) {
    samples.sort_unstable();
    println!(
        "{label} ns p50={} p90={} p99={} p99.9={}",
        percentile(samples, 0.50),
        percentile(samples, 0.90),
        percentile(samples, 0.99),
        percentile(samples, 0.999)
    );
}

fn time_nops(proactor: &mut Proactor, spin_wait: bool, samples: &mut [u128]) {
    for (index, sample) in samples.iter_mut().enumerate() {
        let started = Instant::now();
        nop_once(proactor, spin_wait, index as u64 + 1);
        *sample = started.elapsed().as_nanos();
    }
}

struct PingSeen {
    ping: bool,
    pong: bool,
}

fn drive_socket(
    proactor: &mut Proactor,
    io: &mut CompletionSocketIo,
    spin: bool,
    seen: &mut PingSeen,
    until_pong: bool,
) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let done = if until_pong { seen.pong } else { seen.ping };
        if done {
            return;
        }
        assert!(Instant::now() < deadline, "tcp ping timed out");
        let mut dispatch = |completion, context: &mut SubmissionContext<'_>| {
            io.on_completion(completion, context, |event| {
                if let SocketEvent::Received { data, .. } = event {
                    if &*data == b"ping" {
                        seen.ping = true;
                    } else if &*data == b"pong" {
                        seen.pong = true;
                    }
                }
                Ok(())
            })
        };
        if spin {
            must(proactor.tick(&mut dispatch));
            core::hint::spin_loop();
        } else {
            must(proactor.wait_completions(1, Some(Duration::from_millis(20)), &mut dispatch));
        }
    }
}

fn tcp_pair() -> (OwnedFd, OwnedFd) {
    let listener = must(TcpListener::bind("127.0.0.1:0"));
    let client = must(TcpStream::connect(must(listener.local_addr())));
    let (server, _) = must(listener.accept());
    must(client.set_nodelay(true));
    must(server.set_nodelay(true));
    (client.into(), server.into())
}

fn ping_pong(
    proactor: &mut Proactor,
    io: &mut CompletionSocketIo,
    client: SocketId,
    server: SocketId,
    spin: bool,
) {
    let mut seen = PingSeen {
        ping: false,
        pong: false,
    };
    must(io.receive(proactor, server, ReceiveMode::Once));
    must(io.receive(proactor, client, ReceiveMode::Once));
    must(io.send(proactor, client, b"ping", false));
    drive_socket(proactor, io, spin, &mut seen, false);
    assert!(seen.ping, "server missed ping");
    must(io.send(proactor, server, b"pong", false));
    drive_socket(proactor, io, spin, &mut seen, true);
}

fn socket_engine(proactor: &mut Proactor) -> CompletionSocketIo {
    must(CompletionSocketIo::new(
        proactor,
        SocketIoConfig {
            sockets: 4,
            operations: 32,
            receive_buffers: 8,
            send_buffers: 4,
            buffer_len: 64,
            ..SocketIoConfig::default()
        },
    ))
}

fn ignore_completion(
    _completion: Completion,
    _context: &mut SubmissionContext<'_>,
) -> liburing::Result<()> {
    Ok(())
}

struct Affinity {
    original: Vec<usize>,
}

impl Affinity {
    fn pin_pair() -> liburing::Result<(Self, u32, u32)> {
        let mut mask = vec![0usize; 16];
        loop {
            // SAFETY: The aligned initialized mask covers the writable byte extent.
            // pid zero queries this owner thread and no pointer escapes the call.
            if unsafe {
                libc::sched_getaffinity(
                    0,
                    std::mem::size_of_val(mask.as_slice()),
                    mask.as_mut_ptr().cast(),
                )
            } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) || mask.len() >= 1 << 14 {
                return Err(error.into());
            }
            mask.resize(mask.len() * 2, 0);
        }
        let mut cpus = mask.iter().enumerate().flat_map(|(index, word)| {
            (0..usize::BITS).filter_map(move |bit| {
                (word & (1usize << bit) != 0)
                    .then_some((index * usize::BITS as usize + bit as usize) as u32)
            })
        });
        let (Some(owner), Some(sq_cpu)) = (cpus.next(), cpus.next()) else {
            return Err(liburing::UringError::InvalidConfig(
                "SQPOLL examples and benchmarks require two allowed CPUs",
            ));
        };
        let mut pinned = vec![0usize; mask.len()];
        pinned[owner as usize / usize::BITS as usize] = 1usize << (owner % usize::BITS);
        let guard = Self { original: mask };
        // SAFETY: The word-aligned readable mask spans the supplied byte extent.
        // The selected owner CPU belongs to the captured mask of this thread.
        if unsafe {
            libc::sched_setaffinity(
                0,
                std::mem::size_of_val(pinned.as_slice()),
                pinned.as_ptr().cast(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((guard, owner, sq_cpu))
    }
}

impl Drop for Affinity {
    fn drop(&mut self) {
        // SAFETY: The captured initialized mask remains readable for its full
        // extent and restores only this calling thread's original affinity.
        let restored = unsafe {
            libc::sched_setaffinity(
                0,
                std::mem::size_of_val(self.original.as_slice()),
                self.original.as_ptr().cast(),
            )
        };
        assert_eq!(
            restored,
            0,
            "affinity restoration failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn preflight_modes() {
    let (_affinity, _, sq_cpu) = must(Affinity::pin_pair());
    let mut event = mode_proactor(ProactorMode::event_driven());
    idle_ticks(&mut event, "event-driven idle tick");
    let mut event_samples = [0_u128; 256];
    time_nops(&mut event, true, &mut event_samples);
    print_percentiles("event-driven nop rtt", &mut event_samples);
    must(event.shutdown());

    let mut sq = mode_proactor(ProactorMode::sq_poll(sq_cpu));
    idle_ticks(&mut sq, "sq-poll idle tick");
    for payload in 1..=16 {
        nop_once(&mut sq, true, payload);
    }
    let baseline_enters = sq.stats().enter_calls;
    assert_zero_alloc("sq-poll warm nop", || nop_once(&mut sq, true, 17));
    let mut sq_samples = [0_u128; 256];
    time_nops(&mut sq, true, &mut sq_samples);
    assert_eq!(
        sq.stats().enter_calls,
        baseline_enters,
        "warm sq-poll rtt entered kernel"
    );
    print_percentiles("sq-poll nop rtt", &mut sq_samples);
    must(sq.shutdown());

    let mut polled = mode_proactor(ProactorMode::io_poll());
    idle_ticks(&mut polled, "io-poll idle tick");
    must(polled.shutdown());

    let (client, server) = tcp_pair();
    let mut event = mode_proactor(ProactorMode::event_driven());
    let mut io = socket_engine(&mut event);
    let client_id = must(io.insert(client));
    let server_id = must(io.insert(server));
    assert_zero_alloc("event-driven tcp ping", || {
        ping_pong(&mut event, &mut io, client_id, server_id, false);
    });
    let mut tcp_samples = [0_u128; 64];
    for sample in &mut tcp_samples {
        let started = Instant::now();
        ping_pong(&mut event, &mut io, client_id, server_id, false);
        *sample = started.elapsed().as_nanos();
    }
    print_percentiles("event-driven tcp ping-pong", &mut tcp_samples);
    must(io.close(&mut event, client_id));
    must(io.close(&mut event, server_id));
    must(event.shutdown());

    let (client, server) = tcp_pair();
    let mut sq = mode_proactor(ProactorMode::sq_poll(sq_cpu));
    let mut io = socket_engine(&mut sq);
    let client_id = must(io.insert(client));
    let server_id = must(io.insert(server));
    ping_pong(&mut sq, &mut io, client_id, server_id, true);
    let warmed = sq.stats().enter_calls;
    assert_zero_alloc("sq-poll tcp ping", || {
        ping_pong(&mut sq, &mut io, client_id, server_id, true);
    });
    assert_eq!(sq.stats().enter_calls, warmed, "sq-poll tcp ping entered");
    let mut tcp_samples = [0_u128; 64];
    for sample in &mut tcp_samples {
        let started = Instant::now();
        ping_pong(&mut sq, &mut io, client_id, server_id, true);
        *sample = started.elapsed().as_nanos();
    }
    print_percentiles("sq-poll tcp ping-pong", &mut tcp_samples);
    must(io.close(&mut sq, client_id));
    must(io.close(&mut sq, server_id));
    must(sq.shutdown());
}

fn bench_modes(c: &mut Criterion) {
    let (_affinity, _, sq_cpu) = must(Affinity::pin_pair());
    let mut group = c.benchmark_group("proactor_mode");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(20));
    group.measurement_time(Duration::from_millis(100));
    let mut event = mode_proactor(ProactorMode::event_driven());
    group.bench_function("idle_tick_event_driven", |b| {
        b.iter(|| black_box(must(event.tick(&mut ignore_completion))));
    });
    let mut payload = 10_u64;
    group.bench_function("nop_rtt_event_driven", |b| {
        b.iter(|| {
            payload = payload.wrapping_add(1);
            nop_once(&mut event, true, payload);
        });
    });
    must(event.shutdown());
    let mut sq = mode_proactor(ProactorMode::sq_poll(sq_cpu));
    group.bench_function("idle_tick_sq_poll", |b| {
        b.iter(|| black_box(must(sq.tick(&mut ignore_completion))));
    });
    group.bench_function("nop_rtt_sq_poll", |b| {
        b.iter(|| {
            payload = payload.wrapping_add(1);
            nop_once(&mut sq, true, payload);
        });
    });
    must(sq.shutdown());
    let mut polled = mode_proactor(ProactorMode::io_poll());
    group.bench_function("idle_tick_io_poll", |b| {
        b.iter(|| black_box(must(polled.tick(&mut ignore_completion))));
    });
    must(polled.shutdown());
    group.finish();
}

fn preflight() {
    preflight_slab();
    preflight_payload();
    preflight_proactor();
    preflight_buffers();
    preflight_files();
    preflight_socket();
    preflight_modes();
}

criterion_group!(
    hotpath,
    bench_slab,
    bench_payload,
    bench_proactor,
    bench_buffers,
    bench_files,
    bench_socket,
    bench_modes
);

fn main() {
    preflight();
    hotpath();
}
