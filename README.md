# liburing-rs

A single-threaded Linux `io_uring` foundation for completion-driven applications.
The backend is pure Rust, using `io-uring` 0.7.15 to operate mapped submission
and completion rings. Building this workspace requires no native library source,
C compiler, generated bindings, or shim library.

## Why liburing-rs?

Much of Rust's networking ecosystem is built around `async`/`await`, so using
its I/O libraries often means adopting an asynchronous runtime too. That model
works well for servers handling large numbers of concurrent connections. For a
latency-sensitive client, however, executor scheduling, task queues, and waker
handoffs can add variability between an I/O completion and the business code
that needs to act on it. Controlling that path matters when predictable tail
latency is more valuable than general-purpose task scheduling.

Such clients often need nonblocking I/O without a coroutine state machine around
every operation. `liburing-rs` takes a Proactor approach: submit work to the
kernel, collect completions, and advance application state directly. The I/O
remains nonblocking while the application follows ordinary synchronous control
flow. The caller decides when to submit, harvest, and dispatch work, keeping
completion handling close to the decision it enables.

This fits shared-nothing and thread-per-core designs. Each worker owns its own
`Proactor`, which is `!Send + !Sync`, together with its business state. Neither
has to migrate through a work-stealing scheduler or satisfy the
`Send + Sync + 'static` bounds that some multithreaded task APIs impose. Workers
can process local I/O without cross-thread synchronization; applications still
choose how to communicate between workers when communication is needed.

Keeping that ownership model synchronous also avoids function coloring.
Introducing a runtime-bound dependency into a synchronous stack can force
callers to propagate asynchronous signatures or build bridges between two
execution models. Here, submission and completion dispatch use ordinary
function calls throughout the stack. Breakpoints follow those calls and the
explicit state transitions, without stepping through an executor's scheduling
machinery or compiler-generated coroutine resume paths.

The same explicit structure helps with AI-assisted development. Lifetimes
across `.await`, pinning, future types, and task-transfer bounds can make mixed
synchronous and asynchronous code difficult for both engineers and language
models to reason about. A caller-owned Proactor keeps the relevant state,
operation lifetimes, and completion transitions visible at the API boundary.
That gives human reviewers and coding tools a smaller, clearer set of contracts
to check when building and maintaining low-latency clients.

## Design

- One thread owns each `Proactor`, its bounded submission queue, operation slab,
  and registered resources. Worker state and dispatchers remain caller-owned.
- `CompletionDispatcher` uses generic static dispatch. Completion harvesting
  acknowledges each batch with one completion-queue synchronization. Mutable
  borrows of custom dispatchers forward dispatch, including trait objects.
  Closures infer `ClosureDispatch`; wrappers accepting both forms use a
  `D: CompletionDispatcher<Kind>` bound with an inferred `Kind` parameter.
- `OperationSlab<Meta>` holds generation-checked operation metadata through cancellation,
  multishot receives, and zero-copy send notifications.
- `CompletionSocketIo` submits real receives and sends. Received bytes already
  occupy a kernel-selected buffer when the completion reaches the dispatcher.
- Each `Proactor` is an ordinary owned value confined to its creating thread,
  with `!Send + !Sync` enforced by its type. Applications drive it directly.

## Crates

| Crate | Purpose |
| --- | --- |
| `liburing` | Proactor, operation lifetimes, registered resources, completion socket I/O, and static dispatch. |
| `liburing-macros` | `OperationPayloadCodec` derive and validated `define_subsystems!` static routing. |

Source, integration tests, and runnable examples live under
`crates/liburing/{src,tests,examples}/`. Read [AGENTS.md](AGENTS.md) for contributor
instructions and the crate rustdoc for public safety and ownership contracts.

## Quick Start

Borrow worker state through a static dispatcher and submit a NOP:

```rust
use std::time::Duration;
use liburing::{OperationId, OperationPayload, Proactor, Result, SubsystemId, UringError};
use liburing_macros::define_subsystems;

define_subsystems! {
    enum Routes { Network = 1, Storage = 2 }
}

struct Worker { counts: [usize; 2] }

fn main() -> Result<()> {
    let mut proactor = Proactor::builder().entries(16).build()?;
    let mut worker = Worker { counts: [0; 2] };
    let subsystem = SubsystemId::new(Routes::Network.id())
        .ok_or(UringError::InvalidSubsystemId(0))?;
    proactor.alloc_sqe(OperationId::pack(subsystem, OperationPayload::new_unchecked(7)))?;
    {
        let mut dispatcher = Routes::dispatcher(&mut worker, |route, state, cqe, _| {
            state.counts[usize::from(route.id() - 1)] += 1;
            assert_eq!(cqe.result, 0);
            Ok(())
        });
        proactor.wait_completions(1, Some(Duration::from_secs(1)), &mut dispatcher)?;
        proactor.shutdown_with(&mut dispatcher)?;
    }
    assert_eq!(worker.counts, [1, 0]);
    Ok(())
}
```

The macro's `dispatcher(&mut state, callback)` returns a concrete closure that
implements `CompletionDispatcher`. Every declared route shares the same
exclusive state borrow. The callback receives its enum route, worker state,
completion, and `SubmissionContext`; follow-up SQEs enter bounded staging.
Undeclared routes return `InvalidSubsystemId`. Subsystem zero is internal.

`OperationId` preserves `[8-bit SubsystemId | 56-bit OperationPayload]`. Raw preparation helpers
continue accepting `*mut backend::RawSqe`, a checked 64-byte Rust SQE layout.
Referenced buffers and descriptors must outlive the operation's final CQE.

`prepare_keyed_sqe_with(subsystem, prepare)`, `prepare_keyed_buffer_sqe_with`,
and `prepare_keyed_owned_sqe_with` are available on both `Proactor` and
`SubmissionContext`. They return an `operation_slab::OperationKey` and dispatch
`Completion::operation_id = OperationId::pack(subsystem, key.payload())`.
These paths allocate a slab slot without inserting or deleting a caller identity
in the hash table. Retain the returned key for `cancel_key`; caller-identity
lookup APIs apply to the payload-preserving preparation methods.

## Ring modes

`ProactorMode` is chosen once, when the ring opens.

| Mode | Negotiated setup | Owner loop |
| --- | --- | --- |
| `EventDriven(EventDrivenConfig)` | `SINGLE_ISSUER\|COOP_TASKRUN\|DEFER_TASKRUN\|TASKRUN_FLAG`, then `SI\|COOP\|TASKRUN_FLAG`, then `COOP\|TASKRUN_FLAG`, then none | `wait_completions` blocks in the kernel. `no_iowait` skips iowait accounting on Linux 6.15+. `batch_wait_usec` coalesces wakeups on Linux 6.12+. |
| `SqPoll(SqPollConfig)` | `SQPOLL\|SQ_AFF\|SINGLE_ISSUER` only | Spin on `tick`. Kernel thread `iou-sqp-<pid>` consumes SQEs. |
| `IoPoll` | `IOPOLL\|SINGLE_ISSUER\|DEFER_TASKRUN\|TASKRUN_FLAG`, then `IOPOLL\|SINGLE_ISSUER`, then `IOPOLL` | Spin on `tick` for polled `O_DIRECT` reads and writes. |
| `SqPollIoPoll(SqPollConfig)` | `SQPOLL\|SQ_AFF\|IOPOLL\|SINGLE_ISSUER` only | The SQ thread submits and reaps polled block I/O. |

Caller `setup_flags` may add only `CLAMP`, `SUBMIT_ALL`, and `NO_SQARRAY`. The mode
owns the polling and task-run bits. Polling modes require `enable_optimizations`.
SQPOLL modes do not fall back to another mode. Each attempt tries
`SUBMIT_ALL|NO_SQARRAY` first. A successful ring must advertise `EXT_ARG` and
`NODROP`. A `SqPoll` ring must also advertise `SQPOLL_NONFIXED`.

Pin the owner thread to one CPU and set `SqPollConfig::thread_cpu` to a different
CPU. Construction fails when the owner's allowed set is exactly that SQ CPU. The
library does not change the owner's affinity.

The example and benchmark select the first two CPUs in the calling thread's
allowed affinity mask, pin the owner to the first, and place the SQ thread on the
second. An RAII guard restores the original mask. They report a clear error when
fewer than two CPUs are allowed. The library leaves owner affinity to the caller.

| Method | `EventDriven` | `SqPoll` | `IoPoll` | `SqPollIoPoll` |
| --- | --- | --- | --- | --- |
| `submit()` | Publish bounded batches and enter to flush SQEs until blocked. | Publish one bounded pass; wake the SQ thread if needed. | Publish bounded batches and enter with `GETEVENTS` to submit and poll block I/O. | Publish one bounded pass; the SQ thread submits and polls block I/O. |
| `poll_completions()` | Flush flagged task work/overflow and harvest a CQ batch. | Harvest a CQ batch; service flagged task work/overflow. | Enter with `GETEVENTS` when pending I/O has no ready CQE, then harvest. | Harvest a CQ batch while the SQ thread polls; service flagged work/overflow. |
| `wait_completions()` | Publish, wait in the kernel as requested, and harvest. | Only `(0, None)` is allowed and delegates to `tick()`. | Only `(0, None)` is allowed and delegates to `tick()`. | Only `(0, None)` is allowed and delegates to `tick()`. |
| `tick()` | Submit, then harvest one bounded CQ batch. | Publish/wake as needed, then harvest. | Submit and poll pending block I/O, then harvest. | Publish/wake as needed, then harvest while the SQ thread polls. |

In every mode, `submit()` returns the count of SQEs newly published from staging
into the SQ ring during that call. Kernel consumption and previously published
SQEs do not contribute to this count. `EINTR`, `EAGAIN`, and `EBUSY` from
`io_uring_enter` preserve `Ok(published)` and pending SQ entries. They do not
trigger an error-retry loop: bounded batching continues only with visible SQ-head
progress; otherwise flushing is deferred to a later `submit()`, `tick()`, or
eligible wait. An SQ thread reads descriptors and operand bytes after publication,
so those operands remain alive until their terminal CQEs.

`poll_completions()` advances kernel completion work without submitting pending
application SQEs on owner-driven rings. After harvesting, it publishes staging,
including callback follow-up SQEs, in all four modes. In `SqPoll` and
`SqPollIoPoll`, publication also wakes a sleeping SQ thread as needed. In
`EventDriven` and `IoPoll`, call `submit()`, `tick()`, or an eligible wait to flush
those published follow-ups. `DEFER_TASKRUN` is paired with `TASKRUN_FLAG` so
flagged deferred work and CQ overflow are flushed before harvesting.

Calling `wait_completions(min_complete, timeout, ...)` in any busy-polling mode
with `min_complete > 0` or `timeout.is_some()` returns
`Err(UringError::BlockingWaitUnavailable { mode })` before publication or dispatch.
`wait_completions(0, None, ...)` performs a nonblocking tick in every mode.

A fully idle `tick()` performs zero syscalls in `EventDriven` and `SqPoll`
(and in both IOPOLL modes), with no SQ-tail store or `SeqCst` fence. Pending
kernel work or overflow can require an enter even with empty staging. In `IoPoll`,
when `operation_count() > 0`, the CQ is empty, and no SQE needs submission, `tick()`
issues `io_uring_enter(0, 0, IORING_ENTER_GETEVENTS)` to poll the block driver's
completion queues. Private drive strategies are `Interrupt`, `SqThread`, and
`SyscallPoll` for event-driven, SQ-thread, and owner-polled modes respectively.

`OpcodeSet::IOPOLL` admits NOP and polled read/write opcodes. `IoPoll` and
`SqPollIoPoll` reject sockets, timers, and cancellation. An `IOPOLL` ring and a
successful NOP establish ring support; actual `O_DIRECT` reads and writes also
require hardware poll queues on the backing block device and filesystem support.
For NVMe, enable queues with `nvme.poll_queues=N` and check
`/sys/block/<dev>/queue/io_poll == 1`. Without that support, real I/O can complete
with `-EOPNOTSUPP` even though ring setup and NOP succeed.

An unallocated sparse-file hole can take a kernel zero-fill shortcut and does
not verify device polling. `DirectFile::supports_polled_io()` checks the backing
queue's advertised `io_poll` capability through sysfs, using `st_rdev` for raw
block devices and the filesystem's `st_dev` for regular files. Qualify the complete path
with a real preallocated, initialized `O_DIRECT` polled read on the target device.
Construction checks `O_DIRECT` and alignment; advertised capability alone does
not prove that a specific filesystem/device read succeeds.

`pending_cancel_count()` counts target-cancel acknowledgments still outstanding.
`is_idle()` requires empty staging, no application operations, no target-cancel
acknowledgments, and no outstanding shutdown-cancel request. `remaining_capacity()`
counts staging credit and reusable slab slots; exhausted generations give no credit.

## Operation and Buffer Ownership

`OperationSlab<Meta>` preallocates a fixed number of slots. `OperationKey` encodes a 24-bit
slot and a 32-bit generation in the 56-bit payload. `available()` excludes both
occupied and permanently retired slots. Slot generations never wrap
back to a previously valid key. Completion marks a slot terminal; explicit
removal retires its metadata and permits reuse.

Cancellation changes the target state to `Canceling`. The cancel request and
its target have independent completions: a cancel acknowledgement cannot release
the target's memory. A zero-copy send can enter `AwaitingZeroCopyNotification` after its main
completion and remains retained until the required notification. Multishot
operations remain live while the kernel sets the continuation flag.

`Proactor` owns configured fixed buffers, fixed-file registrations, and provided
buffer groups. `CompletionSocketIo` retains socket descriptors and fixed send
memory through their final completions. `ReceiveMode::Once` and `Multishot` use
buffer selection; `SocketEvent::Received` delivers a `BufferLease` whose drop
returns its buffer. Send events distinguish bytes sent from zero-copy memory
release. Applications handle partial sends and retry depleted receives after
leases return. Completion dispatchers use `receive_with_context` and
`send_with_context` to stage follow-up socket work through `SubmissionContext`
after returning any selected receive lease. `BufferRing` and
`BufferLease` are also exported from the crate root.

`FixedBufferPool::new(ring, buffer_count, buffer_len)` provides 4096-byte-aligned
storage for direct I/O. `FixedBufferPool::with_alignment(ring, buffer_count,
buffer_len, alignment)` selects an explicit power-of-two alignment. The raw `ring`
argument is a live `*mut IoUring` and both constructors are unsafe: their pool and
detached-handle lifetimes must remain within the ring's lifetime.
`Proactor::configure_direct_buffers(count, buffer_len, alignment)` registers
an aligned proactor-owned pool and returns `Result<()>`.

`DirectFile::open(path: &Path, access: DirectAccess) -> Result<DirectFile>` accepts
`DirectAccess::ReadOnly` or `DirectAccess::ReadWrite`.
`DirectFile::from_owned_fd(fd: OwnedFd) -> Result<DirectFile>` takes an existing
descriptor. Both constructors validate `O_DIRECT` and query direct-I/O alignment.
`read_fixed` and `write_fixed` retain the descriptor and in-flight buffer through
its terminal completion; their `_with_context` variants stage callback follow-ups.
Buffers, lengths, and offsets must meet file alignment. Raw `ops::fs` helpers are
`prep_read`, `prep_write`, `prep_readv`, `prep_writev`, `prep_read_fixed`,
`prep_write_fixed`, `prep_readv_fixed`, and `prep_writev_fixed`; callers retain all
raw pointer operands and vector descriptors through the final completion.
The scalar helpers `prep_read`, `prep_write`, `prep_read_fixed`, and
`prep_write_fixed` take `len: u32`; convert larger host lengths with
`u32::try_from` before preparation. `DirectFile` performs that checked conversion.
For `prep_readv_fixed` and `prep_writev_fixed`, the iovec descriptor array may live
in ordinary user memory. Keep it readable and immutable through kernel
submission, which can occur after `submit()` returns under SQPOLL; retaining it
through the final CQE is sufficient. Each described payload range must lie within
the one registered buffer at `buf_index`. Those ranges remain valid through the
final CQE, exclusively writable for reads and readable/immutable for writes.

Fixed-buffer checkout and return use a preallocated stack of slot IDs with
`Cell` state; they allocate no storage and perform no runtime borrow checking.

Raw pool APIs expose additional lifetime obligations. In particular,
`Proactor::fixed_buffers` is unsafe: keep all detached handles within the owning
proactor's lifetime and return or transfer them before teardown. Follow each
method's safety contract when managing registration or raw DMA directly.

`shutdown_with(&mut dispatcher)` delivers teardown completions through caller-owned
state; `shutdown()` discards business completions. Both discard unpublished
staging locally with synthetic `-ECANCELED` completions and zero callback staging
credit. Published targets drain naturally in IOPOLL modes; `EventDriven` and
`SqPoll` issue one global cancellation request across retries. All ready CQEs are
drained regardless of the normal batch limit.

The default consecutive stall budget is 320ms for `EventDriven` and `SqPoll`, and
5s for `IoPoll` and `SqPollIoPoll`. `shutdown_stall_timeout` overrides it; every
harvested CQE resets the stall timer. `IoPoll` retries unconsumed SQ entries and
uses user-space `spin_loop()` after polling. The other three modes use internal
`kernel_wait_private` waits of 10ms per idle pass. This is a no-progress budget,
not a bound on total teardown time while completions keep arriving.

If the kernel/device stops completing targets for the configured budget,
`shutdown()` returns `Err(UringError::Wait(libc::ETIMEDOUT))`. Pending operation
metadata, DMA buffers, and retained descriptors remain owned for a safe retry.
`Drop` invokes `shutdown()` on the owner thread and can spend the same stall
budget. If teardown still fails, it intentionally leaks the pending resource
and operation owners rather than free memory the kernel may still access.
An unconfirmed cancellation never permits DMA reuse.

On the supported Linux x86_64 target, the buffer-ring tail and descriptor fields
use aligned volatile accesses. A compiler memory barrier precedes tail publication,
keeping initialized descriptors visible to the kernel before it observes the tail.

## Examples

Examples use real kernel I/O and local sockets or descriptors, check results,
print a summary, and exit. Required kernel capabilities fail visibly.

| Example | Demonstrates |
| --- | --- |
| `proactor_subsystems` | Shared worker routing, callback staging, and shutdown through caller-owned state. |
| `fixed_files_and_buffer_ring_tcp_echo` | Fixed-file growth, direct close, fixed sends, and multishot receive buffer recovery. |
| `completion_socket_io` | TCP and Unix receive/send completions, zero-copy release, and socket close. |
| `proactor_modes` | Event-driven blocking wait, warm SQPOLL NOPs with no additional enters, five drive counters, affinity selection, and IOPOLL shutdown. |

```bash
cargo run -p liburing-proactor --example proactor_subsystems
cargo run -p liburing-proactor --example fixed_files_and_buffer_ring_tcp_echo
cargo run -p liburing-proactor --example completion_socket_io
cargo run -p liburing-proactor --example proactor_modes
```

## Build and Test

Requires Linux with permitted `io_uring`, the pinned Rust toolchain, and kernel
support for the operations being exercised. The crate exposes one pure Rust backend.

```bash
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

GitHub-hosted CI executes these Cargo checks directly. Review dependencies,
source vocabulary, ASCII text, and authored file sizes when changing the source.
Generated lockfiles retain Cargo's native format and are exempt from the
800-line authored-file bound. Macro rejection cases compile
as rustdoc examples. Tests cover routing, cancellation ordering, buffer lifetime,
socket I/O, bounded control queues, and shutdown against real kernel rings.
