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

Default optimized rings pair `DEFER_TASKRUN` with `TASKRUN_FLAG`.
`poll_completions` flushes flagged deferred kernel work and CQ overflow before
reading the CQ, retries interrupted flushes, and defers transient kernel backpressure.
`submit()` publishes staged batches until staging drains or the kernel accepts
no more entries. Thus `submit()` plus `poll_completions()`, or `tick()`, also progresses pending
socket completions. No completion wait is required for this polling mode.
`pending_cancel_count()` reports target-cancel acknowledgments still outstanding;
`is_idle()` requires empty staging, no application operations, no target-cancel
acknowledgments, and no outstanding shutdown-cancel request. `remaining_capacity()`
counts staging credit and reusable slab slots; exhausted generations contribute
no credit.

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

Fixed-buffer checkout and return use a preallocated stack of slot IDs with
`Cell` state; they allocate no storage and perform no runtime borrow checking.

Raw pool APIs expose additional lifetime obligations. In particular,
`Proactor::fixed_buffers` is unsafe: keep all detached handles within the owning
proactor's lifetime and return or transfer them before teardown. Follow each
method's safety contract when managing registration or raw DMA directly.

`shutdown_with(&mut dispatcher)` cancels and drains while preserving caller-owned
state. Teardown callbacks have zero staging credit. `shutdown()` discards
business completions. Teardown errors preserve pending resource ownership rather
than treating an unconfirmed cancellation as permission to recycle DMA storage.
Shutdown drains all ready CQEs regardless of the normal batch limit, sends one
global cancellation request across retries, and bounds only waits without progress.

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

```bash
cargo run -p liburing --example proactor_subsystems
cargo run -p liburing --example fixed_files_and_buffer_ring_tcp_echo
cargo run -p liburing --example completion_socket_io
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
