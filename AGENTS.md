# Agent Guide

Operational instructions for coding agents working in `liburing-rs`.
Use this file as the repository authority, [README.md](README.md) for setup and
examples, and crate rustdoc for public API and safety contracts. These
instructions apply equally to Claude Code, OpenAI Codex, and Gemini CLI.

## Before Editing

Inspect the worktree and relevant staged and unstaged differences. Preserve
concurrent changes and work within the assigned files. Only create commits or
publish when requested. Review the changed paths and `git diff --check` before
reporting completion.

This Linux, Rust 2024 workspace has two crates:

| Path | Responsibility |
| --- | --- |
| `crates/liburing` | Pure Rust ring ownership, bounded staging, operation lifetimes, registered resources, socket I/O, and completion dispatch. |
| `crates/liburing-macros` | Payload derives, validated subsystem IDs, and static shared-worker dispatch generation. |

Runtime implementations are under `crates/liburing/src/`, kernel regression tests
under `crates/liburing/tests/`, and runnable programs under
`crates/liburing/examples/`. Shared dependencies belong in the root
`[workspace.dependencies]`; member manifests inherit them using single-line
inline tables. Keep inherited workspace lints and profiles.

## Ownership and Dispatch

- Each `Proactor` and its ring-owned resources stay on the creating thread.
  Keep it an ordinary owned value with `!Send + !Sync`; callers drive it directly.
  Preserve per-instance state and explicit caller-owned dispatch.
- Business state and completion dispatchers remain caller-owned. Use generic
  `CompletionDispatcher` dispatch; closures implement the trait. The
  `define_subsystems!` macro's `dispatcher(&mut worker, callback)` shares an
  exclusive worker borrow across a static match on declared routing bytes.
- Public `OperationId` values preserve an 8-bit subsystem and 56-bit payload. Subsystem
  zero is internal. The runtime separately tracks operation keys and restores
  the application's original identity before delivering a completion.
- `poll_completions`, `wait_completions`, and `tick` take `&mut dispatcher`.
  Callback follow-up work goes through `SubmissionContext::prepare_sqe_with`.
  Staging is bounded; exhausting its preallocated credits returns `SqRingFull`.
  Preserve accepted FIFO order and acknowledge each harvested CQ batch once.
  Event-driven `submit` publishes bounded batches and enters until blocked.
  SQPOLL `submit` publishes one pass. An empty tick does not store the SQ tail.
  Completion polling flushes deferred task work and CQ overflow when those flags
  are set, and it handles signal interruption. See Ring modes.
- Raw `prep_*` helpers accept Rust `backend::RawSqe` pointers. Borrow preparation
  pointers only within the callback, and retain every referenced descriptor and
  buffer through the operation's final completion.

Before changing dispatch or preparation, read `subsystem.rs`, `proactor.rs`, and
`operation.rs`. When changing generated routing, read `liburing-macros` and run
successful expansions, compiler-rejected examples, and kernel dispatch tests.

## Ring modes

`ProactorMode` is fixed for the life of the ring. Preserve this contract in
`config/mode.rs`, `proactor/setup.rs`, `proactor/drive.rs`, and `proactor/shutdown.rs`.

- Variants are `EventDriven(EventDrivenConfig)`, `SqPoll(SqPollConfig)`, `IoPoll`,
  and `SqPollIoPoll(SqPollConfig)`.
- Caller `setup_flags` may set only `CLAMP`, `SUBMIT_ALL`, and `NO_SQARRAY`.
  Negotiation owns `SQPOLL`, `SQ_AFF`, `IOPOLL`, `SINGLE_ISSUER`, `COOP_TASKRUN`,
  `DEFER_TASKRUN`, and `TASKRUN_FLAG`. Polling modes require `enable_optimizations`.
  Event-driven fallback is `SI|COOP|DEFER|TASKRUN_FLAG`, then `SI|COOP|TASKRUN_FLAG`,
  then `COOP|TASKRUN_FLAG`, then none. `IoPoll` falls back
  `IOPOLL|SI|DEFER|TASKRUN_FLAG`, then `IOPOLL|SI`, then `IOPOLL`. `SqPoll` accepts
  only `SQPOLL|SQ_AFF|SINGLE_ISSUER`. `SqPollIoPoll` accepts only
  `SQPOLL|SQ_AFF|IOPOLL|SINGLE_ISSUER`. Each attempt tries preferred
  `SUBMIT_ALL|NO_SQARRAY` first. Refuse a ring that lacks `EXT_ARG` or `NODROP`.
  `SqPoll` also requires `SQPOLL_NONFIXED`.
- Pin the owner to one CPU and set `SqPollConfig::thread_cpu` to a different CPU.
  Reject a mask whose only allowed CPU is `thread_cpu`. Do not pin the owner inside
  the library.
- The example and benchmark choose two CPUs from a growable `sched_getaffinity`
  mask, pin the owner to the first, and give the second to the SQ thread. Their
  RAII guards restore the original mask. Fewer than two allowed CPUs is an error.
  Permit cold-start SQ-thread wakeups during warmup; measure warm enter counts
  against the post-warmup baseline. Keep all five frozen `ProactorStats` fields.

Preserve this drive matrix and the public contracts in README:

| Method | `EventDriven` | `SqPoll` | `IoPoll` | `SqPollIoPoll` |
| --- | --- | --- | --- | --- |
| `submit()` | Publish bounded batches, enter to flush until blocked. | One bounded publish/wakeup pass. | Publish bounded batches, enter with `GETEVENTS`. | One bounded publish/wakeup pass; SQ thread submits/polls. |
| `poll_completions()` | Flush flagged work/overflow, harvest. | Harvest; service flagged work/overflow. | Poll pending I/O with `GETEVENTS` if CQ is empty, harvest. | Harvest while SQ thread polls; service flagged work/overflow. |
| `wait_completions()` | Publish, kernel wait, harvest. | `(0, None)` delegates to tick; other waits rejected. | `(0, None)` delegates to tick; other waits rejected. | `(0, None)` delegates to tick; other waits rejected. |
| `tick()` | Submit then harvest one batch. | Publish/wake then harvest. | Submit/poll block I/O then harvest. | Publish/wake then harvest. |

- Every `submit()` returns newly published SQEs, independent of kernel acceptance.
  Transient `EINTR`/`EAGAIN`/`EBUSY` preserve `Ok(published)` and defer unconsumed SQ
  entries when no SQ-head progress is observed. Avoid an error-retry loop inside
  a drive pass. Only visible progress permits another bounded submission batch.
- After CQ dispatch, `poll_completions()` publishes staging, including callback
  follow-ups, in every mode. SQ-thread modes wake on `IORING_SQ_NEED_WAKEUP`;
  owner-driven modes flush those follow-ups on a subsequent submit/tick/wait.
- Busy-polling `wait_completions` rejects `min_complete > 0` or any timeout with
  `UringError::BlockingWaitUnavailable { mode }` before side effects.
- A fully idle tick has zero syscalls, fences, and SQ-tail stores. Empty staging
  alone does not exclude pending kernel work. For `IoPoll`, pending operations
  with an empty CQ require `GETEVENTS`; if no SQE is pending, that is
  `io_uring_enter(0, 0, IORING_ENTER_GETEVENTS)`.
- `OpcodeSet::IOPOLL` admits NOP and polled read/write opcodes. IOPOLL modes reject
  sockets, timers, and cancellation. Actual `O_DIRECT` I/O requires filesystem and
  hardware poll-queue support, for example `nvme.poll_queues=N` and
  `/sys/block/<dev>/queue/io_poll == 1`; otherwise CQEs can report `-EOPNOTSUPP`
  despite successful ring setup and NOP. Reading a sparse hole may use zero-fill
  and does not qualify hardware polling. `DirectFile::supports_polled_io()` reads
  advertised sysfs support; validate with a preallocated, initialized polled read.
- Direct I/O uses aligned memory. `FixedBufferPool::new(ring, buffer_count,
  buffer_len)` defaults to 4096-byte alignment; `FixedBufferPool::with_alignment(
  ring, buffer_count, buffer_len, alignment)` selects a power-of-two alignment.
  Both raw constructors require the unsafe ring lifetime contract.
  `Proactor::configure_direct_buffers(count, buffer_len, alignment)` owns the
  registered pool. `DirectFile::open(path: &Path, access: DirectAccess)` accepts
  `DirectAccess::ReadOnly` or `DirectAccess::ReadWrite`; `from_owned_fd(OwnedFd)`
  transfers an existing descriptor. Both return `Result<DirectFile>` and check
  `O_DIRECT` and alignment requirements. Raw preparation helpers live in `ops::fs`.
- `shutdown_with` locally discards unpublished SQEs with synthetic `-ECANCELED`
  and zero staging credit, then drains published targets. Only `EventDriven` and
  `SqPoll` issue the single global cancel across retries. `IoPoll` retries pending
  SQ entries and uses `spin_loop()`; the other three modes use
  `kernel_wait_private` in 10ms idle waits.
- `shutdown()` and owner-thread `Drop` use a consecutive stall budget of 320ms in
  `EventDriven`/`SqPoll`, or 5s in `IoPoll`/`SqPollIoPoll`, overridden by
  `shutdown_stall_timeout`. CQ progress resets the timer. On expiry, `shutdown()`
  returns `Err(UringError::Wait(libc::ETIMEDOUT))` with pending DMA and descriptor
  owners retained for retry. If `Drop` cannot drain them, it intentionally leaks
  resource and operation owners to prevent kernel DMA from using freed storage.

## Operation and Resource Lifetimes

- `OperationSlab<Meta>` is fixed-capacity after construction. Its `OperationKey` packs a 24-bit
  slot and 32-bit generation into the payload. Reject stale generations and
  retire exhausted generations instead of wrapping. Completion and metadata
  removal are separate operations. `available()` excludes permanently retired
  slots; submission capacity uses this reusable count.
- A cancellation control CQE is independent from its target. Keep the target's
  DMA and descriptor ownership through its own final completion. Cancellation
  must not release a buffer merely because the control request succeeded.
- Multishot operations remain live while the continuation flag is set.
  Zero-copy sends retain memory in `AwaitingZeroCopyNotification` until the required
  notification. Test both notification order and cancellation races.
- `Proactor` owns configured fixed buffers, fixed-file tables, and provided
  buffer groups. Unsafe pool getters and direct registration APIs require the
  caller to preserve the documented owner, ring, and detached-handle lifetimes.
  Fixed-buffer checkout and return use a preallocated stack with Cell state;
  preserve its exact capacity and generation checks without runtime borrows.
- A selected receive buffer is reusable only after its `BufferLease` ends. For
  depleted receive groups, return leases before rearming. Remove parked receive
  records before closing their descriptors.
- `CompletionSocketIo` uses real buffer-select receives and tracked sends.
  Its socket identity and operation generation prevent descriptor reuse from
  accepting stale completions. Handle partial sends, depletion, peer close,
  cancellation, and zero-copy release separately. Callback follow-up receives
  and sends use their `with_context` variants after returning selected leases.
- Use `shutdown_with` when business teardown completions must be delivered.
  Teardown has zero staging credit. Errors preserve pending ownership for retry;
  an unconfirmed target completion never permits DMA reuse. Drain ready CQEs
  independently of the normal batch limit; issue global cancellation once across
  retries and consume wait budget only when a poll makes no progress.

For resource changes, read `fixed_buffers.rs`, `fixed_files.rs`, `buffer_ring.rs`,
and `proactor/resources.rs`. For socket integration, read `socket_io.rs`
through its completion and close paths, then run the matching kernel regressions.
For operation state transitions, read `operation_slab.rs` and its lifecycle tests.

## Backend and Kernel Visibility

The backend uses `io-uring` 0.7.15 directly. SQEs and CQEs are Rust values over
mapped kernel queues. Keep batch synchronization outside per-entry processing.
The crate exposes one backend and requires no native source build or generated bindings.

On Linux x86_64, buffer descriptors and their shared-page tail use aligned
volatile accesses. In advance(), a compiler memory barrier precedes the tail
write so descriptors become visible to the kernel first. The x86_64 store
ordering completes this publication contract. Keep state confined to its owner.

## Coding and Documentation

- Every handwritten file is at most 800 lines and uses ASCII English. Generated
  `Cargo.lock` retains Cargo's native format and is exempt from the line bound.
- Preserve deterministic dependencies and source restrictions. Use explicit
  completion state machines and caller-owned dispatch on the owning thread.
- Production errors propagate through `Result`. Preserve signed CQE results
  until translating them at the intended API boundary. Avoid placeholder
  implementations and unchecked success assumptions.
- Each unsafe block has a preceding `// SAFETY:` comment explaining pointer
  validity, initialization, aliasing, lifetime, and ownership. Public unsafe
  functions document caller obligations under `# Safety`.
- Public functions document `# Errors` and `# Panics`, including their absence
  when applicable. State buffer, descriptor, and completion ownership explicitly.
- Keep architecture explanations and supported commands in README and rustdoc;
  keep temporary review notes and progress reports outside the repository.

## Verification

Use affected targets during implementation. Kernel tests require Linux with
permitted rings and support for the exercised operations. Initialization or
missing-capability failures must be visible; do not skip required coverage.

Before completing code changes, run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

GitHub-hosted CI runs the Cargo commands above directly. Run the following
examples explicitly while changing the corresponding examples or architecture:

```bash
cargo run -p liburing-proactor --example proactor_subsystems
cargo run -p liburing-proactor --example fixed_files_and_buffer_ring_tcp_echo
cargo run -p liburing-proactor --example completion_socket_io
cargo run -p liburing-proactor --example proactor_modes
```

Cancellation, generation, DMA ownership, and socket changes require their focused
kernel regression targets in addition to unit tests. The default harness runs
resource-accounting cases serially with independent thread-confined rings.
Macro compile-fail examples run through rustdoc directly.

Pure documentation edits need reference, API-signature, ASCII, line-count, and
diff checks. Report actual commands and outcomes, including any unverified
boundaries. Finish with `git diff --check` and an ownership-aware diff review.
