# liburing-rs

A synchronous, thread-local Linux `io_uring` foundation for composing protocol
state machines on one ring per application thread. `Proactor` owns the ring and
completion dispatch. Callers explicitly register subsystem handlers, prepare
operations, submit work, and harvest completions.

The ring stays on its creating thread. Completion callbacks receive a bounded
`SubmissionContext` for follow-up work; `ProactorWaker` and
`CrossThreadCommandQueue` provide the cross-thread control boundary.
`UringSocketBridge` adapts external socket state machines to the same ring.

## Workspace

| Layer | Crate | Responsibility |
| --- | --- | --- |
| Native boundary | `liburing-sys` | Build upstream C liburing and an inline-helper shim into a static archive; expose raw C bindings. |
| Compile-time integration | `liburing-macros` | `OpPayloadCodec` derive and validated subsystem IDs through `define_subsystems!`. |
| Runtime | `liburing` | Thread-local proactor, staged SQEs, completion routing, buffer and descriptor helpers, wakeups, and socket bridge. |

The workspace uses Rust 2024 and the toolchain selected by
`rust-toolchain.toml`. Shared dependencies, lints, and profiles live in the root
`Cargo.toml`. Native headers and source come from the same upstream tree; binaries
do not need a system `liburing.so`.

## Features and Native Source

Exactly one native-source feature must be enabled:

| Feature | Upstream source |
| --- | --- |
| `pre-release` (default) | Upstream `master`. |
| `stable` | The `liburing-2.15` release tag. |

Use `--no-default-features --features stable` to select stable. Enabling both
features, including through `--all-features`, is invalid. An existing checkout
cache is reused; a default build does not fetch a new `master` revision on every
invocation.

`liburing-sys` resolves source in this order:

1. `LIBURING_DIR`, pointing to an upstream source tree containing `configure`
   and `src/include/liburing.h`.
2. `crates/liburing-sys/vendor/liburing` or `vendor/liburing`.
3. A shallow upstream checkout cached below the Cargo target directory.

An explicit source override supplies its own revision; choose a tree compatible
with the feature mode being tested. Git-backed vendor and cache trees are checked
against the selected ref. Configuration and compilation use private Cargo build
output directories, preserving the input tree. The build compiles upstream C
sources and the inline shim into `liburing_bundled.a` and generates bindings with
bindgen. System `pkg-config` and a dynamically linked liburing are not involved.

## Completion Routing

Kernel `user_data` contains the exact `OpId` supplied during preparation:

```text
63              56 55                                               0
+-----------------+--------------------------------------------------+
| SubsystemId (8) | OpPayload (56)                                   |
+-----------------+--------------------------------------------------+
```

`SubsystemId(0)` is reserved for internal operations; application handlers use
identifiers `1..=255`. `OpPayload::new` validates the 56-bit bound. Construct an
operation with `OpId::pack` and recover its parts with `unpack`. Payload fields,
including operation kind, socket generation, and sequence number, belong to the
subsystem's codec. The bridge uses this space to reject stale poll completions.

The `OpPayloadCodec` derive accepts `u8`, `u16`, and `u32` fields, including
their `core::primitive::` and `std::primitive::` paths. Each accepted field must
resolve to the corresponding primitive type; an alias with a different width
or signedness is rejected. Fields and enum tags together must fit within 56 bits.
Named fields, including `raw`, `body`, and `tag`, keep their values through
encoding and decoding.

`define_subsystems!` declares fieldless subsystem variants with explicit, unique
IDs in `1..=255`. Its enum and variants reject `cfg` and `cfg_attr` attributes.
Place a conditional attribute on the macro invocation or its containing module
to enable or disable the complete declaration and all generated helpers together.

Register a `SubsystemHandler` before submitting its operations. Completion
dispatch calls its `on_completion` on the owner thread, followed by the optional
observer passed to `poll_completions` or `wait_completions`. Internal wake CQEs are
handled by the proactor and are not delivered to application observers.
Unregistering a handler does not cancel its operations or retire its DMA resources;
the caller must drain those operations first.

## Reentrant SQE Staging

Callbacks often initiate more work: a DNS result starts a connection, or a read
completion schedules another read. `SubmissionContext::prepare_sqe_with` copies
a prepared SQE into a preallocated queue without exposing the ring or entering
the kernel. The preparation pointer is temporary and must not escape the call.

`ProactorConfig::entries` controls kernel SQ depth; `staged_capacity` separately
bounds queued overflow and callback submissions. A full staging queue returns
`UringError::SqRingFull` so callers can retry without losing accepted work. After
callback dispatch ends, staged SQEs move into available kernel slots in FIFO order.
The application continues submitting and polling until pending work drains.
Nested submission and completion dispatch are rejected with
`UringError::ReentrantDispatch`.
Linked SQEs (`IOSQE_IO_LINK` and `IOSQE_IO_HARDLINK`) are rejected with
`UringError::InvalidPreparedSqe`: bounded staging can split submissions across
kernel batches and does not preserve link-chain atomicity.
`IOSQE_IO_DRAIN` is also rejected, since it can wait indefinitely for the
proactor's persistent internal eventfd poll to complete.

`tick` submits and performs a nonblocking completion batch. `wait_completions`
submits and waits for a minimum completion count or relative timeout. The
configured `max_cqe_batch` bounds default harvest work. Callbacks can stage more
than one kernel SQ's worth of operations when staging capacity allows, without
recursive `io_uring_submit` calls.

## DMA Isolation and Provided Buffers

`FixedFileTable::grow(min_capacity)` doubles its current capacity or reaches the
requested minimum while preserving every occupied slot index. `insert` grows a
full table automatically. Growth replaces the kernel registration and should run
on the control plane after prior fixed-file operations retire; unregistration can
wait for outstanding I/O. Bookkeeping allocation precedes kernel replacement. A
failed replacement attempts to restore the original table; failed restoration
marks the table unregistered so later slot operations fail consistently.

Each occupied fixed-file slot retains a private close-on-exec duplicate in
addition to the kernel reference. This preserves the registered file's identity
across growth even after the caller closes or reuses its original descriptor.
Public slot lookups still report the original descriptor number. Removing a slot,
reclaiming its direct close, or unregistering the table releases the duplicate;
the caller retains ownership of its own descriptor. Duplication and growth may
fail due to OS descriptor limits, kernel registration limits, or allocation errors.

Preparing an SQE does not transfer arbitrary raw-pointer lifetimes to `Proactor`.
The submitter must keep buffers, addresses, message headers, and descriptors valid
until the operation's final CQE, including during cancellation.

The fixed-buffer ownership model separates reusable memory from memory still
visible to the kernel. `FixedBufferPool::checkout` yields a `FixedBufHandle`;
`into_in_flight` consumes it into an `InFlightWaitingBuffer` before publishing
the SQE. Dropping the waiting token quarantines its slot rather than recycling it:

```text
available -> in flight -> waiting for target completion -> available
                 |                    ^
                 +-- cancel request --+
```

An asynchronous cancel produces its own control CQE independently of the target
operation's CQE. A successful cancel acknowledgement does not authorize buffer
reuse. Only the target's final completion, without `IORING_CQE_F_MORE`, establishes
that the kernel has relinquished the operation. After establishing that condition,
the caller explicitly uses `InFlightWaitingBuffer::complete` or
`FixedBufferPool::reclaim_completed`; these unsafe operations rely on the caller
matching the final CQE to the exact buffer checkout. The same rule applies before
closing or recycling a descriptor referenced by submitted work.

`ProvidedBufRing` registers stable receive storage. `PbufLease` gives exclusive
access to a selected payload and republishes that buffer on release or drop.
After a terminal `-ENOBUFS` CQE, call `mark_depleted_recv(fd, flags, op_id)`
to park that receive. Returning leases restores buffer availability. Drive
`rearm_depleted_recvs` with a staging callback: the helper detects available
buffers, including leases returned earlier in the CQE batch, and supplies each
eligible receive's fd, message flags, operation
ID, and buffer group. The callback stages exactly one multishot receive on success
and nothing on failure; failed records stay pending for retry. Lease drop itself
does not enter the kernel. Remove a parked receive with `forget_depleted_recv`
before closing its fd. The buffer ring and backing storage must outlive every
receive selecting that group.

## External Socket State Machines

`UringSocketBridge` binds one `SubsystemId` to managed socket fds.
`SocketInterest` contains `READABLE` and `WRITABLE`; `UringSocketOps` supplies the
operation-staging boundary. `BridgeOpKind` distinguishes `PollAdd`, `PollRemove`,
`Cancel`, `Connect`, and `Close`.

The socket capacity supplied at construction is an initial reservation, not a
registration limit. Registering beyond it doubles socket bookkeeping (zero grows
to four slots) and reserves at least six pending operations per socket. Pending
operation bookkeeping also doubles independently when full, preserving live
tokens and indices. These control-plane transitions can allocate and return
`BridgeError::Capacity` on allocation failure or capacity overflow.

The bridge maintains a single active `POLL_ADD` per socket generation. Interest
changes remove the old poll before installing its replacement. Close cancels
pending work and waits for relevant completions before staging descriptor close.
Stale CQEs from old poll sequences cannot signal a reused fd. `BridgeEvent`
returns the fd, readiness mask, and original signed completion result to the
caller. Control events carry an empty interest mask; deliver only nonempty masks
to a library's readiness-processing entry point. Call `drive()` after consuming a
completion batch to stage replacement polls and deferred closes. Keep the bridge
and adapter alive until all managed sockets finish close; dropping the bridge
does not cancel or close them. A final close CQE retires the fd even on errors
reported after close executes; retrying Linux close could affect a reused
descriptor. A canceled close did not execute and can be staged again.
Submission failures before close is staged remain retryable through `drive()`.
Cancellation controls retain their target's lifetime. Failures other than the
normal `-ENOENT`/`-EALREADY` completion races permit retry;
superseded polls never emit readiness, even if the interest mask changes back.
Start `connect()` before installing readiness interest. A pending poll addition
or removal causes `BridgeError::PollInFlight`; clear interest and retire those
poll operations before retrying connect on the same socket.

For c-ares, collect readiness events and advance the library with its fd-processing
entry point. Compute its retry deadline and use a bounded wait so it can advance
even when no socket CQE arrives. Preserve negative CQE errors when translating to
its callback conventions.

The bridge handles readiness and lifecycle operations. A socket I/O adapter must
separately preserve UDP peer addresses and datagram boundaries, retain unread TCP
bytes, and queue unsent suffixes after short TCP writes. Poll readiness alone
neither implements these queues nor transfers ownership of payload buffers.

## Four-Pillar Architecture

The broader composition model has four pillars:

1. **Dual-mode I/O:** direct completions for Rust engines and socket adaptation
   for external callback state machines.
2. **Owned operation routing:** generation-aware slots and bounded two-phase
   dispatch allow each active subsystem to flush once per completion batch.
3. **Shared resource lifetime:** provided receive buffers, cancel-safe stable DMA
   storage, and descriptor retirement share a target-completion barrier.
4. **Coalesced deadlines:** one monotonic timer registry computes the earliest
   wait deadline across protocol engines.

The current public foundation exposes `Proactor`, an 8/56-bit `OpId`, per-CQE
handlers, bounded staging, and explicit buffer ownership helpers. A shared
`SlotTable`, automatic unregister quarantine, batch-handler scheduling, and a
unified timer registry are higher-level architecture requirements; applications
must not infer those guarantees from raw SQE preparation. Until such facilities
are exposed, callers own operation retirement and deadline selection.

## Build and Test

Build on Linux with a C compiler, shell tools, Git for uncached upstream source,
Rust, and libclang for bindgen. Use `LIBURING_DIR` or a populated vendor tree for
builds without network access. Kernel policy must permit `io_uring`; container
seccomp profiles or disabled-ring sysctls can prevent ring creation. Provided
buffer rings and multishot receive also require support for those operations.

Run from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --no-default-features --features stable
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
bash .github/scripts/ci-incremental.sh
```

### Test matrix

`lifecycle_and_scenario_e2e` separates four dimensions into named test modules.
Each uses a real Linux kernel ring: setup and missing required capabilities fail
the test instead of producing a passing skip. Test infrastructure may create
control-plane producer threads; ring submission and dispatch stay on one thread.

| Dimension | Source under `crates/liburing/tests/` | Coverage | Focused command |
| --- | --- | --- | --- |
| Integration test | `lifecycle_and_scenario_e2e/integration.rs` | One proactor with growing fixed-file registration, stable slot I/O after original fd closure, generation-checked fixed-buffer recovery, cancel/target CQE isolation, and provided-buffer UDP leases. | `cargo test -p liburing --test lifecycle_and_scenario_e2e integration::` |
| Lifecycle test | `lifecycle_and_scenario_e2e/lifecycle.rs` | Builder construction, multiple subsystems, registration, in-flight work, file-table growth, direct close and slot reuse, shutdown callback delivery, rejected follow-ups, and deterministic resource release. | `cargo test -p liburing --test lifecycle_and_scenario_e2e lifecycle::` |
| Scenario test | `lifecycle_and_scenario_e2e/scenario*.rs` | Bridge growth and connect/poll/remove/close barriers with fd reuse; UDP buffer exhaustion and bounded rearming; concurrent wakeups, batch draining, and queue backpressure recovery. | `cargo test -p liburing --test lifecycle_and_scenario_e2e scenario::` |
| E2E test | `lifecycle_and_scenario_e2e/e2e.rs` | A single-thread proactor loop drives local TCP/UDP traffic, timeout completion, and a cross-thread stop command through the control mailbox. | `cargo test -p liburing --test lifecycle_and_scenario_e2e e2e::` |

Run the entire matrix in both native-source configurations:

```bash
cargo test -p liburing --test lifecycle_and_scenario_e2e
cargo test -p liburing --test lifecycle_and_scenario_e2e --no-default-features --features stable
```

`proactor_and_waker`, `fixed_resources_and_pbuf`, `adversarial_proactor`,
`socket_bridge_growth`, and `prepared_sqe_validation` retain narrower routing,
resource, stress, growth, and rejected-SQE regressions alongside this matrix.

The focused runtime stress target is:

```bash
cargo test -p liburing --test adversarial_proactor
cargo test -p liburing --test adversarial_proactor --no-default-features --features stable
```

Its scenarios exercise an SQ depth of 16 with 128 submissions from one completion
callback; cancellation of 16 blocked fixed-buffer reads and delayed reuse;
provided-buffer exhaustion and receive recovery; three interleaved subsystem
routes with 32 reads and 32 writes each; and four external producers delivering
2,500 commands each (10,000 total). Wakeups may coalesce; command delivery
must remain lossless. After a wake, drain the mailbox until `pop()?` returns
`None`, or use `CrossThreadCommandQueue::drain_with` to process the queued commands
without holding the queue mutex during callbacks. The helper recovers a poisoned
mutex so accepted commands can still be drained. Real ring creation is required;
an unavailable or forbidden kernel ring fails the focused target instead of
silently skipping its kernel scenarios.
The target also checks native socket poll replacement, readiness decoding, and
cancellation before deferred close through `UringSocketBridge`.
A unit scenario in the same target checks multishot routing and stale readiness
after interest-mask changes.

## License

The Rust workspace is licensed under MIT. Bundled upstream C sources retain
liburing's upstream licenses.
