# Agent Guide

Operational contract for contributors working in `liburing-rs`. Use [README.md](README.md)
for architecture and integration guidance. Cargo manifests and source define the
current API and build behavior.

## Repository Boundaries

This Linux, Rust 2024 workspace has three layers:

| Crate | Responsibility |
| --- | --- |
| `crates/liburing-sys` | Upstream static C build, inline-helper shim, generated bindings, and ABI checks. |
| `crates/liburing-macros` | `OpPayloadCodec` derive and validated subsystem IDs through `define_subsystems!`. |
| `crates/liburing` | Ring ownership, staged submissions, completion routing, DMA and descriptor helpers, wakeups, and socket bridge. |

Keep native ABI changes in `liburing-sys`, syntax generation in
`liburing-macros`, and runtime ownership in `liburing`. Downstream protocol
semantics belong to their adapters. Shared dependencies come from root
`[workspace.dependencies]`; retain inherited lints and profiles.

Before editing, inspect staged and unstaged differences in each target file and
preserve concurrent work. Commit or publish only when requested. Stage explicit
paths belonging to the authorized change.

## Runtime Contracts

- `Proactor` and ring-owned resources remain on their creating thread.
  `ProactorWaker` and `CrossThreadCommandQueue` cross threads; callbacks and ring
  access stay on the owner thread. The command queue is a bounded control-plane
  mailbox with a mutex, not a lock-free data-plane primitive.
- Route `OpId` as `[8-bit SubsystemId | 56-bit OpPayload]`. Subsystem zero is
  internal; public handlers use `1..=255`. Preserve payload width validation and
  leave generation/sequence layout to the subsystem codec.
- Register a handler before submitting its operations. Keep kernel-visible
  resources alive when a handler unregisters: registry removal alone does not
  cancel, drain, or release operations.
- Callback follow-up work goes through `SubmissionContext::prepare_sqe_with`.
  Keep preparation pointers within the call. Respect `staged_capacity`, return
  `SqRingFull` on exhaustion, and preserve FIFO order for accepted operations.
  Flush staging only after callback dispatch; reject recursive submit/dispatch.
- Raw SQE preparation leaves referenced buffer and descriptor lifetimes with the
  submitter. Keep them valid until the target operation's final CQE, including
  cancellation races and multishot continuation.
- Treat the cancel control CQE and target CQE as independent. A successful cancel
  acknowledgement does not release target DMA storage. Reuse and deferred close
  require the target's final completion without `IORING_CQE_F_MORE`.
- Return provided buffers only after their payload lease ends. Park terminal
  `-ENOBUFS` receives with `mark_depleted_recv`, then drive
  `rearm_depleted_recvs` after lease returns. Its callback stages exactly one
  receive on success and nothing on error; failed records remain retryable.
  Remove parked records with `forget_depleted_recv` before fd close.
- Preserve socket generation and poll-sequence checks in `UringSocketBridge`.
  Validate interest replacement, late completions, close races, and negative CQE
  results whenever changing the bridge.

Read `crates/liburing/src/subsystem.rs` and `proactor.rs` before changing callback
submission or dispatch. Read `socket_bridge.rs` and `UringSocketOps` before
changing external socket integration. Follow fixed-buffer and provided-buffer
ownership from preparation through final CQE before changing cancellation.

The four-pillar composition model is described in README. Keep implemented
contracts distinct from higher-level goals such as unified timers, automatic
unregister quarantine, a shared operation slot table, and batch callbacks.

## Native Build and Features

`liburing-sys` statically builds upstream source and its C shim. Exactly one of
`pre-release` (upstream `master`, default) and `stable` (`liburing-2.15`) is valid.
Test stable with default features disabled; `--all-features` is invalid.

Source selection checks `LIBURING_DIR`, crate/root `vendor/liburing`, then the
Cargo target cache. Explicit overrides select their own tree. Keep generated
bindings, inline wrappers, and native objects tied to that same tree. Preserve
private build-output configuration and the absence of system `pkg-config` or a
runtime `liburing.so` dependency.

For native declarations, source selection, feature forwarding, or build flag
changes, validate both feature modes and inspect linked test binaries. For macro
changes, exercise successful expansion and rejected input diagnostics.

## Coding and Documentation

- Keep every source file at or below 800 lines; split by responsibility.
- Write identifiers, comments, diagnostics, and documentation in English using
  ASCII text.
- Propagate production errors without `unwrap`, `expect`, or placeholder
  implementations. Preserve signed native CQE results until their intended
  translation boundary.
- Explain every unsafe block with a preceding `// SAFETY:` comment covering its
  actual pointer validity, initialization, aliasing, lifetime, and ownership
  requirements. Unsafe public functions also require `# Safety` rustdoc.
- Public functions document `# Errors` and `# Panics`, explicitly describing their
  absence when appropriate. Describe caller obligations and resource contracts.
- Keep design-session notes and progress reports out of source and product docs.
  Update README with changes to public behavior, feature selection, or commands.

## Verification

Run from the repository root. During implementation, use affected package and
test targets. Before completing a code change, run the repository gate and docs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --no-default-features --features stable
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
bash .github/scripts/ci-incremental.sh
```

Run `cargo test -p liburing --test adversarial_proactor` for staging, cancellation,
buffer reuse, routing, and wakeup changes. Add
`--no-default-features --features stable` when feature behavior is affected.

Runtime tests need Linux with permitted `io_uring` and support for the exercised
operations. Distinguish skipped kernel-dependent assertions from executed tests.
Report actual commands, results, and uncovered boundaries. End with
`git diff --check` and a review of the changed paths. Pure documentation edits
need factual, reference, and diff checks rather than a full native rebuild.
