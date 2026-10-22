# liburing-rs

A single-threaded Linux `io_uring` foundation for completion-driven applications.

- One thread owns each `Proactor`; callbacks stage follow-up work, and cross-thread
  control uses an eventfd waker with a bounded command queue.
- Upstream liburing is compiled statically: default `pre-release` selects `master`
  (first fetch, then cache reuse); `stable` selects `liburing-2.15`. Choose one.
- `OpId` carries an 8-bit subsystem ID and a 56-bit application payload, with
  derive macros for typed codecs and validated subsystem declarations.
- `FixedFileTable` and `UringSocketBridge` grow dynamically; `FixedBufferPool`
  and `ProvidedBufRing` provide explicit registered-buffer ownership.

## Crates

| Crate | Purpose |
| --- | --- |
| `liburing-sys` | Static upstream build, C shim, raw bindings, and ABI checks. |
| `liburing-macros` | `OpPayloadCodec` derive and `define_subsystems!`. |
| `liburing` | Proactor, completion routing, wakeups, buffers, and socket bridge. |

Source, integration tests, and runnable examples live under
`crates/liburing/{src,tests,examples}/`. See [AGENTS.md](AGENTS.md) and the
crate rustdoc for ownership contracts and contributor guidance.

## Quick Start

Configure a thread-local ring, register a handler, and drive a completion:

```rust
use liburing::{Completion, OpId, OpPayload, Proactor, Result,
    SubmissionContext, SubsystemHandler, SubsystemId, UringError};

struct Handler;
impl SubsystemHandler for Handler {
    fn on_completion(&mut self, cqe: Completion,
        _: &mut SubmissionContext<'_>) -> Result<()> {
        println!("operation {:?}: {}", cqe.op_id, cqe.result);
        Ok(())
    }
}

fn main() -> Result<()> {
    let mut ring = Proactor::builder().entries(16).build()?;
    let subsystem = SubsystemId::new(1).ok_or(UringError::InvalidSubsystemId(1))?;
    ring.register_subsystem(subsystem, Handler)?;
    ring.alloc_sqe(OpId::pack(subsystem, OpPayload::new_unchecked(7)))?; // NOP
    ring.wait_completions(1, Some(std::time::Duration::from_secs(1)), |_, _| Ok(()))?;
    ring.shutdown()
}
```

Keep operation buffers and descriptors alive until their final completion.
Subsystem zero is reserved; application IDs are `1..=255`.

## Examples

Each program uses real kernel `io_uring`, only local descriptors or loopback,
checks its results, prints a summary, and exits. Unsupported kernel features
return errors. All examples live in `crates/liburing/examples/`.

| Example | Demonstrates |
| --- | --- |
| `proactor_subsystems_and_waker` | Typed routing, callback staging, cross-thread queue draining, and shutdown. |
| `fixed_files_and_pbuf_tcp_echo` | TCP echo, fixed-file growth/direct close, fixed sends, multishot buffer recovery. |
| `socket_bridge_readiness` | Growing registrations, connect/read/write readiness, and ordered removal/close. |

```bash
cargo run -p liburing --example proactor_subsystems_and_waker
cargo run -p liburing --example fixed_files_and_pbuf_tcp_echo
cargo run -p liburing --example socket_bridge_readiness
```

## Build and Test

Requires Linux with permitted `io_uring`, Rust from `rust-toolchain.toml`, a C
compiler, libclang, and Git for uncached native source. `LIBURING_DIR` can select
an offline upstream tree. Binaries require no system `liburing.so`.

```bash
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --no-default-features --features stable
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
bash .github/scripts/ci-incremental.sh
```

After package gates pass, the incremental gate discovers and runs all examples,
with a 30-second bound each. Selecting `liburing` or `liburing-sys` also runs them
with stable features. Tests cover integration, lifecycle, scenarios, and local
network E2E; failures to initialize a required kernel ring fail visibly.

## License

Rust code: MIT. Bundled liburing sources retain their upstream licenses.
See [LICENSE](LICENSE).
