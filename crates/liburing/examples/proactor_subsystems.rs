//! One thread owns a worker, static subsystem dispatch, and staged follow-up work.

use std::time::{Duration, Instant};

use liburing::{
    OperationId, OperationPayload, Proactor, Result, SubsystemId, UringError, ops::prep_nop,
};
use liburing_macros::{OperationPayloadCodec, define_subsystems};

define_subsystems! { enum Subsystems { Compute = 1, Audit = 2 } }
#[derive(Clone, Copy, OperationPayloadCodec)]
struct Work {
    sequence: u32,
}
struct WorkerState {
    counts: [usize; 2],
}
fn id(subsystem: Subsystems, sequence: u32) -> OperationId {
    OperationId::pack(
        SubsystemId::new_unchecked(subsystem.id()),
        OperationPayload::new_unchecked(Work { sequence }.encode_payload()),
    )
}

fn main() -> Result<()> {
    let mut ring = Proactor::builder().entries(16).build()?;
    let mut worker = WorkerState { counts: [0; 2] };
    ring.alloc_sqe(id(Subsystems::Compute, 0))?;
    ring.alloc_sqe(id(Subsystems::Audit, 0))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    {
        let mut dispatcher =
            Subsystems::dispatcher(&mut worker, |subsystem, state, cqe, submissions| {
                if cqe.result != 0 {
                    return Err(UringError::from_errno(cqe.result));
                }
                let index = match subsystem {
                    Subsystems::Compute => 0,
                    Subsystems::Audit => 1,
                };
                state.counts[index] += 1;
                let work = Work::decode_payload(cqe.operation_id.payload().raw())
                    .map_err(UringError::InvalidPayload)?;
                if work.sequence == 0 {
                    submissions.prepare_sqe_with(id(subsystem, 1), |sqe| {
                        // SAFETY: This callback owns initialized exclusive SQE storage.
                        unsafe { prep_nop(sqe) };
                    })?;
                }
                Ok(())
            });
        while ring.operation_count() != 0 {
            if Instant::now() >= deadline {
                return Err(UringError::Wait(libc::ETIMEDOUT));
            }
            ring.wait_completions(1, Some(Duration::from_millis(100)), &mut dispatcher)?;
        }
        ring.shutdown_with(&mut dispatcher)?;
    }
    if worker.counts != [2, 2] {
        return Err(UringError::InvalidConfig("incomplete worker accounting"));
    }
    println!(
        "Static shared-worker routing, callback staging, and thread-confined shutdown passed."
    );
    Ok(())
}
