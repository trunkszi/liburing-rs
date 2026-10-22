//! Typed completion routing, callback staging, and a cross-thread stop command.
//!
//! Run with `cargo run -p liburing --example proactor_subsystems_and_waker`.
//! A real Linux io_uring is required; no kernel failures are skipped.

use std::{
    cell::RefCell,
    rc::Rc,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use liburing::{
    Completion, CrossThreadCommandQueue as WakerQueue, OpId, OpPayload, Proactor, ProactorWaker,
    Result, SubmissionContext, SubsystemHandler, SubsystemId, UringError, ops::prep_nop,
};
use liburing_macros::{OpPayloadCodec, define_subsystems};

type ExampleResult = std::result::Result<(), Box<dyn std::error::Error>>;

define_subsystems! {
    enum Subsystems {
        Compute = 1,
        Audit = 2,
    }
}

#[derive(Clone, Copy, Debug, OpPayloadCodec)]
struct Work {
    sequence: u32,
}

fn operation(subsystem: SubsystemId, sequence: u32) -> Result<OpId> {
    let raw = Work { sequence }.encode_payload();
    let payload = OpPayload::new(raw).ok_or(UringError::InvalidPayload(raw))?;
    Ok(OpId::pack(subsystem, payload))
}

struct Worker {
    id: SubsystemId,
    counts: Rc<RefCell<[usize; 2]>>,
}

impl SubsystemHandler for Worker {
    fn on_completion(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> Result<()> {
        let work = Work::decode_payload(completion.op_id.payload().raw())
            .map_err(UringError::InvalidPayload)?;
        if work.sequence == 2 {
            // shutdown may race a completed NOP with its cancellation request.
            if completion.result != 0 && completion.result != -libc::ECANCELED {
                return Err(UringError::InvalidConfig("unexpected shutdown NOP result"));
            }
            if submissions.remaining_capacity() != 0 {
                return Err(UringError::InvalidConfig("expected shutdown dispatch"));
            }
        } else if completion.result != 0 || work.sequence > 1 {
            return Err(UringError::InvalidConfig("unexpected worker completion"));
        }
        self.counts.borrow_mut()[usize::from(self.id.raw() - 1)] += 1;
        if work.sequence == 0 {
            submissions.prepare_sqe_with(operation(self.id, 1)?, |sqe| {
                // SAFETY: The callback lends initialized, exclusive SQE storage;
                // NOP has no borrowed buffer or descriptor operands.
                unsafe { prep_nop(sqe) };
            })?;
        }
        Ok(())
    }
}

enum Command {
    Start,
    Stop,
}

fn main() -> ExampleResult {
    let mut proactor = Proactor::builder()
        .entries(8)
        .staged_capacity(16)
        .enable_waker(true)
        .build()?;
    let counts = Rc::new(RefCell::new([0; 2]));
    for subsystem in Subsystems::ALL {
        let id = SubsystemId::new(subsystem.id()).ok_or("invalid subsystem ID")?;
        proactor.register_subsystem(
            id,
            Worker {
                id,
                counts: Rc::clone(&counts),
            },
        )?;
    }
    println!("Created a real io_uring and registered Compute and Audit handlers.");

    let waker: ProactorWaker = proactor.waker().ok_or("waker was not enabled")?;
    // WakerQueue is an example-local alias for CrossThreadCommandQueue.
    // Eventfd wakeups coalesce, so drain every accepted command after each wait.
    let queue = WakerQueue::new(2, waker.clone());
    let producer_queue = queue.clone();
    let (work_done, completion_notice) = mpsc::sync_channel(1);
    let producer = thread::spawn(move || -> Result<()> {
        producer_queue.push(Command::Start)?;
        completion_notice
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| UringError::InvalidConfig("owner did not finish its work"))?;
        producer_queue.push(Command::Stop)?;
        Ok(())
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut started = false;
    let mut notified = false;
    let mut stopped = false;
    while !stopped {
        if Instant::now() >= deadline {
            return Err("cross-thread command/completion deadline elapsed".into());
        }
        let harvested =
            proactor.wait_completions(1, Some(Duration::from_millis(100)), |_, _| Ok(()))?;
        if harvested == 0 {
            continue;
        }
        let mut commands = Vec::new();
        let drained = queue.drain_with(|command| commands.push(command));
        for command in commands {
            match command {
                Command::Start => {
                    if started {
                        return Err("duplicate start command".into());
                    }
                    started = true;
                    for subsystem in Subsystems::ALL {
                        let id = SubsystemId::new(subsystem.id()).ok_or("invalid subsystem ID")?;
                        proactor.prepare_sqe_with(operation(id, 0)?, |sqe| {
                            // SAFETY: Preparation owns initialized SQE storage;
                            // NOP has no kernel-visible external resources.
                            unsafe { prep_nop(sqe) };
                        })?;
                    }
                    println!("Drained {drained} command; submitted one NOP per subsystem.");
                }
                Command::Stop => stopped = true,
            }
        }
        if *counts.borrow() == [2, 2] && !notified {
            work_done.send(())?;
            notified = true;
            println!("Both handlers completed their callback-staged follow-up NOPs.");
        }
    }
    producer.join().map_err(|_| "command producer panicked")??;
    if !started || !notified || *counts.borrow() != [2, 2] || !queue.is_empty()? {
        return Err("incomplete command or subsystem accounting".into());
    }
    println!("Received the producer's Stop command through the eventfd wake path.");

    // Leave one submitted application operation for shutdown to retire. Its
    // handler accepts either normal completion or cancellation, exactly once.
    let audit = SubsystemId::new(Subsystems::Audit.id()).ok_or("invalid Audit ID")?;
    proactor.prepare_sqe_with(operation(audit, 2)?, |sqe| {
        // SAFETY: Exclusive initialized SQE storage; NOP borrows no resources.
        unsafe { prep_nop(sqe) };
    })?;
    proactor.submit()?;
    proactor.shutdown()?;
    if *counts.borrow() != [2, 3] || !waker.is_closed() {
        return Err("shutdown did not retire the final operation and close the waker".into());
    }
    proactor.shutdown()?;
    println!("Shutdown drained the final NOP, closed the waker, and exited deterministically.");
    Ok(())
}
