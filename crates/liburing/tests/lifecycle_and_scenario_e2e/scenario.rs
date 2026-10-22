use std::{
    cell::RefCell,
    rc::Rc,
    time::{Duration, Instant},
};

use liburing::{
    Completion, OpId, OpPayload, Proactor, ProactorConfig, SubmissionContext, SubsystemHandler,
    SubsystemId,
};

#[path = "scenario_bridge.rs"]
mod bridge;
#[path = "scenario_pbuf.rs"]
mod pbuf;
#[path = "scenario_waker.rs"]
mod waker;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_millis(20);
const DEADLINE: Duration = Duration::from_secs(15);

fn kernel(waker: bool) -> liburing::Result<Proactor> {
    Proactor::new(ProactorConfig {
        entries: 64,
        staged_capacity: 256,
        max_cqe_batch: 128,
        enable_waker: waker,
        ..ProactorConfig::default()
    })
}

fn route() -> SubsystemId {
    SubsystemId::new(7).expect("nonzero scenario subsystem")
}

fn op(payload: u64) -> OpId {
    OpId::pack(
        route(),
        OpPayload::new(payload).expect("scenario token fits"),
    )
}

fn deadline(start: Instant) {
    assert!(
        start.elapsed() < DEADLINE,
        "scenario exceeded bounded kernel wait"
    );
}

struct Recorder(Rc<RefCell<Vec<Completion>>>);

impl SubsystemHandler for Recorder {
    fn on_completion(
        &mut self,
        completion: Completion,
        _: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        self.0.borrow_mut().push(completion);
        Ok(())
    }
}
