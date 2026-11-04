//! Terminal CQ dispatch remains observable when a retained token fails release.
use std::time::Instant;

use super::*;
#[test]
fn terminal_completion_dispatches_before_reporting_release_error() -> Result<()> {
    let mut proactor = Proactor::new(ProactorConfig::default())?;
    proactor.configure_fixed_buffers(1, 64)?;
    // SAFETY: The pool remains owned by the live Proactor until all tokens are retired.
    let token = unsafe { proactor.fixed_buffers() }?
        .checkout()?
        .into_in_flight();
    let bid = token.id();
    let generation = token.generation();
    let id = OperationId::pack(SubsystemId(4), crate::OperationPayload(1));
    proactor.prepare_buffer_sqe_with(id, token, |sqe| {
        // SAFETY: Exclusive SQE; NOP never refers to the retained buffer bytes.
        unsafe { crate::ops::prep_nop(sqe) };
    })?;
    proactor.submit()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(Instant::now() < deadline, "NOP did not complete");
        if !proactor
            .ring
            .as_mut()
            .ok_or(UringError::InvalidConfig("closed ring"))?
            .completion()
            .is_empty()
        {
            break;
        }
        proactor.advance_kernel(false)?;
    }
    // SAFETY: The final NOP CQE is visible, there is no MORE or notification,
    // and no kernel operation can access this token. Reclaiming before harvest
    // deliberately makes the retained token stale, without any DMA in flight.
    unsafe {
        proactor
            .fixed_buffers()?
            .reclaim_completed_generation(bid, generation)
    }?;
    let mut delivered = false;
    let error =
        proactor.poll_completions(8, &mut |c: Completion, _: &mut SubmissionContext<'_>| {
            assert_eq!(c.operation_id, id);
            assert_eq!(c.result, 0);
            delivered = true;
            Ok(())
        });
    assert_eq!(error, Err(UringError::BufferNotInFlight(bid.raw())));
    assert!(delivered);
    assert_eq!(proactor.operation_count(), 0);
    assert_eq!(
        proactor.poll_completions(
            8,
            &mut |_: Completion, _: &mut SubmissionContext<'_>| panic!("completion replayed")
        )?,
        0
    );
    proactor.shutdown()
}
