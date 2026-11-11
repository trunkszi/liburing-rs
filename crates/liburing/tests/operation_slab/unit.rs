use super::*;

#[test]
fn exhausted_generation_retires_slot() -> Result<()> {
    let mut slab = OperationSlab::new(2)?;
    slab.headers[0] = slab.headers[0].patch(
        uarch::bits::BitPatch::EMPTY.with_field(SlotHeader::GENERATION, (u32::MAX - 1) as u64),
    );
    let final_generation = slab.insert(1, OperationKind::Single)?;
    assert_eq!(slab.available(), 1);
    assert_eq!(final_generation.generation(), u32::MAX);
    assert!(slab.complete(final_generation, 0, 0)?);
    assert_eq!(slab.remove(final_generation)?, 1);
    assert_eq!(slab.available(), 1);
    let other = slab.insert(2, OperationKind::Single)?;
    assert_eq!(other.slot(), 1);
    assert_eq!(
        slab.insert(3, OperationKind::Single),
        Err(UringError::SqRingFull)
    );
    assert!(slab.get(final_generation).is_err());
    assert_eq!(slab.capacity(), 2);
    assert!(slab.complete(other, 0, 0)?);
    assert_eq!(slab.remove(other)?, 2);
    assert_eq!(slab.available(), 1);
    Ok(())
}

#[test]
fn exhausted_rollback_preserves_reusable_credit() -> Result<()> {
    let mut slab = OperationSlab::new(2)?;
    slab.headers[0] = slab.headers[0].patch(
        uarch::bits::BitPatch::EMPTY.with_field(SlotHeader::GENERATION, (u32::MAX - 1) as u64),
    );
    let exhausted = slab.insert(1, OperationKind::Single)?;
    // SAFETY: No operation in this fixture was ever staged or sent to a kernel.
    assert_eq!(unsafe { slab.discard_unsubmitted(exhausted) }?, 1);
    assert_eq!(slab.available(), 1);
    let live = slab.insert(2, OperationKind::Single)?;
    assert_eq!(slab.available(), 0);
    // SAFETY: This fixture has no ring and no published operands.
    unsafe { slab.retire_after_ring_close() };
    assert_eq!(slab.available(), 1);
    assert!(slab.get(live).is_err());
    // SAFETY: No kernel can access this fixture, including after repeated retirement.
    unsafe { slab.retire_after_ring_close() };
    assert_eq!(slab.available(), 1);
    Ok(())
}

#[test]
fn retired_generations_reduce_submission_credit() -> Result<()> {
    use crate::{
        OperationId, SubsystemId, identity_map::IdentityMap, operation::TrackedOperation,
        proactor::resources::Resources, subsystem::SubmissionContext,
    };
    let mut operations = OperationSlab::new(2)?;
    operations.headers[0] = operations.headers[0].patch(
        uarch::bits::BitPatch::EMPTY.with_field(SlotHeader::GENERATION, (u32::MAX - 1) as u64),
    );
    let key = operations.insert(
        TrackedOperation {
            original: OperationId(1 << 56),
            keyed: true,
            selected_buffer_group: None,
            buffer: None,
            socket: None,
        },
        OperationKind::Single,
    )?;
    assert!(operations.complete(key, 0, 0)?);
    operations.remove(key)?.release()?;
    let mut staged = std::collections::VecDeque::with_capacity(2);
    let mut identities = IdentityMap::new(2)?;
    let resources = Resources::new(1);
    let mut pending_cancels = 0;
    let mut context = SubmissionContext {
        owner_id: 1,
        selected_buffer_group: None,
        staged: &mut staged,
        capacity: 2,
        admission: crate::config::OpcodeSet::ALL,
        cancellable: true,
        mode_name: "event-driven",
        operations: &mut operations,
        identities: &mut identities,
        resources: &resources,
        pending_cancels: &mut pending_cancels,
        current_completion: None,
    };
    assert_eq!(context.remaining_capacity(), 1);
    let key = context.prepare_keyed_sqe_with(SubsystemId(1), |sqe| {
        // SAFETY: Initialized exclusive SQE storage; NOP has no external operands.
        unsafe { crate::ops::prep_nop(sqe) };
    })?;
    assert_eq!(context.remaining_capacity(), 0);
    assert_eq!(
        context.prepare_keyed_sqe_with(SubsystemId(1), |_| {
            panic!("retired capacity must reject before preparation")
        }),
        Err(UringError::SqRingFull)
    );
    context.staged.clear();
    // SAFETY: The only staged entry was removed above without ever being published.
    unsafe { context.operations.discard_unsubmitted(key) }?.release()?;
    assert_eq!(context.remaining_capacity(), 1);
    Ok(())
}

#[test]
fn headers_stay_dense_for_large_metadata() -> Result<()> {
    let mut slab = OperationSlab::<[u8; 257]>::new(9)?;
    assert_eq!(core::mem::size_of_val(&slab.headers[0]), 8);
    assert_eq!(slab.headers.len(), 9);
    assert_eq!(slab.metas.len(), 9);
    let storage = (slab.headers.as_ptr(), slab.metas.as_ptr());
    let keys = (0..9)
        .map(|value| slab.insert([value; 257], OperationKind::Single))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(slab.headers[8..].as_ptr().addr() - storage.0.addr(), 64);
    for (value, key) in keys.into_iter().enumerate() {
        assert_eq!(*slab.get(key)?, [value as u8; 257]);
        assert_eq!(slab.complete_and_remove(key)?.1, [value as u8; 257]);
    }
    assert_eq!((slab.headers.as_ptr(), slab.metas.as_ptr()), storage);
    assert_eq!(slab.available(), 9);
    Ok(())
}

#[test]
fn exhausted_builder_retires_on_panic() -> Result<()> {
    let mut slab = OperationSlab::<u8>::new(2)?;
    slab.headers[0] = slab.headers[0].patch(
        uarch::bits::BitPatch::EMPTY.with_field(SlotHeader::GENERATION, (u32::MAX - 1) as u64),
    );
    let escaped = std::cell::Cell::new(None);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _result = slab.insert_with(OperationKind::Single, |key| {
            escaped.set(Some(key));
            panic!("builder failed at final generation");
        });
    }));
    assert!(panic.is_err());
    assert_eq!(slab.available(), 1);
    assert!(slab.is_empty());
    let escaped = escaped
        .get()
        .ok_or(UringError::InvalidConfig("missing escaped key"))?;
    assert_eq!(escaped.generation(), u32::MAX);
    let other = slab.insert(7, OperationKind::Single)?;
    assert_eq!(other.slot(), 1);
    assert!(slab.get(escaped).is_err());
    assert_eq!(
        slab.insert(8, OperationKind::Single),
        Err(UringError::SqRingFull)
    );
    assert_eq!(slab.complete_and_remove(other)?, (OperationKind::Single, 7));
    assert_eq!(slab.available(), 1);
    Ok(())
}
