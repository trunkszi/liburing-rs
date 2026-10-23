//! Public generation and DMA lifetime contracts.

use std::{cell::Cell, rc::Rc};

use liburing::{
    OperationPayload, Result, UringError,
    operation_slab::{OperationKey, OperationKind, OperationSlab, OperationState},
};

const MAX_CAPACITY: usize = 1 << 24;
const SLOT_MASK: u64 = (1 << 24) - 1;

const MORE: u32 = 2;
const NOTIFICATION: u32 = 8;

#[test]
fn stale_keys_cannot_read_mutate_complete_cancel_or_remove_new_ownership() -> Result<()> {
    let mut slab = OperationSlab::new(1)?;
    let old = slab.insert(17, OperationKind::Single)?;
    assert_eq!(OperationKey::from_payload(old.payload())?, old);
    assert!(slab.complete(old, 1, 0)?);
    assert_eq!(slab.remove(old)?, 17);
    let current = slab.insert(29, OperationKind::Single)?;
    assert_eq!(old.slot(), current.slot());
    assert_eq!(current.generation(), old.generation() + 1);
    assert!(slab.get(old).is_err());
    assert!(slab.get_mut(old).is_err());
    assert!(slab.complete(old, -125, 0).is_err());
    assert!(slab.mark_canceling(old).is_err());
    assert!(slab.remove(old).is_err());
    assert_eq!(*slab.get(current)?, 29);
    assert_eq!(slab.state(current)?, OperationState::InFlight);
    assert!(slab.complete(current, 0, 0)?);
    assert_eq!(slab.remove(current)?, 29);
    Ok(())
}

#[test]
fn cancel_ack_and_target_are_independent_in_both_completion_orders() -> Result<()> {
    for ack_first in [false, true] {
        let mut slab = OperationSlab::new(2)?;
        let target = slab.insert("target", OperationKind::Single)?;
        let control = slab.insert("cancel", OperationKind::CancelControl)?;
        slab.mark_canceling(target)?;
        slab.mark_canceling(target)?;
        assert!(slab.remove(target).is_err());
        if ack_first {
            assert!(slab.complete(control, 0, 0)?);
            assert_eq!(slab.remove(control)?, "cancel");
            assert_eq!(slab.state(target)?, OperationState::Canceling);
        }
        assert!(slab.complete(target, -125, 0)?);
        assert_eq!(slab.remove(target)?, "target");
        if !ack_first {
            assert_eq!(slab.state(control)?, OperationState::InFlight);
            assert!(slab.complete(control, -2, 0)?);
            assert_eq!(slab.remove(control)?, "cancel");
        }
        assert!(slab.is_empty());
    }
    Ok(())
}

#[test]
fn multishot_more_retains_signed_errors_and_canceling_ownership() -> Result<()> {
    let mut slab = OperationSlab::new(1)?;
    let target = slab.insert(vec![1, 2], OperationKind::Multishot)?;
    for result in [8, 0, -105] {
        assert!(!slab.complete(target, result, MORE)?);
        assert_eq!(slab.state(target)?, OperationState::InFlight);
        assert!(slab.remove(target).is_err());
    }
    slab.mark_canceling(target)?;
    assert!(!slab.complete(target, 8, MORE)?);
    assert_eq!(slab.state(target)?, OperationState::Canceling);
    assert!(slab.complete(target, -125, 0)?);
    assert_eq!(slab.remove(target)?, vec![1, 2]);
    Ok(())
}

#[test]
fn zero_copy_requires_main_and_notification_in_either_order() -> Result<()> {
    for notification_first in [false, true] {
        let mut slab = OperationSlab::new(1)?;
        let key = slab.insert(37, OperationKind::ZeroCopy)?;
        slab.mark_canceling(key)?;
        let first = if notification_first {
            NOTIFICATION
        } else {
            MORE
        };
        assert!(!slab.complete(key, 37, first)?);
        assert!(slab.remove(key).is_err());
        assert_eq!(
            slab.state(key)?,
            if notification_first {
                OperationState::Canceling
            } else {
                OperationState::AwaitingZeroCopyNotification
            }
        );
        slab.mark_canceling(key)?;
        assert!(slab.complete(
            key,
            0,
            if notification_first {
                MORE
            } else {
                NOTIFICATION
            }
        )?);
        assert!(slab.complete(key, 0, NOTIFICATION).is_err());
        assert_eq!(slab.remove(key)?, 37);
    }
    Ok(())
}

#[test]
fn zero_copy_without_more_finishes_and_duplicate_or_invalid_cqes_are_atomic() -> Result<()> {
    let mut slab = OperationSlab::new(2)?;
    let ordinary = slab.insert(1, OperationKind::Single)?;
    let zc = slab.insert(2, OperationKind::ZeroCopy)?;
    assert!(slab.complete(ordinary, 0, NOTIFICATION).is_err());
    assert_eq!(slab.state(ordinary)?, OperationState::InFlight);
    assert!(slab.complete(zc, 0, NOTIFICATION | MORE).is_err());
    assert!(!slab.complete(zc, 0, NOTIFICATION)?);
    assert!(slab.complete(zc, 0, NOTIFICATION).is_err());
    assert!(slab.complete(zc, -22, 0)?);
    assert_eq!(slab.remove(zc)?, 2);
    assert!(slab.complete(ordinary, 0, 0)?);
    assert_eq!(slab.remove(ordinary)?, 1);
    let zc = slab.insert(3, OperationKind::ZeroCopy)?;
    assert!(slab.complete(zc, -22, 0)?);
    assert_eq!(slab.remove(zc)?, 3);
    Ok(())
}

struct DropCounter(Rc<Cell<usize>>);

impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn noncopy_metadata_survives_cancel_and_stale_cqes_until_explicit_final_removal() -> Result<()> {
    let drops = Rc::new(Cell::new(0));
    let mut slab = OperationSlab::new(1)?;
    let key = slab.insert(DropCounter(Rc::clone(&drops)), OperationKind::ZeroCopy)?;
    slab.mark_canceling(key)?;
    assert!(!slab.complete(key, 1, MORE)?);
    assert_eq!(drops.get(), 0);
    assert!(slab.remove(key).is_err());
    assert!(slab.complete(key, 0, NOTIFICATION)?);
    assert_eq!(drops.get(), 0);
    drop(slab.remove(key)?);
    assert_eq!(drops.get(), 1);
    let current = slab.insert(DropCounter(Rc::clone(&drops)), OperationKind::Single)?;
    assert!(slab.complete(key, -125, 0).is_err());
    assert_eq!(drops.get(), 1);
    // SAFETY: This test uses no ring or SQEs, so no kernel access is possible.
    unsafe { slab.retire_after_ring_close() };
    assert_eq!(drops.get(), 2);
    assert!(slab.get(current).is_err());
    let next = slab.insert(DropCounter(Rc::clone(&drops)), OperationKind::Single)?;
    assert_ne!(next.generation(), current.generation());
    // SAFETY: Neither this key nor any resource pointer was published.
    drop(unsafe { slab.discard_unsubmitted(next)? });
    assert_eq!(drops.get(), 3);
    Ok(())
}

#[test]
fn live_drop_is_fail_closed_and_completed_drop_releases_metadata() -> Result<()> {
    let drops = Rc::new(Cell::new(0));
    let mut slab = OperationSlab::new(2)?;
    slab.insert(DropCounter(Rc::clone(&drops)), OperationKind::Single)?;
    let done = slab.insert(DropCounter(Rc::clone(&drops)), OperationKind::Single)?;
    assert!(slab.complete(done, 0, 0)?);
    drop(slab);
    assert_eq!(drops.get(), 1);
    Ok(())
}

#[test]
fn encoding_and_fixed_capacity_rejections_do_not_publish_slots() -> Result<()> {
    assert!(OperationSlab::<()>::new(0).is_err());
    assert!(OperationSlab::<()>::new(MAX_CAPACITY + 1).is_err());
    for raw in [0, SLOT_MASK, OperationPayload::MAX_RAW + 1, u64::MAX] {
        assert!(OperationKey::from_payload(OperationPayload(raw)).is_err());
    }
    let boundary = OperationKey::from_payload(OperationPayload(OperationPayload::MAX_RAW))?;
    assert_eq!(boundary.slot(), MAX_CAPACITY - 1);
    assert_eq!(boundary.generation(), u32::MAX);
    let mut slab = OperationSlab::new(2)?;
    let first = slab.insert(5, OperationKind::Single)?;
    let second = slab.insert(8, OperationKind::Single)?;
    assert_eq!(slab.len(), 2);
    assert_eq!(
        slab.iter()
            .map(|(key, value)| (key, *value))
            .collect::<Vec<_>>(),
        [(first, 5), (second, 8)]
    );
    *slab.get_mut(first)? = 13;
    assert_eq!(*slab.get(first)?, 13);
    assert_eq!(
        slab.insert(21, OperationKind::Single),
        Err(UringError::SqRingFull)
    );
    for key in [first, second] {
        assert!(slab.complete(key, 0, 0)?);
        slab.remove(key)?;
    }
    assert!(slab.is_empty());
    Ok(())
}
