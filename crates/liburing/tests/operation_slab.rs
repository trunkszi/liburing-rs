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
fn stale_keys_preserve_reused_ownership() -> Result<()> {
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
fn cancel_ack_preserves_target_ownership() -> Result<()> {
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
fn multishot_errors_preserve_canceling_ownership() -> Result<()> {
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
fn zero_copy_preserves_both_completion_orders() -> Result<()> {
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
fn zero_copy_rejects_invalid_completions() -> Result<()> {
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
fn metadata_survives_until_final_removal() -> Result<()> {
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
fn live_drop_retains_pending_metadata() -> Result<()> {
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
fn invalid_encoding_preserves_fixed_capacity() -> Result<()> {
    assert!(OperationSlab::<()>::new(0).is_err());
    assert!(OperationSlab::<()>::new(MAX_CAPACITY).is_err());
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

#[test]
fn insert_with_builds_reserved_identity() -> Result<()> {
    let mut slab = OperationSlab::new(1)?;
    let called = Cell::new(0);
    let key = slab.insert_with(OperationKind::Single, |key| {
        called.set(called.get() + 1);
        (key, 41)
    })?;
    assert_eq!(called.get(), 1);
    assert_eq!(*slab.get(key)?, (key, 41));
    assert_eq!(
        slab.insert_with(OperationKind::Single, |_| panic!("full builder invoked")),
        Err(UringError::SqRingFull)
    );
    assert_eq!(
        slab.complete_and_remove(key)?,
        (OperationKind::Single, (key, 41))
    );
    let next = slab.insert_with(OperationKind::Multishot, |key| (key, 42))?;
    assert_eq!(next.slot(), key.slot());
    assert_eq!(next.generation(), key.generation() + 1);
    assert!(slab.complete_and_remove(key).is_err());
    assert_eq!(*slab.get(next)?, (next, 42));
    assert_eq!(slab.complete_and_remove(next)?.0, OperationKind::Multishot);
    Ok(())
}

#[test]
fn builder_panic_preserves_slot_credit() -> Result<()> {
    let mut slab = OperationSlab::<u64>::new(1)?;
    let escaped = Cell::new(None);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _result = slab.insert_with(OperationKind::Single, |key| {
            escaped.set(Some(key));
            panic!("builder failed");
        });
    }));
    assert!(panic.is_err());
    assert_eq!(slab.available(), 1);
    assert!(slab.is_empty());
    let escaped = escaped
        .get()
        .ok_or(UringError::InvalidConfig("missing escaped key"))?;
    let key = slab.insert(7, OperationKind::Single)?;
    assert_eq!(key.slot(), escaped.slot());
    assert_eq!(key.generation(), escaped.generation() + 1);
    assert!(slab.get(escaped).is_err());
    assert_eq!(slab.complete_and_remove(key)?, (OperationKind::Single, 7));
    Ok(())
}

#[test]
fn fused_completion_releases_each_kind() -> Result<()> {
    let drops = Rc::new(Cell::new(0));
    for kind in [
        OperationKind::Single,
        OperationKind::Multishot,
        OperationKind::CancelControl,
    ] {
        let mut slab = OperationSlab::new(1)?;
        let key = slab.insert_with(kind, |_| DropCounter(Rc::clone(&drops)))?;
        slab.mark_canceling(key)?;
        let (removed_kind, metadata) = slab.complete_and_remove(key)?;
        assert_eq!(removed_kind, kind);
        assert!(slab.is_empty());
        assert_eq!(slab.available(), 1);
        assert!(slab.complete_and_remove(key).is_err());
        drop(metadata);
    }
    assert_eq!(drops.get(), 3);
    let mut slab = OperationSlab::new(1)?;
    let key = slab.insert(1, OperationKind::Single)?;
    assert!(slab.complete(key, 0, 0)?);
    assert!(slab.complete_and_remove(key).is_err());
    assert_eq!(slab.remove(key)?, 1);
    Ok(())
}

#[test]
fn fused_main_preserves_notification_ownership() -> Result<()> {
    let mut slab = OperationSlab::new(1)?;
    let key = slab.insert(1, OperationKind::ZeroCopy)?;
    assert!(!slab.complete(key, 1, MORE)?);
    assert!(slab.complete_and_remove(key).is_err());
    assert_eq!(
        slab.state(key)?,
        OperationState::AwaitingZeroCopyNotification
    );
    assert_eq!(slab.available(), 0);
    assert!(slab.complete(key, 0, NOTIFICATION)?);
    assert_eq!(slab.remove(key)?, 1);
    let key = slab.insert(2, OperationKind::ZeroCopy)?;
    assert!(!slab.complete(key, 0, NOTIFICATION)?);
    slab.mark_canceling(key)?;
    assert_eq!(slab.complete_and_remove(key)?, (OperationKind::ZeroCopy, 2));
    Ok(())
}

#[test]
fn ring_close_panic_preserves_remaining_ownership() -> Result<()> {
    struct Metadata {
        id: usize,
        drops: Rc<std::cell::RefCell<Vec<usize>>>,
    }
    impl Drop for Metadata {
        fn drop(&mut self) {
            self.drops.borrow_mut().push(self.id);
            if self.id == 1 {
                panic!("metadata destructor failed");
            }
        }
    }
    let drops = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut slab = OperationSlab::new(2)?;
    let first = slab.insert(
        Metadata {
            id: 0,
            drops: Rc::clone(&drops),
        },
        OperationKind::Single,
    )?;
    slab.insert(
        Metadata {
            id: 1,
            drops: Rc::clone(&drops),
        },
        OperationKind::Single,
    )?;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: This fixture never publishes metadata to a kernel ring.
        unsafe { slab.retire_after_ring_close() };
    }));
    assert!(panic.is_err());
    assert_eq!(slab.len(), 1);
    assert_eq!(slab.available(), 1);
    assert_eq!(slab.get(first)?.id, 0);
    assert_eq!(*drops.borrow(), [1]);
    // SAFETY: The fixture remains unpublished after the first destructor panicked.
    unsafe { slab.retire_after_ring_close() };
    assert!(slab.is_empty());
    assert_eq!(slab.available(), 2);
    drop(slab);
    assert_eq!(*drops.borrow(), [1, 0]);
    Ok(())
}
