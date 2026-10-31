use super::*;

fn bytes() -> super::aligned::AlignedBytes {
    match super::aligned::AlignedBytes::allocate(32, 64) {
        Ok(bytes) => bytes,
        Err(error) => panic!("aligned allocation failed: {error}"),
    }
}

fn pool(count: u16) -> FixedBufferPool {
    let slots = (0..count)
        .map(|_| Slot {
            bytes: UnsafeCell::new(bytes()),
            state: Cell::new(State::Free),
            generation: Cell::new(0),
        })
        .collect();
    FixedBufferPool {
        inner: Rc::new(Inner {
            ring: NonNull::dangling(),
            slots,
            free: (0..count).rev().map(Cell::new).collect(),
            free_len: Cell::new(usize::from(count)),
            // A test registration without FFI: all operations stay in user space.
            registered: Cell::new(true),
            mock_registration: true,
        }),
    }
}

fn detach(pool: &FixedBufferPool) {
    pool.inner.registered.set(false);
}

#[test]
fn free_stack_preserves_capacity_and_order() -> Result<()> {
    let pool = pool(3);
    let allocation = pool.inner.free.as_ptr();
    for _ in 0..1024 {
        let first = pool.checkout()?;
        let second = pool.checkout()?;
        let third = pool.checkout()?;
        let (first_id, second_id) = (first.id(), second.id());
        assert_ne!(first_id, second_id);
        assert_ne!(first_id, third.id());
        assert_ne!(second_id, third.id());
        assert_eq!(pool.available(), 0);
        assert!(matches!(
            pool.checkout(),
            Err(UringError::FixedBuffersExhausted)
        ));
        drop(second);
        drop(first);
        let reused_first = pool.checkout()?;
        let reused_second = pool.checkout()?;
        assert_eq!(reused_first.id(), first_id);
        assert_eq!(reused_second.id(), second_id);
        drop((reused_first, reused_second, third));
        assert_eq!(pool.available(), 3);
        assert_eq!(pool.inner.free.as_ptr(), allocation);
    }
    detach(&pool);
    Ok(())
}

#[test]
fn cancelled_buffer_waits_for_target_completion() -> Result<()> {
    let pool = pool(2);
    let mut original = pool.checkout()?;
    original.as_mut_slice()[0] = 91;
    let original_id = original.id();
    let address = original.as_ptr();
    let mut waiting = original.into_in_flight();
    waiting.quarantine()?;
    waiting.quarantine()?;
    drop(waiting);
    let other = pool.checkout()?;
    assert_ne!(other.id(), original_id);
    assert!(pool.checkout().is_err());
    assert_eq!(pool.available(), 0);
    // SAFETY: This test never submits an SQE, so no kernel access exists.
    unsafe { pool.reclaim_completed(original_id)? };
    let recovered = pool.checkout()?;
    assert_eq!(recovered.id(), original_id);
    assert_eq!(recovered.as_ptr(), address);
    assert_eq!(recovered.as_slice()[0], 91);
    detach(&pool);
    Ok(())
}

#[test]
fn stale_token_preserves_reused_slot() -> Result<()> {
    let pool = pool(1);
    let old = pool.checkout()?.into_in_flight();
    let id = old.id();
    // SAFETY: No request was submitted; this simulates its final completion.
    unsafe { pool.reclaim_completed(id)? };
    let current = pool.checkout()?.into_in_flight();
    drop(old);
    // SAFETY: No kernel request references this buffer in this unit test.
    let returned = unsafe { current.complete()? };
    assert!(pool.checkout().is_err());
    drop(returned);
    assert_eq!(pool.available(), 1);
    // SAFETY: There is no kernel request; the state must reject double reclaim.
    let reclaimed_twice = unsafe { pool.reclaim_completed(id) };
    assert!(matches!(
        reclaimed_twice,
        Err(UringError::BufferNotInFlight(_))
    ));
    detach(&pool);
    Ok(())
}

#[test]
fn completion_returns_bytes_then_recycles_once() -> Result<()> {
    let pool = pool(1);
    let mut buffer = pool.checkout()?;
    buffer.as_mut_slice()[..4].copy_from_slice(b"data");
    let waiting = buffer.into_in_flight();
    assert_eq!(pool.available(), 0);
    // SAFETY: This test never makes the buffer accessible to the kernel.
    let completed = unsafe { waiting.complete()? };
    assert_eq!(&completed.as_slice()[..4], b"data");
    drop(completed);
    assert_eq!(pool.available(), 1);
    let checked_out = pool.checkout()?;
    // SAFETY: No kernel access exists; CheckedOut must reject reclamation.
    let prematurely_reclaimed = unsafe { pool.reclaim_completed(checked_out.id()) };
    assert!(matches!(
        prematurely_reclaimed,
        Err(UringError::BufferNotInFlight(_))
    ));
    drop(checked_out);
    assert_eq!(pool.available(), 1);
    detach(&pool);
    Ok(())
}

#[test]
fn cancel_order_preserves_reused_generation() -> Result<()> {
    for cancel_first in [true, false] {
        let pool = pool(1);
        let mut waiting = pool.checkout()?.into_in_flight();
        let id = waiting.id();
        waiting.quarantine()?;
        let mut replacement = None;
        for target_final in [!cancel_first, cancel_first] {
            if target_final {
                // SAFETY: No SQE is submitted in this unit state-machine
                // test; this event represents the target's own final CQE.
                unsafe { pool.reclaim_completed(id)? };
                replacement = Some(pool.checkout()?.into_in_flight());
            } else {
                assert_eq!(pool.available(), 0);
                assert!(matches!(
                    pool.checkout(),
                    Err(UringError::FixedBuffersExhausted)
                ));
                assert!(matches!(
                    pool.inner.slots[0].state.get(),
                    State::Quarantined | State::InFlight
                ));
            }
        }
        assert!(matches!(
            waiting.quarantine(),
            Err(UringError::BufferNotInFlight(_))
        ));
        drop(waiting);
        assert_eq!(pool.inner.slots[0].state.get(), State::InFlight);
        let replacement = replacement.ok_or(UringError::BufferNotInFlight(id.0))?;
        // SAFETY: The replacement also remained in user space throughout;
        // no kernel request or zero-copy notification can still access it.
        drop(unsafe { replacement.complete()? });
        assert_eq!(pool.available(), 1);
        detach(&pool);
    }
    Ok(())
}

#[test]
fn spent_generation_retires_without_blocking_slots() -> Result<()> {
    let mut pool = pool(2);
    pool.inner.slots[0].generation.set(u64::MAX);
    assert!(matches!(
        pool.checkout(),
        Err(UringError::Syscall {
            errno: libc::EOVERFLOW,
            ..
        })
    ));
    assert_eq!(pool.inner.slots[0].state.get(), State::Retired);
    assert_eq!(pool.available(), 1);
    let remaining = pool.checkout()?;
    assert_eq!(remaining.id(), BufferId(1));
    assert!(pool.unregister().is_err());
    drop(remaining);
    pool.inner.slots[1].generation.set(u64::MAX);
    assert!(matches!(
        pool.checkout(),
        Err(UringError::Syscall {
            errno: libc::EOVERFLOW,
            ..
        })
    ));
    assert_eq!(pool.inner.slots[1].state.get(), State::Retired);
    assert_eq!(pool.available(), 0);
    assert!(matches!(
        pool.checkout(),
        Err(UringError::FixedBuffersExhausted)
    ));
    pool.unregister()?;
    assert!(!pool.inner.registered.get());
    Ok(())
}

#[test]
fn stale_completion_preserves_current_buffer() -> Result<()> {
    let pool = pool(1);
    let old = pool.checkout()?.into_in_flight();
    let id = old.id();
    let old_generation = old.generation();
    // SAFETY: No SQE was submitted, so this operation has no kernel access.
    unsafe { pool.reclaim_completed_generation(id, old_generation)? };
    let current = pool.checkout()?.into_in_flight();
    let current_generation = current.generation();
    assert_ne!(old_generation, current_generation);
    drop(old);
    // SAFETY: The old operation never reached the kernel; only its stale
    // identity is supplied, and rejection must preserve the current owner.
    let stale = unsafe { pool.reclaim_completed_generation(id, old_generation) };
    assert!(matches!(stale, Err(UringError::BufferNotInFlight(_))));
    assert_eq!(pool.available(), 0);
    assert_eq!(pool.inner.slots[0].state.get(), State::InFlight);
    // SAFETY: The current operation also remained entirely in user space.
    drop(unsafe { current.complete()? });
    assert_eq!(pool.available(), 1);
    detach(&pool);
    Ok(())
}

#[test]
fn unregister_rejects_owned_and_quarantined_slots() -> Result<()> {
    let mut pool = pool(1);
    let checked_out = pool.checkout()?;
    assert!(pool.unregister().is_err());
    let mut waiting = checked_out.into_in_flight();
    assert!(pool.unregister().is_err());
    waiting.quarantine()?;
    assert!(pool.unregister().is_err());
    // SAFETY: No SQE was submitted, so no DMA or notification remains.
    unsafe { pool.reclaim_completed(waiting.id())? };
    assert!(matches!(
        waiting.quarantine(),
        Err(UringError::BufferNotInFlight(_))
    ));
    pool.unregister()?;
    pool.unregister()?;
    assert!(pool.checkout().is_err());
    Ok(())
}
