//! Direct generation cancellation and borrowed dispatch through real kernel CQEs.

use std::{
    io::{Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    rc::Rc,
    time::{Duration, Instant},
};

use liburing::{
    Completion, CompletionDispatcher, OperationId, Proactor, ProactorConfig, Result,
    SubmissionContext, SubsystemId, backend,
    ops::{net::prep_poll_multishot, prep_nop},
};

#[derive(Default)]
struct Recorder {
    observed: Vec<Completion>,
}

impl CompletionDispatcher for Recorder {
    fn dispatch(&mut self, cqe: Completion, context: &mut SubmissionContext<'_>) -> Result<()> {
        self.observed.push(cqe);
        if cqe.flags & backend::IORING_CQE_F_MORE != 0 {
            let key =
                liburing::operation_slab::OperationKey::from_payload(cqe.operation_id.payload())?;
            assert!(context.cancel_key(key)?);
        }
        Ok(())
    }
}

#[test]
fn multishot_keyed_cancel_and_trait_object_borrow_reach_exact_idle() -> Result<()> {
    let (socket, mut peer) = UnixStream::pair()?;
    let socket = Rc::new(OwnedFd::from(socket));
    let mut proactor = Proactor::new(ProactorConfig {
        ..ProactorConfig::default()
    })?;
    let key =
        proactor.prepare_keyed_owned_sqe_with(SubsystemId(4), Rc::clone(&socket), None, |sqe| {
            // SAFETY: The tracked operation retains the descriptor through its final poll CQE.
            unsafe { prep_poll_multishot(sqe, socket.as_raw_fd(), libc::POLLIN as u32) };
        })?;
    let identity = OperationId::pack(SubsystemId(4), key.payload());
    proactor.submit()?;
    peer.write_all(b"ready")?;
    let mut recorder = Recorder::default();
    let deadline = Instant::now() + Duration::from_secs(2);
    while recorder.observed.is_empty() {
        assert!(Instant::now() < deadline, "multishot poll did not complete");
        let mut borrowed: &mut dyn CompletionDispatcher = &mut recorder;
        proactor.poll_completions(1, &mut borrowed)?;
    }
    assert_eq!(proactor.operation_count(), 1);
    assert_eq!(proactor.pending_cancel_count(), 1);
    assert!(!proactor.is_idle());
    assert_eq!(Rc::strong_count(&socket), 2);
    while !proactor.is_idle() {
        assert!(
            Instant::now() < deadline,
            "target and control CQEs did not drain"
        );
        proactor.tick(&mut &mut recorder)?;
    }
    assert_eq!(proactor.pending_cancel_count(), 0);
    assert!(
        recorder
            .observed
            .iter()
            .all(|cqe| cqe.operation_id == identity)
    );
    assert!(
        recorder
            .observed
            .iter()
            .any(|cqe| cqe.flags & backend::IORING_CQE_F_MORE != 0)
    );
    assert_eq!(
        recorder.observed.last().map(|cqe| cqe.result),
        Some(-libc::ECANCELED)
    );
    assert_eq!(Rc::strong_count(&socket), 1);
    assert!(!proactor.cancel_key(key)?);
    // Reuse a slab slot and reject the old generation without canceling its successor.
    let next = proactor.prepare_keyed_sqe_with(SubsystemId(4), |sqe| {
        // SAFETY: Exclusive initialized SQE storage; NOP has no raw operands.
        unsafe { prep_nop(sqe) };
    })?;
    assert_ne!(next, key);
    assert!(!proactor.cancel_key(key)?);
    while !proactor.is_idle() {
        assert!(Instant::now() < deadline, "reused key did not complete");
        proactor.tick(&mut recorder)?;
    }
    Ok(())
}

#[test]
fn callback_keyed_buffer_send_releases_dma_and_preserves_generated_identity() -> Result<()> {
    let (socket, mut peer) = UnixStream::pair()?;
    let mut proactor = Proactor::new(ProactorConfig {
        ..ProactorConfig::default()
    })?;
    proactor.configure_fixed_buffers(1, 64)?;
    let seed = proactor.prepare_keyed_sqe_with(SubsystemId(5), |sqe| {
        // SAFETY: Exclusive initialized SQE storage; NOP has no raw operands.
        unsafe { prep_nop(sqe) };
    })?;
    let mut send_key = None;
    let mut sent = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !sent {
        assert!(
            Instant::now() < deadline,
            "callback keyed send did not complete"
        );
        proactor.tick(&mut |cqe: Completion, ctx: &mut SubmissionContext<'_>| {
            if cqe.operation_id == OperationId::pack(SubsystemId(5), seed.payload()) {
                // SAFETY: The checked-out handle immediately becomes a tracked token.
                let mut buffer = unsafe { ctx.fixed_buffers() }?.checkout()?;
                buffer.as_mut_slice()[..4].copy_from_slice(b"ping");
                let pointer = buffer.as_ptr();
                send_key = Some(ctx.prepare_keyed_buffer_sqe_with(
                    SubsystemId(6),
                    buffer.into_in_flight(),
                    |sqe| {
                        // SAFETY: The ring retains this DMA token; socket outlives the ring.
                        unsafe {
                            liburing::ops::net::prep_send_fixed(
                                sqe,
                                socket.as_raw_fd(),
                                pointer,
                                4,
                                0,
                            )
                        };
                    },
                )?);
            } else {
                let key = send_key.expect("send must be staged before completion");
                assert_eq!(
                    cqe.operation_id,
                    OperationId::pack(SubsystemId(6), key.payload())
                );
                assert_eq!(cqe.result, 4);
                sent = true;
            }
            Ok(())
        })?;
    }
    peer.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut payload = [0; 4];
    peer.read_exact(&mut payload)?;
    assert_eq!(&payload, b"ping");
    // SAFETY: This borrow creates no detached handles and stays within ring lifetime.
    assert_eq!(unsafe { proactor.fixed_buffers() }?.available(), 1);
    assert!(proactor.is_idle());
    Ok(())
}

mod preparation_contracts {

    use std::{
        os::{fd::OwnedFd, unix::net::UnixStream},
        panic::{AssertUnwindSafe, catch_unwind},
        time::Instant,
    };

    use liburing::{
        OperationPayload, UringError, backend::RawSqe, fixed_buffers::InFlightWaitingBuffer,
        operation_slab::OperationKey,
    };

    use super::*;

    fn ring(capacity: usize) -> Result<Proactor> {
        Proactor::new(ProactorConfig {
            operation_capacity: capacity,
            staged_capacity: capacity,
            ..ProactorConfig::default()
        })
    }

    fn nop(sqe: *mut RawSqe) {
        // SAFETY: Preparation supplies exclusive initialized storage; NOP has no operands.
        unsafe { prep_nop(sqe) };
    }

    fn token(proactor: &Proactor) -> Result<InFlightWaitingBuffer> {
        // SAFETY: Each derived token is immediately staged or rolled back before ring drop.
        Ok(unsafe { proactor.fixed_buffers() }?
            .checkout()?
            .into_in_flight())
    }

    fn available(proactor: &Proactor) -> Result<usize> {
        // SAFETY: This borrow creates no handles that could outlive the ring.
        Ok(unsafe { proactor.fixed_buffers() }?.available())
    }

    #[test]
    fn every_keyed_preparation_retains_resources_without_identity_map_entries() -> Result<()> {
        let mut proactor = ring(6)?;
        proactor.configure_fixed_buffers(4, 64)?;
        let (socket, _peer) = UnixStream::pair()?;
        let socket = Rc::new(OwnedFd::from(socket));
        let subsystem = SubsystemId(7);
        let seed = proactor.prepare_keyed_sqe_with(subsystem, nop)?;
        let mut keys = vec![seed];
        keys.push(proactor.prepare_keyed_buffer_sqe_with(subsystem, token(&proactor)?, nop)?);
        keys.push(proactor.prepare_keyed_owned_sqe_with(
            subsystem,
            Rc::clone(&socket),
            Some(token(&proactor)?),
            nop,
        )?);
        for key in &keys {
            assert!(
                proactor
                    .operation_key(OperationId::pack(subsystem, key.payload()))
                    .is_err()
            );
        }
        assert_eq!(available(&proactor)?, 2);
        assert_eq!(Rc::strong_count(&socket), 2);
        assert!(!proactor.is_idle());
        let mut observed = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while observed.len() < 6 {
            assert!(Instant::now() < deadline, "keyed NOP deadline elapsed");
            proactor.tick(
                &mut |cqe: Completion, context: &mut SubmissionContext<'_>| {
                    assert_eq!(cqe.result, 0);
                    observed.push(cqe.operation_id);
                    if cqe.operation_id == OperationId::pack(subsystem, seed.payload()) {
                        // SAFETY: Each detached token is immediately retained in this context.
                        let pool = unsafe { context.fixed_buffers() }?;
                        let buffer = pool.checkout()?.into_in_flight();
                        let owned = pool.checkout()?.into_in_flight();
                        keys.push(context.prepare_keyed_sqe_with(subsystem, nop)?);
                        keys.push(context.prepare_keyed_buffer_sqe_with(subsystem, buffer, nop)?);
                        keys.push(context.prepare_keyed_owned_sqe_with(
                            subsystem,
                            Rc::clone(&socket),
                            Some(owned),
                            nop,
                        )?);
                    }
                    Ok(())
                },
            )?;
        }
        for key in keys {
            assert!(observed.contains(&OperationId::pack(subsystem, key.payload())));
            assert!(!proactor.cancel_key(key)?);
        }
        assert!(proactor.is_idle());
        assert_eq!(proactor.pending_cancel_count(), 0);
        assert_eq!(available(&proactor)?, 4);
        assert_eq!(Rc::strong_count(&socket), 1);
        Ok(())
    }

    #[test]
    fn keyed_rejection_and_preparation_panic_return_dma_and_descriptor_ownership() -> Result<()> {
        let mut proactor = ring(1)?;
        proactor.configure_fixed_buffers(1, 64)?;
        let (socket, _peer) = UnixStream::pair()?;
        let socket = Rc::new(OwnedFd::from(socket));
        assert!(
            proactor
                .prepare_keyed_owned_sqe_with(
                    SubsystemId::INTERNAL,
                    Rc::clone(&socket),
                    Some(token(&proactor)?),
                    nop,
                )
                .is_err()
        );
        assert_eq!(Rc::strong_count(&socket), 1);
        assert_eq!(available(&proactor)?, 1);
        assert!(
            proactor
                .prepare_keyed_buffer_sqe_with(SubsystemId(1), token(&proactor)?, |sqe| {
                    nop(sqe);
                    // SAFETY: Exclusive initialized SQE; validation rejects this flag before
                    // publication.
                    unsafe { (*sqe).flags = backend::IOSQE_CQE_SKIP_SUCCESS as u8 };
                })
                .is_err()
        );
        assert_eq!(available(&proactor)?, 1);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let buffer = token(&proactor).expect("available buffer");
                let _key = proactor
                    .prepare_keyed_buffer_sqe_with(SubsystemId(1), buffer, |_| {
                        panic!("preparation failed before publication")
                    })
                    .expect("preparation must panic");
            }))
            .is_err()
        );
        assert_eq!(available(&proactor)?, 1);
        proactor.prepare_keyed_sqe_with(SubsystemId(1), nop)?;
        assert_eq!(
            proactor.prepare_keyed_buffer_sqe_with(SubsystemId(1), token(&proactor)?, |_| panic!(
                "capacity must reject first"
            ),),
            Err(UringError::SqRingFull)
        );
        assert_eq!(available(&proactor)?, 1);
        proactor.shutdown()?;
        assert!(proactor.is_idle());
        assert!(!proactor.cancel_key(OperationKey::from_payload(OperationPayload(1 << 24))?)?);
        Ok(())
    }

    #[test]
    fn keyed_retirement_preserves_a_colliding_caller_identity() -> Result<()> {
        let mut proactor = ring(2)?;
        let key = proactor.prepare_keyed_sqe_with(SubsystemId(1), nop)?;
        proactor.submit()?;
        let identity = OperationId::pack(SubsystemId(1), key.payload());
        proactor.alloc_sqe(identity)?;
        let mapped = proactor.operation_key(identity)?;
        assert_ne!(mapped, key);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut completed = false;
        while !completed {
            assert!(
                Instant::now() < deadline,
                "keyed retirement deadline elapsed"
            );
            proactor.poll_completions(
                1,
                &mut |cqe: Completion, _: &mut SubmissionContext<'_>| {
                    assert_eq!(cqe.operation_id, identity);
                    completed = true;
                    Ok(())
                },
            )?;
        }
        assert_eq!(proactor.operation_key(identity)?, mapped);
        assert_eq!(proactor.operation_count(), 1);
        proactor.shutdown()?;
        assert!(proactor.operation_key(identity).is_err());
        Ok(())
    }

    #[test]
    fn idle_requires_staging_operations_and_both_cancel_counters_to_drain() -> Result<()> {
        let mut proactor = ring(1)?;
        assert!(proactor.is_idle());
        assert_eq!(proactor.remaining_capacity(), 1);
        let key = proactor.prepare_keyed_sqe_with(SubsystemId(1), nop)?;
        assert_eq!(proactor.remaining_capacity(), 0);
        assert!(!proactor.is_idle());
        assert!(proactor.cancel_key(key)?);
        assert_eq!(proactor.pending_cancel_count(), 1);
        assert!(!proactor.is_idle());
        proactor.shutdown()?;
        assert!(proactor.is_idle());
        assert_eq!(proactor.remaining_capacity(), 0);
        assert_eq!(proactor.pending_cancel_count(), 0);
        Ok(())
    }
}
