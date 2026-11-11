//! Cold native ring negotiation and persistent registered-index adoption.
use crate::{
    Result,
    backend::{IoUring, setup},
    config::{KernelFeatures, ProactorConfig},
};

pub(super) fn register_ring_fd(ring: &mut IoUring) -> Option<u32> {
    ring.register_owned_index()
}

pub(super) fn create(config: ProactorConfig) -> Result<(IoUring, KernelFeatures)> {
    let native = setup::negotiate(config)?;
    let params = native.params();
    let features = KernelFeatures {
        setup_flags: params.flags,
        features: params.features,
    };
    Ok((IoUring::from_native(native), features))
}

static NEXT_OWNER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(super) fn next_owner_id() -> Result<u64> {
    NEXT_OWNER_ID
        .try_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |id| id.checked_add(1),
        )
        .map_err(|_| crate::UringError::InvalidConfig("proactor owner identities exhausted"))
}
