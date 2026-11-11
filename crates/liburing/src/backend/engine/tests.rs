//! Native control-plane rollback and invalid-handle regression tests.
use super::IoUring;
use crate::backend::{sys::params::IORING_ENTER_REGISTERED_RING, types::SubmitArgs};

#[test]
fn missing_handle_returns_ebadf() -> std::io::Result<()> {
    let mut ring = IoUring::new(2)?;
    let retained_handle = ring.inner.storage.handle.take();
    // SAFETY: Null arguments with size 8 select the ordinary no-signal-mask ABI.
    // The retained handle keeps the mapping live; the facade must reject its absent handle.
    let raw = unsafe { ring.submitter().enter_raw(0, 0, 0, core::ptr::null(), 8) };
    assert_eq!(
        raw.map_err(|error| error.raw_os_error()),
        Err(Some(libc::EBADF))
    );
    let submitted = ring.submitter().submit_and_wait(0);
    assert_eq!(
        submitted.map_err(|error| error.raw_os_error()),
        Err(Some(libc::EBADF))
    );
    let extended = ring.submitter().submit_with_args(0, &SubmitArgs::new());
    assert_eq!(
        extended.map_err(|error| error.raw_os_error()),
        Err(Some(libc::EBADF))
    );
    ring.inner.storage.handle = retained_handle;
    Ok(())
}

#[test]
fn failed_index_adoption_releases_fresh_slot() -> std::io::Result<()> {
    let mut ring = IoUring::new(2)?;
    let Some(index) = ring.register_owned_index() else {
        return Err(std::io::Error::other("initial ring registration failed"));
    };
    for _ in 0..32 {
        assert_eq!(ring.register_owned_index(), None);
        assert_eq!(
            ring.inner.handle().map(|handle| handle.enter_target()),
            Some((index as i32, IORING_ENTER_REGISTERED_RING))
        );
    }
    // Linux provides 16 task-local ring slots. Rejected adoptions must leave
    // every slot other than the original registration available to new owners.
    let mut others = Vec::with_capacity(15);
    for _ in 0..15 {
        let mut other = IoUring::new(2)?;
        assert!(other.register_owned_index().is_some());
        others.push(other);
    }
    let mut exhausted = IoUring::new(2)?;
    assert_eq!(exhausted.register_owned_index(), None);
    drop(others);
    assert!(exhausted.register_owned_index().is_some());
    Ok(())
}
