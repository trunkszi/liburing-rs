use super::*;

fn null_file() -> OwnedFd {
    match std::fs::File::open("/dev/null") {
        Ok(file) => file.into(),
        Err(error) => panic!("opening /dev/null: {error}"),
    }
}

struct FakeTable(FixedFileTable);

impl std::ops::Deref for FakeTable {
    type Target = FixedFileTable;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for FakeTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for FakeTable {
    fn drop(&mut self) {
        self.0.registered = false;
    }
}

fn fake_table() -> FakeTable {
    FakeTable(FixedFileTable {
        ring: RegisterTarget::VfsFd(-1),
        entries: vec![Some(10), None, Some(12)],
        retained: vec![Some(null_file()), None, Some(null_file())],
        free: vec![1],
        registered: true,
        alloc_range: None,
        single_thread: PhantomData,
    })
}

#[test]
fn replacement_failure_restores_original_slots() {
    let mut table = fake_table();
    let originals: Vec<_> = table
        .retained
        .iter()
        .map(|fd| fd.as_ref().map_or(-1, AsRawFd::as_raw_fd))
        .collect();
    let mut expanded = originals.clone();
    expanded.resize(6, -1);
    let mut calls = Vec::new();
    let result = table.grow_with(4, |files| {
        calls.push(files.map(<[RawFd]>::to_vec));
        if calls.len() == 2 {
            Err(errno(EINVAL))
        } else {
            Ok(())
        }
    });
    assert_eq!(result, Err(errno(EINVAL)));
    assert!(table.registered);
    assert!(table.is_registered());
    assert_eq!(table.entries, [Some(10), None, Some(12)]);
    assert_eq!(table.free, [1]);
    assert_eq!(calls, [None, Some(expanded), Some(originals)]);
}

#[test]
fn failed_rollback_invalidates_table() {
    use std::io::Read;
    let (retained, mut peer) = match std::os::unix::net::UnixStream::pair() {
        Ok(pair) => pair,
        Err(error) => panic!("creating socket pair: {error}"),
    };
    assert!(peer.set_nonblocking(true).is_ok());
    let mut table = fake_table();
    table.retained[0] = Some(retained.into());
    let mut calls = 0;
    assert!(
        table
            .grow_with(4, |_| {
                calls += 1;
                if calls == 1 {
                    Ok(())
                } else {
                    Err(errno(EINVAL))
                }
            })
            .is_err()
    );
    assert_eq!(calls, 3);
    assert!(!table.registered);
    assert!(!table.is_registered());
    assert_eq!(table.capacity(), 0);
    assert!(table.entries.is_empty());
    assert!(table.free.is_empty());
    assert!(matches!(peer.read(&mut [0]), Ok(0)));
    assert_eq!(table.get(UringFileSlot(0)), None);
    assert_eq!((table.len(), table.available()), (0, 0));
    assert!(table.insert(10).is_err());
    assert!(table.grow(8).is_err());
}

#[test]
fn reclaim_updates_kernel_slot_before_releasing() {
    let mut table = fake_table();
    assert!(table.grow_with(4, |_| Ok(())).is_ok());
    let mut observed = None;
    let result = table.reclaim_with(UringFileSlot(0), |table, index, fd| {
        observed = Some((index, fd, table.get(UringFileSlot(0))));
        Ok(())
    });
    assert_eq!(result, Ok(10));
    assert_eq!(observed, Some((0, -1, Some(10))));
    assert_eq!(table.get(UringFileSlot(0)), None);
    assert_eq!(table.free.last(), Some(&0));
    assert!(table.retained[0].is_none());
}

#[test]
fn reclaim_update_failure_preserves_slot() {
    let mut table = fake_table();
    let result = table.reclaim_with(UringFileSlot(0), |_, _, _| Err(errno(EIO)));
    assert_eq!(result, Err(errno(EIO)));
    assert_eq!(table.get(UringFileSlot(0)), Some(10));
    assert!(table.retained[0].is_some());
    assert_eq!(table.free, [1]);
}

#[test]
fn unregister_failure_preserves_retry_and_noop() {
    let mut table = fake_table();
    assert!(
        table
            .grow_with(4, |files| {
                assert!(files.is_none());
                Err(errno(libc::EBUSY))
            })
            .is_err()
    );
    assert!(table.registered);
    assert_eq!(table.get(UringFileSlot(0)), Some(10));
    assert_eq!(table.capacity(), 3);
    assert!(
        table
            .grow_with(3, |_| panic!("no-op must not replace table"))
            .is_ok()
    );
    assert!(
        table
            .grow_with(u32::MAX, |_| panic!(
                "invalid capacity must not replace table"
            ))
            .is_err()
    );
}

#[test]
fn growth_preserves_ascending_new_slots() {
    let mut table = fake_table();
    assert!(table.grow_with(7, |_| Ok(())).is_ok());
    assert_eq!(table.capacity(), 7);
    assert_eq!(table.get(UringFileSlot(0)), Some(10));
    assert_eq!(table.get(UringFileSlot(2)), Some(12));
    assert_eq!(table.free, [1, 6, 5, 4, 3]);
    assert!(table.free.capacity() >= table.capacity());
}
