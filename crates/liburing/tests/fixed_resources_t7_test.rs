//! Native registration and kernel-selected resource ownership regressions.
//! Group fixtures retain allocations on early failure to protect any pending kernel DMA.
use std::{mem::ManuallyDrop, os::fd::AsRawFd};

use liburing::{
    backend::{IoUring, opcode, types},
    fixed_files::FixedFileTable,
};

#[test]
fn direct_allocation_preserves_reserved_range() -> Result<(), Box<dyn std::error::Error>> {
    let mut ring = IoUring::new(8)?;
    // SAFETY: Ring outlives the exclusive table and all direct operations below.
    let mut files = unsafe { FixedFileTable::new(&mut ring, 4)? };
    assert!(files.set_alloc_range(u32::MAX, 2).is_err());
    assert!(files.set_alloc_range(3, 2).is_err());
    assert_eq!(files.available(), 4);
    files.set_alloc_range(1, 2)?;
    files.set_alloc_range(1, 2)?;
    assert!(files.set_alloc_range(0, 1).is_err());
    assert_eq!((files.available(), files.len()), (2, 0));
    let source = std::fs::File::open("/dev/null")?;
    let first = files.insert(source.as_raw_fd())?;
    let second = files.insert(source.as_raw_fd())?;
    assert_eq!((first.0, second.0), (0, 3));
    assert!(files.insert(source.as_raw_fd()).is_err());
    assert!(files.grow(8).is_err());
    for expected in [1, 2, -libc::ENFILE] {
        let entry = opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), c"/dev/null".as_ptr())
            .file_index(Some(types::DestinationSlot::auto_target()))
            .build();
        // SAFETY: Static path and live table remain valid through the completion.
        unsafe {
            ring.submission().push(&entry)?;
        }
        ring.submit_and_wait(1)?;
        assert_eq!(
            ring.completion().next().expect("open CQE").result(),
            expected
        );
    }
    assert_eq!((files.available(), files.len()), (0, 2));
    files.unregister()?;
    assert!(files.set_alloc_range(0, 1).is_err());
    Ok(())
}

fn receive(
    ring: &mut IoUring,
    fd: i32,
    group: u16,
    len: u32,
    bundle: bool,
) -> Result<(u32, i32), Box<dyn std::error::Error>> {
    let mut entry = opcode::Recv::new(types::Fd(fd), std::ptr::null_mut(), len)
        .buf_group(group)
        .build()
        .flags(liburing::backend::squeue::Flags::BUFFER_SELECT);
    if bundle {
        let raw: *mut liburing::backend::RawSqe =
            (&mut entry as *mut liburing::backend::squeue::Entry).cast();
        // SAFETY: Entry has the identical 64-byte SQE layout; only the bundle flag changes.
        unsafe {
            (*raw).ioprio |= 1 << 4;
        }
    }
    // SAFETY: Caller retains socket and group storage through this one-shot receive's CQE.
    unsafe {
        ring.submission().push(&entry)?;
    }
    let timeout = types::Timespec::new().sec(2);
    ring.submitter()
        .submit_with_args(1, &types::SubmitArgs::new().timespec(&timeout))?;
    let cqe = ring.completion().next().expect("receive CQE");
    assert!(cqe.result() >= 0, "receive result {}", cqe.result());
    Ok((cqe.flags(), cqe.result()))
}

#[test]
fn incremental_views_delay_buffer_recycling() -> Result<(), Box<dyn std::error::Error>> {
    use liburing::{buffer_ring::BufferRing, id::BufferGroupId};
    let mut ring = IoUring::new(8)?;
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
    sender.connect(receiver.local_addr()?)?;
    // SAFETY: Exclusive group and stable ring outlive both drained one-shot receives and leases.
    let mut buffers = ManuallyDrop::new(unsafe {
        BufferRing::new_incremental(&mut ring, 1, 8, BufferGroupId(71))?
    });
    sender.send(b"abcd")?;
    let (flags, result) = receive(&mut ring, receiver.as_raw_fd(), 71, 4, false)?;
    assert_ne!(flags & (1 << 4), 0);
    // SAFETY: Fresh CQE grants exclusive access to the first initialized four-byte segment.
    let first = unsafe { buffers.lease_from_cqe(flags, result)? };
    assert_eq!(&*first, b"abcd");
    sender.send(b"efgh")?;
    let (flags, result) = receive(&mut ring, receiver.as_raw_fd(), 71, 4, false)?;
    assert_eq!(flags & (1 << 4), 0);
    // SAFETY: Fresh final CQE grants the disjoint trailing four-byte segment.
    let mut last = unsafe { buffers.lease_from_cqe(flags, result)? };
    assert_eq!(&*last, b"efgh");
    last.as_mut_slice()[0] = b'E';
    assert_eq!(&*first, b"abcd");
    drop(last);
    assert_eq!(buffers.returned_count(), 0);
    drop(first);
    assert_eq!(buffers.returned_count(), 1);
    sender.send(b"ijklmnop")?;
    let (flags, result) = receive(&mut ring, receiver.as_raw_fd(), 71, 8, false)?;
    // SAFETY: Fresh final CQE describes the recycled buffer's complete initialized payload.
    let reused = unsafe { buffers.lease_from_cqe(flags, result)? };
    assert_eq!(&*reused, b"ijklmnop");
    drop(reused);
    assert_eq!(buffers.returned_count(), 2);
    // SAFETY: Both receives and the recycled receive delivered final CQEs; no leases remain.
    unsafe {
        buffers.unregister()?;
        ManuallyDrop::drop(&mut buffers);
    }
    Ok(())
}

#[test]
fn bundle_leases_follow_publication_order() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    use liburing::{buffer_ring::BufferRing, id::BufferGroupId};
    let mut ring = IoUring::new(8)?;
    let (receiver, mut sender) = std::os::unix::net::UnixStream::pair()?;
    // SAFETY: Stable ring and exclusive group outlive the drained receive operations.
    let mut buffers =
        ManuallyDrop::new(unsafe { BufferRing::new(&mut ring, 4, 8, BufferGroupId(72))? });
    sender.write_all(b"abcdefghijklmnopqrstuvwx")?;
    let (flags, result) = receive(&mut ring, receiver.as_raw_fd(), 72, 0, true)?;
    assert_eq!(result, 24);
    let mut too_short = [None, None];
    // SAFETY: Real bundle CQE is validated only; insufficient output must transfer nothing.
    assert!(unsafe { buffers.lease_bundle_from_cqe(flags, result, &mut too_short) }.is_err());
    assert!(too_short.iter().all(Option::is_none));
    drop(too_short);
    let mut leases = [None, None, None, None];
    // SAFETY: This fresh bundle CQE consumes three descriptors in published order.
    let count = unsafe { buffers.lease_bundle_from_cqe(flags, result, &mut leases)? };
    assert_eq!(count, 3);
    assert_eq!(leases[0].as_ref().expect("first").as_slice(), b"abcdefgh");
    assert_eq!(leases[1].as_ref().expect("second").as_slice(), b"ijklmnop");
    assert_eq!(leases[2].as_ref().expect("last").as_slice(), b"qrstuvwx");
    // Return bid 1, then 0, then 2: next descriptors are [3, 1, 0, 2].
    drop(leases[1].take());
    drop(leases[0].take());
    drop(leases[2].take());
    assert_eq!(buffers.returned_count(), 3);
    sender.write_all(b"ABCDEFGHIJKLMNOPQRSTUVWX")?;
    let (flags, result) = receive(&mut ring, receiver.as_raw_fd(), 72, 0, true)?;
    // SAFETY: Fresh CQE grants the next three descriptors, whose bids are deliberately
    // nonconsecutive.
    let count = unsafe { buffers.lease_bundle_from_cqe(flags, result, &mut leases)? };
    assert_eq!(count, 3);
    assert_eq!(leases[0].as_ref().expect("first").buffer_id().0, 3);
    assert_eq!(leases[1].as_ref().expect("second").buffer_id().0, 1);
    assert_eq!(leases[2].as_ref().expect("last").buffer_id().0, 0);
    assert_eq!(leases[2].as_ref().expect("last").as_slice(), b"QRSTUVWX");
    drop(leases);
    // SAFETY: All receives are complete and every segment lease has been returned.
    unsafe {
        buffers.unregister()?;
        ManuallyDrop::drop(&mut buffers);
    }
    Ok(())
}

#[test]
fn native_targets_own_registered_resources() -> Result<(), Box<dyn std::error::Error>> {
    use liburing::{
        backend::{register::*, sys::register::IoUringRsrcUpdate},
        buffer_ring::BufferRing,
        fixed_buffers::FixedBufferPool,
        id::BufferGroupId,
    };
    let mut ring = IoUring::new(8)?;
    let target = RegisterTarget::VfsFd(ring.as_raw_fd());
    let mut updates = [IoUringRsrcUpdate {
        offset: u32::MAX,
        data: ring.as_raw_fd() as u64,
        ..Default::default()
    }];
    // SAFETY: This live ring and initialized output record remain owned on this thread.
    assert_eq!(unsafe { register_ring_fds(target, &mut updates)? }, 1);
    struct IndexGuard {
        target: RegisterTarget,
        index: Option<u32>,
    }
    impl Drop for IndexGuard {
        fn drop(&mut self) {
            if let Some(offset) = self.index {
                let record = IoUringRsrcUpdate {
                    offset,
                    ..Default::default()
                };
                // SAFETY: Guard outlives resources and drops before the live ring on this thread.
                let result = unsafe { unregister_ring_fds(self.target, &[record]) };
                assert!(result.is_ok(), "registered-index cleanup: {result:?}");
            }
        }
    }
    let mut guard = IndexGuard {
        target,
        index: Some(updates[0].offset),
    };
    let registered = RegisterTarget::RegisteredIndex(updates[0].offset);
    // SAFETY: The registered index remains live and exclusively owns both resource tables.
    let mut buffers = unsafe { FixedBufferPool::with_target(registered, 2, 64, 64)? };
    let handle = buffers.checkout()?;
    assert_eq!(handle.as_slice(), &[0; 64]);
    drop(handle);
    buffers.unregister()?;
    // SAFETY: Native target remains live and no other owner has a fixed-file registration.
    let mut files = unsafe { FixedFileTable::new_target(registered, 2)? };
    let source = std::fs::File::open("/dev/null")?;
    let slot = files.insert(source.as_raw_fd())?;
    assert_eq!(files.remove(slot)?, source.as_raw_fd());
    files.unregister()?;
    // SAFETY: Exclusive provided group and target remain live through the one-shot receive.
    let mut group = ManuallyDrop::new(unsafe {
        BufferRing::with_target(registered, 2, 8, BufferGroupId(73), false)?
    });
    let recv = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let send = std::net::UdpSocket::bind("127.0.0.1:0")?;
    send.send_to(b"native", recv.local_addr()?)?;
    let (flags, result) = receive(&mut ring, recv.as_raw_fd(), 73, 8, false)?;
    // SAFETY: Fresh CQE releases the selected initialized buffer with no further DMA.
    let lease = unsafe { group.lease_from_cqe(flags, result)? };
    assert_eq!(&*lease, b"native");
    drop(lease);
    // SAFETY: All operations and leases have completed; native target is still live.
    unsafe {
        group.unregister()?;
        ManuallyDrop::drop(&mut group);
    }
    let updates = [IoUringRsrcUpdate {
        offset: updates[0].offset,
        ..Default::default()
    }];
    // SAFETY: All registrations were explicitly unregistered before removing this ring index.
    assert_eq!(unsafe { unregister_ring_fds(target, &updates)? }, 1);
    guard.index = None;
    Ok(())
}

#[test]
fn incremental_early_release_preserves_cursor() -> Result<(), Box<dyn std::error::Error>> {
    use liburing::{buffer_ring::BufferRing, id::BufferGroupId};
    let mut ring = IoUring::new(8)?;
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
    sender.connect(receiver.local_addr()?)?;
    // SAFETY: Ring/group and sockets outlive all drained one-shot receives below.
    let mut buffers = ManuallyDrop::new(unsafe {
        BufferRing::new_incremental(&mut ring, 2, 8, BufferGroupId(74))?
    });
    for cycle in 0..8 {
        for (index, bytes) in [b"ab", b"cd", b"ef", b"gh"].into_iter().enumerate() {
            sender.send(bytes)?;
            let (flags, result) = receive(&mut ring, receiver.as_raw_fd(), 74, 2, false)?;
            assert_eq!(flags & (1 << 4) != 0, index != 3);
            // SAFETY: Each fresh CQE hands off only its initialized two-byte segment.
            let mut lease = unsafe { buffers.lease_from_cqe(flags, result)? };
            assert_eq!(lease.as_slice(), bytes);
            lease.as_mut_slice()[0] = b'X';
            drop(lease);
            assert_eq!(buffers.returned_count(), cycle + u64::from(index == 3));
        }
    }
    // SAFETY: Final CQEs consumed every incremental suffix, and all leases have ended.
    unsafe {
        buffers.unregister()?;
        ManuallyDrop::drop(&mut buffers);
    }
    Ok(())
}

#[test]
fn bitmap_chunks_keep_leases_independent() -> Result<(), Box<dyn std::error::Error>> {
    use liburing::{buffer_ring::BufferRing, id::BufferGroupId};
    let mut ring = IoUring::new(8)?;
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
    sender.connect(receiver.local_addr()?)?;
    // SAFETY: This exclusive group retains its allocation on failure and outlives every receive.
    let mut buffers =
        ManuallyDrop::new(unsafe { BufferRing::new(&mut ring, 128, 8, BufferGroupId(75))? });
    let mut leases = Vec::with_capacity(128);
    for id in 0..128 {
        sender.send(&[id])?;
        let (flags, result) = receive(&mut ring, receiver.as_raw_fd(), 75, 8, false)?;
        // SAFETY: Each fresh CQE grants one distinct initialized buffer with no outstanding DMA.
        let lease = unsafe { buffers.lease_from_cqe(flags, result)? };
        assert_eq!(lease.buffer_id().0, u16::from(id));
        assert_eq!(&*lease, &[id]);
        leases.push(Some(lease));
    }
    assert_eq!(buffers.returned_count(), 0);
    for id in [64, 0, 127, 63] {
        drop(leases[id].take());
    }
    assert_eq!(buffers.returned_count(), 4);
    for id in [64, 0, 127, 63] {
        sender.send(b"reused")?;
        let (flags, result) = receive(&mut ring, receiver.as_raw_fd(), 75, 8, false)?;
        // SAFETY: The fresh CQE consumes exactly the next returned buffer in publication order.
        let lease = unsafe { buffers.lease_from_cqe(flags, result)? };
        assert_eq!(lease.buffer_id().0, id);
        assert_eq!(&*lease, b"reused");
        drop(lease);
    }
    drop(leases);
    assert_eq!(buffers.returned_count(), 132);
    // SAFETY: Every one-shot receive delivered its CQE and all leases have been returned.
    unsafe {
        buffers.unregister()?;
        ManuallyDrop::drop(&mut buffers);
    }
    Ok(())
}
