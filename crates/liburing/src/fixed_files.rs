//! Registered-file slots for one single-threaded io_uring instance.
//!
//! The table owns kernel registrations, not the supplied OS descriptors. A slot
//! must not be reused until all operations that refer to its previous file have
//! completed. Direct-close completion is an explicit, unsafe reclamation seam.

use std::{
    marker::PhantomData,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr::NonNull,
    rc::Rc,
};

use crate::{
    error::{Result, UringError},
    id::UringFileSlot,
};

const EINVAL: i32 = 22;
const EBADF: i32 = 9;
const EIO: i32 = 5;

/// A dynamically growing registered-file table with a free-slot stack.
///
/// Registering a descriptor retains a kernel file reference and leaves ownership
/// of the original descriptor with the caller. This type is neither `Send` nor
/// `Sync`. Call [`Self::unregister`] to observe teardown errors explicitly;
/// dropping the table attempts to unregister any remaining registration. Each
/// occupied slot retains a private close-on-exec duplicate so growth preserves
/// file identity when a caller closes or reuses its original descriptor.
pub struct FixedFileTable {
    ring: NonNull<io_uring::IoUring>,
    entries: Vec<Option<RawFd>>,
    retained: Vec<Option<OwnedFd>>,
    free: Vec<u32>,
    registered: bool,
    single_thread: PhantomData<Rc<()>>,
}

impl FixedFileTable {
    /// Registers an empty sparse table with `capacity` fixed-file slots.
    ///
    /// # Errors
    /// Returns an error for a null ring, zero or unrepresentable capacity, or a
    /// kernel registration failure (including an existing registered table).
    ///
    /// # Panics
    /// Does not panic for invalid arguments. Allocation failure follows the
    /// process allocator's policy.
    ///
    /// # Safety
    /// `ring` must be initialized and remain alive at a stable address until
    /// this table is unregistered or dropped. All access to the ring and its
    /// file registration must remain on this thread and must be serialized with
    /// this table; no other owner may register, update, or unregister its files.
    pub unsafe fn new(ring: *mut io_uring::IoUring, capacity: u32) -> Result<Self> {
        let ring = NonNull::new(ring).ok_or_else(|| errno(EINVAL))?;
        if capacity == 0 || capacity > i32::MAX as u32 {
            return Err(errno(EINVAL));
        }
        let entries = vec![None; capacity as usize];
        let free = (0..capacity).rev().collect();
        let retained = std::iter::repeat_with(|| None)
            .take(capacity as usize)
            .collect();
        // SAFETY: The caller guarantees a live, exclusively managed ring; the
        // validated capacity fits the kernel's signed fixed-file index range.
        unsafe { ring.as_ref() }
            .submitter()
            .register_files_sparse(capacity)?;
        Ok(Self {
            ring,
            entries,
            retained,
            free,
            registered: true,
            single_thread: PhantomData,
        })
    }

    /// Registers a table initialized from `files`, preserving their indices.
    ///
    /// A `-1` entry creates an empty slot; all other entries must be nonnegative
    /// OS descriptors. The caller retains ownership of every descriptor.
    ///
    /// # Errors
    /// Returns an error for a null ring, empty or oversized input, an invalid
    /// negative descriptor, descriptor duplication failure, or a kernel
    /// registration failure.
    ///
    /// # Panics
    /// Does not panic for invalid arguments. Allocation failure follows the
    /// process allocator's policy.
    ///
    /// # Safety
    /// The ring lifetime, thread confinement, and exclusive file-registration
    /// requirements are identical to [`Self::new`]. The supplied descriptors
    /// must remain valid during this call.
    pub unsafe fn register(ring: *mut io_uring::IoUring, files: &[RawFd]) -> Result<Self> {
        let ring = NonNull::new(ring).ok_or_else(|| errno(EINVAL))?;
        if files.is_empty() || files.len() > i32::MAX as usize || files.iter().any(|&fd| fd < -1) {
            return Err(errno(EINVAL));
        }
        let retained = files
            .iter()
            .map(|&fd| {
                if fd == -1 {
                    Ok(None)
                } else {
                    duplicate(fd).map(Some)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let entries = files
            .iter()
            .map(|&fd| if fd == -1 { None } else { Some(fd) })
            .collect();
        let mut free = Vec::with_capacity(files.len());
        for (index, &fd) in files.iter().enumerate().rev() {
            if fd == -1 {
                free.push(index as u32);
            }
        }
        // SAFETY: The caller guarantees a live exclusively managed ring and
        // valid descriptors; liburing copies this nonempty, bounded fd array
        // during registration and does not retain its pointer afterward.
        unsafe { ring.as_ref() }.submitter().register_files(files)?;
        Ok(Self {
            ring,
            entries,
            retained,
            free,
            registered: true,
            single_thread: PhantomData,
        })
    }

    /// Registers `fd` in the next free slot for `IOSQE_FIXED_FILE` operations.
    ///
    /// The returned slot contains a direct index, not an OS descriptor. The
    /// update and free-stack transition commit only after kernel success. A full
    /// table grows automatically; see [`Self::grow`] for growth requirements.
    ///
    /// # Errors
    /// Returns an error for a negative descriptor, an unregistered table,
    /// descriptor duplication, allocation, growth, or kernel update failure.
    /// Failure leaves
    /// the chosen slot available; successful growth can increase capacity.
    ///
    /// # Panics
    /// Does not panic.
    pub fn insert(&mut self, fd: RawFd) -> Result<UringFileSlot> {
        if !self.registered {
            return Err(errno(EBADF));
        }
        if fd < 0 {
            return Err(errno(EINVAL));
        }
        let retained = duplicate(fd)?;
        if self.free.is_empty() {
            let capacity = self.capacity() as u32;
            self.grow(
                capacity
                    .checked_add(1)
                    .ok_or(UringError::FixedFileSlotsExhausted)?,
            )?;
        }
        let index = self
            .free
            .last()
            .copied()
            .ok_or(UringError::FixedFileSlotsExhausted)?;
        self.update(index, retained.as_raw_fd())?;
        self.retained[index as usize] = Some(retained);
        self.free.pop();
        self.entries[index as usize] = Some(fd);
        Ok(UringFileSlot(index))
    }

    /// Expands registration to at least `min_capacity`, preserving slot indices.
    ///
    /// This is a synchronous control-plane call. Replacing the kernel table
    /// first unregisters the old one, which may block while the kernel retires
    /// outstanding fixed-file operations, so it must not run on a hot path.
    ///
    /// Capacity at least doubles and never exceeds `i32::MAX`. Allocation is
    /// completed before replacing the kernel table. No SQEs may be submitted by
    /// another owner during replacement; construction already requires exclusive
    /// registration ownership. A failed replacement attempts to restore the old
    /// table; that rollback is best effort. Private close-on-exec duplicates
    /// preserve each file identity even after the caller closes or reuses its
    /// original descriptor.
    ///
    /// After a failed rollback, including a failed restore of the previous
    /// table, the table is unregistered and its retained references and slot
    /// bookkeeping are cleared, so all slot lookups and modifications fail.
    /// Callers can distinguish that state from an intact table with
    /// [`Self::is_registered`].
    ///
    /// # Errors
    /// Returns an error for an unregistered table, an oversized request,
    /// allocation failure, or kernel unregistration/replacement failure.
    ///
    /// # Panics
    /// Does not panic.
    pub fn grow(&mut self, min_capacity: u32) -> Result<()> {
        let ring = self.ring;
        self.grow_with(min_capacity, |files| {
            // SAFETY: Construction guarantees exclusive registration ownership
            // on a live stable ring. The slice remains valid throughout the
            // copying syscall; None requests unregistration without a buffer.
            let submitter = unsafe { ring.as_ref() }.submitter();
            match files {
                Some(files) => submitter.register_files(files),
                None => submitter.unregister_files(),
            }
            .map_err(Into::into)
        })
    }

    fn grow_with(
        &mut self,
        min_capacity: u32,
        mut register: impl FnMut(Option<&[RawFd]>) -> Result<()>,
    ) -> Result<()> {
        if !self.registered {
            return Err(errno(EBADF));
        }
        let old_cap = self.entries.len();
        if min_capacity <= old_cap as u32 {
            return Ok(());
        }
        if min_capacity > i32::MAX as u32 {
            return Err(errno(EINVAL));
        }
        let new_cap = (old_cap as u32)
            .max(1)
            .saturating_mul(2)
            .max(min_capacity)
            .min(i32::MAX as u32) as usize;
        let added = new_cap - old_cap;
        let mut files = Vec::new();
        files
            .try_reserve_exact(new_cap)
            .map_err(|_| errno(libc::ENOMEM))?;
        self.entries
            .try_reserve_exact(added)
            .map_err(|_| errno(libc::ENOMEM))?;
        self.free
            .try_reserve_exact(new_cap - self.free.len())
            .map_err(|_| errno(libc::ENOMEM))?;
        self.retained
            .try_reserve_exact(added)
            .map_err(|_| errno(libc::ENOMEM))?;
        files.extend(
            self.retained
                .iter()
                .map(|fd| fd.as_ref().map_or(-1, AsRawFd::as_raw_fd)),
        );
        files.resize(new_cap, -1);
        register(None)?;
        self.registered = false;
        if let Err(error) = register(Some(&files)) {
            self.registered = register(Some(&files[..old_cap])).is_ok();
            if !self.registered {
                self.retained.clear();
                self.entries.clear();
                self.free.clear();
            }
            return Err(error);
        }
        self.registered = true;
        self.entries.resize(new_cap, None);
        self.retained.resize_with(new_cap, || None);
        self.free.extend((old_cap as u32..new_cap as u32).rev());
        Ok(())
    }

    /// Removes a fixed-file registration and makes its slot available again.
    ///
    /// This does not close the original OS descriptor. The caller must retire
    /// all operations using the slot before scheduling operations after reuse.
    ///
    /// The returned value is the descriptor number originally supplied for the
    /// slot, not the table's private `F_DUPFD_CLOEXEC` duplicate. It remains a
    /// valid handle only while the caller keeps that original descriptor open.
    /// After the caller closes or reuses the number, treat it as a bookkeeping
    /// identifier only and do not close it again.
    ///
    /// # Errors
    /// Returns an error for an unregistered, out-of-range, or empty slot, or a
    /// kernel update failure. Failure preserves the existing registration.
    ///
    /// # Panics
    /// Does not panic.
    pub fn remove(&mut self, slot: UringFileSlot) -> Result<RawFd> {
        let fd = self.occupied(slot)?;
        self.update(slot.0, -1)?;
        self.entries[slot.0 as usize] = None;
        self.retained[slot.0 as usize] = None;
        self.free.push(slot.0);
        Ok(fd)
    }

    /// Recycles a slot whose direct-close operation completed successfully.
    ///
    /// Clears the kernel slot with a `-1` update before releasing it. The update
    /// is a no-op when the direct close already emptied the kernel slot; it also
    /// removes the retained duplicate that [`Self::grow`] may have re-registered
    /// while the close CQE waited for reclamation. The returned value identifies
    /// the originally registered descriptor; it does not transfer descriptor
    /// ownership. It remains a valid handle only while the caller keeps that
    /// original descriptor open. After the caller closes or reuses the number,
    /// treat it as a bookkeeping identifier only: never close it again and never
    /// assume it names the slot's current file.
    ///
    /// # Errors
    /// Returns an error if the table is unregistered, the slot is invalid or
    /// already free, or the kernel slot update fails. An error leaves the
    /// registration and the free-slot stack unchanged.
    ///
    /// # Panics
    /// Does not panic.
    ///
    /// # Safety
    /// The successful final CQE for a direct close targeting exactly this slot
    /// must have been observed. All previous operations using this slot must
    /// have retired, and the slot must not have been externally repopulated.
    /// A cancellation-control CQE never satisfies this condition.
    pub unsafe fn reclaim_direct_close(&mut self, slot: UringFileSlot) -> Result<RawFd> {
        self.reclaim_with(slot, |table, index, fd| table.update(index, fd))
    }

    fn reclaim_with(
        &mut self,
        slot: UringFileSlot,
        update: impl FnOnce(&mut Self, u32, RawFd) -> Result<()>,
    ) -> Result<RawFd> {
        let fd = self.occupied(slot)?;
        update(self, slot.0, -1)?;
        self.entries[slot.0 as usize] = None;
        self.retained[slot.0 as usize] = None;
        self.free.push(slot.0);
        Ok(fd)
    }

    /// Returns the original descriptor associated with a currently occupied slot.
    ///
    /// The returned value is the descriptor number the caller supplied when the
    /// slot was inserted or registered, not the table's private
    /// `F_DUPFD_CLOEXEC` duplicate. It remains a valid handle only while the
    /// caller keeps that original descriptor open. After the caller closes or
    /// reuses the number, treat the result as a bookkeeping identifier only:
    /// never close it again and never assume it names the slot's current file.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic; out-of-range and unregistered slots return `None`.
    #[must_use]
    pub fn get(&self, slot: UringFileSlot) -> Option<RawFd> {
        if self.registered {
            self.entries.get(slot.0 as usize).copied().flatten()
        } else {
            None
        }
    }

    /// Returns whether the kernel currently holds this table's registration.
    ///
    /// This is `false` after a successful [`Self::unregister`] and after a
    /// failed rollback during [`Self::grow`]. While it is `false`, slot lookups
    /// and modifications fail: [`Self::get`] returns `None`, and
    /// [`Self::insert`], [`Self::remove`], and [`Self::grow`] return errors.
    /// Repeated [`Self::unregister`] calls are no-ops.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        self.registered
    }

    /// Returns the current number of registered slots, including empty slots.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of occupied registered slots.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn len(&self) -> usize {
        if self.registered {
            self.entries.len() - self.free.len()
        } else {
            0
        }
    }

    /// Returns whether the table has no occupied registered slots.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of available slots, or zero after unregistration.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn available(&self) -> usize {
        if self.registered { self.free.len() } else { 0 }
    }

    /// Unregisters the table without closing caller-owned OS descriptors.
    ///
    /// Repeated calls after success are harmless. After success, insertion and
    /// removal return errors; the table cannot be registered a second time.
    ///
    /// # Errors
    /// Returns the kernel unregistration error. Failure preserves table state
    /// and permits a later retry while the ring remains alive.
    ///
    /// # Panics
    /// Does not panic.
    pub fn unregister(&mut self) -> Result<()> {
        if !self.registered {
            return Ok(());
        }
        // SAFETY: Construction requires the ring to outlive the table and
        // prohibits competing registration owners. No input buffer is retained.
        unsafe { self.ring.as_ref() }
            .submitter()
            .unregister_files()?;
        self.registered = false;
        self.retained.clear();
        Ok(())
    }

    fn occupied(&self, slot: UringFileSlot) -> Result<RawFd> {
        self.get(slot).ok_or(UringError::InvalidFileSlot(slot.0))
    }

    fn update(&mut self, index: u32, fd: RawFd) -> Result<()> {
        // SAFETY: The table owns registration on its live ring, index names an
        // existing slot, and the one-element fd array is valid for the syscall.
        // The kernel copies the descriptor and does not retain this pointer.
        let result = unsafe { self.ring.as_ref() }
            .submitter()
            .register_files_update(index, &[fd])?;
        if result != 1 { Err(errno(EIO)) } else { Ok(()) }
    }
}

impl Drop for FixedFileTable {
    fn drop(&mut self) {
        if let Err(error) = self.unregister() {
            eprintln!("failed to unregister fixed files: {error}");
        }
    }
}

fn duplicate(fd: RawFd) -> Result<OwnedFd> {
    // SAFETY: fcntl validates the integer descriptor and returns a new owned fd;
    // this command has no pointer argument and does not affect caller ownership.
    let copied = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if copied < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: Successful F_DUPFD_CLOEXEC returned a uniquely owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(copied) })
}

fn errno(code: i32) -> UringError {
    UringError::from_errno(code)
}

#[cfg(test)]
mod tests {
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
            ring: NonNull::dangling(),
            entries: vec![Some(10), None, Some(12)],
            retained: vec![Some(null_file()), None, Some(null_file())],
            free: vec![1],
            registered: true,
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
    fn failed_unregister_keeps_registration_and_noop_avoids_syscalls() {
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
    fn growth_commits_capacity_and_ascending_new_slots() {
        let mut table = fake_table();
        assert!(table.grow_with(7, |_| Ok(())).is_ok());
        assert_eq!(table.capacity(), 7);
        assert_eq!(table.get(UringFileSlot(0)), Some(10));
        assert_eq!(table.get(UringFileSlot(2)), Some(12));
        assert_eq!(table.free, [1, 6, 5, 4, 3]);
        assert!(table.free.capacity() >= table.capacity());
    }
}
