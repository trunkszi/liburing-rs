//! Registered-file slots for one single-threaded io_uring instance.
//!
//! The table owns kernel registrations, not the supplied OS descriptors. A slot
//! must not be reused until all operations that refer to its previous file have
//! completed. Direct-close completion is an explicit, unsafe reclamation seam.

use std::{
    marker::PhantomData,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    rc::Rc,
};

use uarch::prelude::*;

use crate::{
    backend::{
        register::{self, RegisterTarget},
        sys::register::{IORING_RSRC_REGISTER_SPARSE, IoUringFileIndexRange, IoUringRsrcRegister},
    },
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
    ring: RegisterTarget,
    entries: Vec<Option<RawFd>>,
    retained: Vec<Option<OwnedFd>>,
    free: Vec<u32>,
    registered: bool,
    alloc_range: Option<(u32, u32)>,
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
    pub unsafe fn new(ring: *mut crate::backend::IoUring, capacity: u32) -> Result<Self> {
        let ring = std::ptr::NonNull::new(ring).ok_or_else(|| errno(EINVAL))?;
        // SAFETY: The caller guarantees the ring lifetime and exclusive registration.
        let target = RegisterTarget::VfsFd(unsafe { ring.as_ref() }.as_raw_fd());
        // SAFETY: The caller guarantees the target outlives the table.
        unsafe { Self::new_target(target, capacity) }
    }

    /// Registers a sparse table on a native VFS or task-local registered ring target.
    /// # Errors
    /// Rejects invalid capacity and propagates registration errors.
    /// # Panics
    /// Allocation follows the allocator policy.
    /// # Safety
    /// The target must remain live on this thread until table drop, with exclusive
    /// ownership of its file registration. It must not be closed or rebound.
    pub unsafe fn new_target(target: RegisterTarget, capacity: u32) -> Result<Self> {
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
        unsafe {
            register::register_files2(
                target,
                &IoUringRsrcRegister {
                    nr: capacity,
                    flags: IORING_RSRC_REGISTER_SPARSE,
                    ..Default::default()
                },
            )?
        };
        Ok(Self {
            ring: target,
            entries,
            retained,
            free,
            registered: true,
            alloc_range: None,
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
    pub unsafe fn register(ring: *mut crate::backend::IoUring, files: &[RawFd]) -> Result<Self> {
        let ring = std::ptr::NonNull::new(ring).ok_or_else(|| errno(EINVAL))?;
        // SAFETY: The caller guarantees the ring lifetime and exclusive registration.
        let target = RegisterTarget::VfsFd(unsafe { ring.as_ref() }.as_raw_fd());
        // SAFETY: The caller guarantees the live target and descriptor ownership contract.
        unsafe { Self::register_target(target, files) }
    }

    /// Registers caller descriptors on a native VFS or task-local ring target.
    /// # Errors
    /// Rejects invalid descriptors/counts and propagates duplication or registration errors.
    /// # Panics
    /// Allocation follows the allocator policy.
    /// # Safety
    /// The target must remain live and unchanged on this thread until table drop.
    /// Own its registration exclusively; retain descriptors through this copying syscall.
    pub unsafe fn register_target(target: RegisterTarget, files: &[RawFd]) -> Result<Self> {
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
        unsafe { register::register_files(target, files)? };
        Ok(Self {
            ring: target,
            entries,
            retained,
            free,
            registered: true,
            alloc_range: None,
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
    #[inline]
    pub fn insert(&mut self, fd: RawFd) -> Result<UringFileSlot> {
        if !self.registered {
            return Err(unregistered_err());
        }
        if fd < 0 {
            return Err(invalid_fd_err());
        }
        let retained = duplicate(fd)?;
        if self.free.is_empty() {
            if self.alloc_range.is_some() {
                return Err(UringError::FixedFileSlotsExhausted);
            }
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
            unsafe {
                match files {
                    Some(files) => register::register_files(ring, files),
                    None => register::unregister_files(ring),
                }
                .map(|_| ())
            }
        })
    }

    fn grow_with(
        &mut self,
        min_capacity: u32,
        mut register: impl FnMut(Option<&[RawFd]>) -> Result<()>,
    ) -> Result<()> {
        if !self.registered {
            return Err(unregistered_err());
        }
        let old_cap = self.entries.len();
        if min_capacity <= old_cap as u32 {
            return Ok(());
        }
        if self.alloc_range.is_some() || min_capacity > i32::MAX as u32 {
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
    #[inline]
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
    #[inline]
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
            self.entries.len()
                - self.free.len()
                - self.alloc_range.map_or(0, |(_, len)| len as usize)
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
        unsafe { register::unregister_files(self.ring)? };
        self.registered = false;
        self.retained.clear();
        Ok(())
    }

    /// Reserves empty slots exclusively for kernel-managed direct-file allocation.
    ///
    /// Reserved slots are excluded from insert/available/get bookkeeping. Observe direct
    /// allocation CQEs and close those slots explicitly, or unregister the table.
    /// Growth is disabled while a range is reserved because replacement would lose
    /// kernel-created file identities. The reservation cannot be changed until unregister.
    /// # Errors
    /// Rejects empty, overflowing, occupied or conflicting ranges and inactive tables.
    /// Propagates kernel registration errors without changing bookkeeping.
    /// # Panics
    /// Does not panic.
    pub fn set_alloc_range(&mut self, off: u32, len: u32) -> Result<()> {
        if !self.registered {
            return Err(unregistered_err());
        }
        if self.alloc_range == Some((off, len)) {
            return Ok(());
        }
        let end = off.checked_add(len).ok_or_else(|| errno(EINVAL))?;
        if len == 0
            || end as usize > self.capacity()
            || self.alloc_range.is_some()
            || self.entries[off as usize..end as usize]
                .iter()
                .any(Option::is_some)
        {
            return Err(errno(EINVAL));
        }
        let range = IoUringFileIndexRange {
            off,
            len,
            ..Default::default()
        };
        // SAFETY: The table exclusively owns the live target; range is initialized and bounded.
        unsafe {
            register::register_file_alloc_range(self.ring, &range)?;
        }
        self.free.retain(|&slot| slot < off || slot >= end);
        self.alloc_range = Some((off, len));
        Ok(())
    }

    #[inline(always)]
    fn occupied(&self, slot: UringFileSlot) -> Result<RawFd> {
        self.get(slot).ok_or_else(|| invalid_slot_err(slot.0))
    }

    fn update(&mut self, index: u32, fd: RawFd) -> Result<()> {
        // SAFETY: The table owns registration on its live ring, index names an
        // existing slot, and the one-element fd array is valid for the syscall.
        // The kernel copies the descriptor and does not retain this pointer.
        let result = unsafe { register::register_files_update(self.ring, index, &[fd])? };
        if result != 1 {
            Err(update_err())
        } else {
            Ok(())
        }
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

#[cold_sink]
fn errno(code: i32) -> UringError {
    UringError::from_errno(code)
}

#[cold_sink]
fn unregistered_err() -> UringError {
    errno(EBADF)
}

#[cold_sink]
fn invalid_fd_err() -> UringError {
    errno(EINVAL)
}

#[cold_sink]
fn invalid_slot_err(slot: u32) -> UringError {
    UringError::InvalidFileSlot(slot)
}

#[cold_sink]
fn update_err() -> UringError {
    errno(EIO)
}

#[cfg(test)]
mod tests;
