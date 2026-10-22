//! Registered-file slots for one single-threaded io_uring instance.
//!
//! The table owns kernel registrations, not the supplied OS descriptors. A slot
//! must not be reused until all operations that refer to its previous file have
//! completed. Direct-close completion is an explicit, unsafe reclamation seam.

use std::{marker::PhantomData, os::fd::RawFd, ptr::NonNull, rc::Rc};

use crate::{
    error::{Result, UringError},
    id::UringFileSlot,
};

const EINVAL: i32 = 22;
const EBADF: i32 = 9;
const EIO: i32 = 5;

/// A bounded registered-file table with an allocation-free free-slot stack.
///
/// Registering a descriptor retains a kernel file reference and leaves ownership
/// of the original descriptor with the caller. This type is neither `Send` nor
/// `Sync`. Call [`Self::unregister`] to observe teardown errors explicitly;
/// dropping the table attempts to unregister any remaining registration.
pub struct FixedFileTable {
    ring: NonNull<liburing_sys::io_uring>,
    entries: Vec<Option<RawFd>>,
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
    pub unsafe fn new(ring: *mut liburing_sys::io_uring, capacity: u32) -> Result<Self> {
        let ring = NonNull::new(ring).ok_or_else(|| errno(EINVAL))?;
        if capacity == 0 || capacity > i32::MAX as u32 {
            return Err(errno(EINVAL));
        }
        let entries = vec![None; capacity as usize];
        let free = (0..capacity).rev().collect();
        // SAFETY: The caller guarantees a live, exclusively managed ring; the
        // validated capacity fits the kernel's signed fixed-file index range.
        let result =
            unsafe { liburing_sys::uring_shim_register_files_sparse(ring.as_ptr(), capacity) };
        check_zero(result)?;
        Ok(Self {
            ring,
            entries,
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
    /// negative descriptor, or a kernel registration failure.
    ///
    /// # Panics
    /// Does not panic for invalid arguments. Allocation failure follows the
    /// process allocator's policy.
    ///
    /// # Safety
    /// The ring lifetime, thread confinement, and exclusive file-registration
    /// requirements are identical to [`Self::new`]. The supplied descriptors
    /// must remain valid during this call.
    pub unsafe fn register(ring: *mut liburing_sys::io_uring, files: &[RawFd]) -> Result<Self> {
        let ring = NonNull::new(ring).ok_or_else(|| errno(EINVAL))?;
        if files.is_empty() || files.len() > i32::MAX as usize || files.iter().any(|&fd| fd < -1) {
            return Err(errno(EINVAL));
        }
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
        let result = unsafe {
            liburing_sys::uring_shim_register_files(
                ring.as_ptr(),
                files.as_ptr(),
                files.len() as u32,
            )
        };
        check_zero(result)?;
        Ok(Self {
            ring,
            entries,
            free,
            registered: true,
            single_thread: PhantomData,
        })
    }

    /// Registers `fd` in the next free slot for `IOSQE_FIXED_FILE` operations.
    ///
    /// The returned slot contains a direct index, not an OS descriptor. The
    /// update and free-stack transition commit only after kernel success.
    ///
    /// # Errors
    /// Returns an error for a negative descriptor, an unregistered or full
    /// table, or a kernel update failure. Failure leaves the slot available.
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
        let index = self
            .free
            .last()
            .copied()
            .ok_or(UringError::FixedFileSlotsExhausted)?;
        self.update(index, fd)?;
        self.free.pop();
        self.entries[index as usize] = Some(fd);
        Ok(UringFileSlot(index))
    }

    /// Removes a fixed-file registration and makes its slot available again.
    ///
    /// This does not close the original OS descriptor. The caller must retire
    /// all operations using the slot before scheduling operations after reuse.
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
        self.free.push(slot.0);
        Ok(fd)
    }

    /// Recycles a slot whose direct-close operation completed successfully.
    ///
    /// No registration syscall is issued because `CLOSE_DIRECT` already removed
    /// the kernel reference. The returned value identifies the originally
    /// registered descriptor; it does not transfer descriptor ownership.
    ///
    /// # Errors
    /// Returns an error if the table is unregistered or the slot is invalid or
    /// already free. An error leaves the free-slot stack unchanged.
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
        let fd = self.occupied(slot)?;
        self.entries[slot.0 as usize] = None;
        self.free.push(slot.0);
        Ok(fd)
    }

    /// Returns the original descriptor associated with a currently occupied slot.
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

    /// Returns the fixed capacity selected during registration.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of occupied registered slots.
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
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of available slots, or zero after unregistration.
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
        let result = unsafe { liburing_sys::uring_shim_unregister_files(self.ring.as_ptr()) };
        check_zero(result)?;
        self.registered = false;
        Ok(())
    }

    fn occupied(&self, slot: UringFileSlot) -> Result<RawFd> {
        self.get(slot).ok_or(UringError::InvalidFileSlot(slot.0))
    }

    fn update(&mut self, index: u32, fd: RawFd) -> Result<()> {
        // SAFETY: The table owns registration on its live ring, index names an
        // existing slot, and the one-element fd array is valid for the syscall.
        // The kernel copies the descriptor and does not retain this pointer.
        let result = unsafe {
            liburing_sys::uring_shim_register_files_update(self.ring.as_ptr(), index, &fd, 1)
        };
        if result < 0 {
            Err(errno(-result))
        } else if result != 1 {
            Err(errno(EIO))
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

fn check_zero(result: i32) -> Result<()> {
    if result < 0 {
        Err(errno(-result))
    } else if result != 0 {
        Err(errno(EIO))
    } else {
        Ok(())
    }
}

fn errno(code: i32) -> UringError {
    UringError::from_errno(code)
}
