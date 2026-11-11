//! Mapping ownership and the distinct VFS/registered-index handle namespaces.
use core::{marker::PhantomData, ptr::NonNull};
use std::{
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
    rc::Rc,
};

use crate::{
    Result, UringError,
    backend::sys::{self, params::*, register::*},
};

/// One mmap allocation; checked addresses do not create references to kernel-owned pages.
pub struct MmapRegion {
    allocation: NonNull<u8>,
    allocation_len: usize,
    data: NonNull<u8>,
    len: usize,
    _local: PhantomData<Rc<()>>,
}
impl MmapRegion {
    /// Maps a kernel ring region and owns its sole munmap obligation.
    /// # Errors
    /// Returns invalid extent/offset or the mmap errno.
    /// # Panics
    /// Does not panic.
    pub fn map(fd: BorrowedFd<'_>, offset: u64, len: usize) -> Result<Self> {
        let offset = i64::try_from(offset)
            .map_err(|_| UringError::InvalidTopology("mmap offset overflow"))?;
        Self::allocate(len, fd.as_raw_fd(), offset, false)
    }
    /// Allocates writable zero-filled pages surrounded by inaccessible guard pages.
    /// # Errors
    /// Returns invalid extent or mmap/mprotect errors.
    /// # Panics
    /// Does not panic.
    pub fn anonymous(len: usize) -> Result<Self> {
        Self::allocate(len, -1, 0, true)
    }
    fn allocate(len: usize, fd: i32, offset: i64, guarded: bool) -> Result<Self> {
        let page = page_size()?;
        let len = len
            .checked_add(page - 1)
            .map(|v| v & !(page - 1))
            .filter(|&v| v != 0 && v <= isize::MAX as usize)
            .ok_or(UringError::InvalidTopology("invalid mmap extent"))?;
        let extra = if guarded { 2 * page } else { 0 };
        let total = len
            .checked_add(extra)
            .filter(|&v| v <= isize::MAX as usize)
            .ok_or(UringError::InvalidTopology("mmap guard extent overflow"))?;
        let (prot, flags) = if guarded {
            (libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS)
        } else {
            (libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED)
        };
        // SAFETY: Kernel chooses the address; checked sizes fit addressable allocations and the
        // borrowed fd is live for this synchronous mmap. No Rust references cover shared bytes.
        let raw = unsafe { libc::mmap(core::ptr::null_mut(), total, prot, flags, fd, offset) };
        if raw == libc::MAP_FAILED {
            return Err(UringError::cold_syscall("mmap", sys::last_os_errno()));
        }
        let Some(allocation) = NonNull::new(raw.cast::<u8>()) else {
            // SAFETY: A successful zero-address mapping still owns this exact mmap extent.
            unsafe {
                libc::munmap(raw, total);
            }
            return Err(UringError::InvalidTopology("zero mmap address"));
        };
        // SAFETY: Guarded allocations include a leading page; both data positions lie in the
        // allocation.
        let data = unsafe {
            NonNull::new_unchecked(allocation.as_ptr().add(if guarded { page } else { 0 }))
        };
        let region = Self {
            allocation,
            allocation_len: total,
            data,
            len,
            _local: PhantomData,
        };
        if guarded {
            // SAFETY: Only the page-aligned interior is enabled; both surrounding guard pages
            // remain inaccessible.
            let protected = unsafe {
                libc::mprotect(
                    data.as_ptr().cast(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            };
            if protected < 0 {
                return Err(UringError::cold_syscall("mprotect", sys::last_os_errno()));
            }
        }
        Ok(region)
    }
    /// Returns the raw mapped address without granting dereference or ownership.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn as_ptr(&self) -> *mut u8 {
        self.data.as_ptr()
    }
    /// Returns the page-rounded accessible extent.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn len(&self) -> usize {
        self.len
    }
    /// Reports whether the accessible extent is empty (valid mappings are never empty).
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub(crate) fn pointer<T>(&self, offset: usize, count: usize) -> Result<*mut T> {
        let bytes = count
            .checked_mul(size_of::<T>())
            .and_then(|n| offset.checked_add(n))
            .filter(|&end| end <= self.len)
            .ok_or(UringError::InvalidTopology(
                "mapped field outside allocation",
            ))?;
        let _ = bytes;
        // SAFETY: The checked offset is within the retained allocation. No dereference occurs here.
        let pointer = unsafe { self.data.as_ptr().add(offset).cast::<T>() };
        if pointer.align_offset(align_of::<T>()) != 0 {
            return Err(UringError::InvalidTopology("unaligned mapped field"));
        }
        Ok(pointer)
    }
}
impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: This unique owner releases the exact allocation returned by mmap, including
        // guards.
        unsafe {
            libc::munmap(self.allocation.as_ptr().cast(), self.allocation_len);
        }
    }
}
pub(crate) fn page_size() -> Result<usize> {
    // SAFETY: sysconf has no pointer arguments and only queries the process page size.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size)
        .ok()
        .filter(|n| n.is_power_of_two())
        .ok_or(UringError::InvalidTopology("invalid system page size"))
}
/// Separate caller-provided SQE and shared-ring allocations for NO_MMAP.
pub struct UserRingMemory {
    pub(crate) sqes: MmapRegion,
    pub(crate) rings: MmapRegion,
}
impl UserRingMemory {
    /// Allocates guarded storage using upper bounds for the kernel-rounded capacities.
    /// # Errors
    /// Returns extent overflow or allocation errors. Guard pages fail kernel pinning if a
    /// future kernel's header exceeds the reserved header page instead of exposing adjacent memory.
    /// # Panics
    /// Does not panic.
    pub fn new(
        sq_entries: u32,
        cq_entries: u32,
        sq_stride: usize,
        cq_stride: usize,
    ) -> Result<Self> {
        let size = |entries: u32, stride: usize| {
            (entries as usize)
                .checked_mul(stride)
                .ok_or(UringError::InvalidTopology("queue extent overflow"))
        };
        let sq_size = size(sq_entries, sq_stride)?;
        let ring_size = size(cq_entries, cq_stride)?
            .checked_add(size(sq_entries, 4)?)
            .and_then(|n| n.checked_add(page_size().ok()?))
            .ok_or(UringError::InvalidTopology("shared ring extent overflow"))?;
        Ok(Self {
            sqes: MmapRegion::anonymous(sq_size)?,
            rings: MmapRegion::anonymous(ring_size)?,
        })
    }
}
/// Handle namespaces are metadata here; only NativeRing adopts registered-slot cleanup.
/// Constructing this enum does not unregister arbitrary task-local slots on Drop.
pub enum RingHandle {
    Vfs {
        fd: OwnedFd,
        registered_index: Option<u32>,
    },
    RegisteredOnly {
        registered_index: u32,
    },
}
impl RingHandle {
    /// Selects the enter fd/index and its namespace flag.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    pub fn enter_target(&self) -> (i32, u32) {
        match self {
            Self::Vfs {
                registered_index: Some(index),
                ..
            }
            | Self::RegisteredOnly {
                registered_index: index,
            } => (*index as i32, IORING_ENTER_REGISTERED_RING),
            Self::Vfs {
                fd,
                registered_index: None,
            } => (fd.as_raw_fd(), 0),
        }
    }
}
pub(crate) enum RingMemory {
    KernelMapped {
        sq: MmapRegion,
        cq: Option<MmapRegion>,
        sqes: MmapRegion,
    },
    UserProvided(UserRingMemory),
}
impl RingMemory {
    pub(crate) fn regions(&self) -> (&MmapRegion, &MmapRegion, &MmapRegion) {
        match self {
            Self::KernelMapped { sq, cq, sqes } => (sq, cq.as_ref().unwrap_or(sq), sqes),
            Self::UserProvided(memory) => (&memory.rings, &memory.rings, &memory.sqes),
        }
    }
}
pub(crate) struct RingStorage {
    pub handle: Option<RingHandle>,
    pub memory: Option<RingMemory>,
    pub retain_memory: bool,
}
impl Drop for RingStorage {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            let index = match handle {
                RingHandle::Vfs {
                    registered_index, ..
                } => *registered_index,
                RingHandle::RegisteredOnly { registered_index } => Some(*registered_index),
            };
            if let Some(index) = index {
                let mut update = IoUringRsrcUpdate {
                    offset: index,
                    ..Default::default()
                };
                let (fd, namespace) = handle.enter_target();
                let tag = if namespace != 0 {
                    IORING_REGISTER_USE_REGISTERED_RING
                } else {
                    0
                };
                // SAFETY: This owner adopted this task-local registered slot during setup;
                // the update record is initialized and writable for the synchronous unregister.
                let result = unsafe {
                    sys::sys_io_uring_register(
                        fd,
                        IORING_UNREGISTER_RING_FDS | tag,
                        (&raw mut update).cast(),
                        1,
                    )
                };
                if result < 0 {
                    self.retain_memory = true;
                }
            }
        }
        drop(self.handle.take());
        if self.retain_memory
            && let Some(memory) = self.memory.take()
        {
            core::mem::forget(memory);
        }
    }
}
