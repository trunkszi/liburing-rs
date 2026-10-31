//! Power-of-two aligned byte allocations for registered direct I/O buffers.
//!
//! `Box<[u8]>` only guarantees the alignment of `u8`. `O_DIRECT` rejects buffers
//! whose addresses are not multiples of the file's `statx` memory alignment.

use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use crate::error::{Result, UringError};

/// Default registration alignment for [`super::FixedBufferPool::new`].
pub(crate) const DEFAULT_ALIGNMENT: usize = 4096;

const EMPTY_LAYOUT: Layout = {
    let Ok(layout) = Layout::from_size_align(0, 1) else {
        panic!("zero-size layout of alignment 1 is valid");
    };
    layout
};

/// A uniquely owned, zeroed allocation whose address respects `alignment`.
pub(super) struct AlignedBytes {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl AlignedBytes {
    /// Allocate `len` zeroed bytes aligned to a power-of-two `alignment`.
    ///
    /// # Errors
    /// Returns an invalid-argument error when `len` is zero, `alignment` is not
    /// a power of two, or the size cannot be represented as a layout. Returns an
    /// out-of-memory error when the allocator fails.
    ///
    /// # Panics
    /// Does not panic.
    pub(super) fn allocate(len: usize, alignment: usize) -> Result<Self> {
        if len == 0 || !alignment.is_power_of_two() {
            return Err(UringError::syscalls("aligned_alloc", libc::EINVAL));
        }
        let layout = Layout::from_size_align(len, alignment)
            .map_err(|_| UringError::syscalls("aligned_alloc", libc::EINVAL))?;
        // SAFETY: `layout` has a non-zero size and a power-of-two alignment.
        // A null return is rejected below and is never dereferenced.
        let ptr = unsafe { alloc_zeroed(layout) };
        let Some(ptr) = NonNull::new(ptr) else {
            return Err(UringError::syscalls("aligned_alloc", libc::ENOMEM));
        };
        Ok(Self { ptr, layout })
    }

    pub(super) const fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub(super) const fn len(&self) -> usize {
        self.layout.size()
    }
}

impl Default for AlignedBytes {
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            layout: EMPTY_LAYOUT,
        }
    }
}

impl Deref for AlignedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        if self.layout.size() == 0 {
            return &[];
        }
        // SAFETY: `ptr` addresses `layout.size()` bytes owned by this value.
        // `alloc_zeroed` initialized them. The caller holds the only borrow.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size()) }
    }
}

impl DerefMut for AlignedBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        if self.layout.size() == 0 {
            return &mut [];
        }
        // SAFETY: This value uniquely owns the allocation, and the mutable
        // borrow is the only access for the duration of the returned slice.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) }
    }
}

impl Drop for AlignedBytes {
    fn drop(&mut self) {
        if self.layout.size() == 0 {
            return;
        }
        // SAFETY: `ptr` came from `alloc_zeroed` with this exact layout and has
        // not been deallocated. `Drop` runs at most once. The zero-size
        // sentinel used by `mem::take` returns above.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
    }
}
