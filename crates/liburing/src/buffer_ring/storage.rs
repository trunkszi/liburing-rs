//! Page-aligned buffer descriptors and release publication to the Linux kernel.

use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr::NonNull,
    sync::atomic::{AtomicU16, Ordering},
};

use crate::{
    backend::{
        register::{self, RegisterTarget},
        sys::register::{IoUringBuf as BufferRingEntry, IoUringBufStatus},
    },
    error::{Result, UringError},
};

pub(super) struct BufferBytes {
    pub(super) pointer: NonNull<u8>,
    pub(super) layout: Layout,
}

impl BufferBytes {
    pub(super) fn new(entries: u16, buffer_len: usize) -> Result<Self> {
        let bytes = usize::from(entries)
            .checked_mul(buffer_len)
            .ok_or(UringError::BufferRingSetup(libc::EINVAL))?;
        let alignment = if bytes >= 4096 { 4096 } else { 8 };
        let size = bytes
            .checked_add(alignment - 1)
            .map(|size| size & !(alignment - 1))
            .ok_or(UringError::BufferRingSetup(libc::EINVAL))?;
        let layout = Layout::from_size_align(size, alignment)
            .map_err(|_| UringError::BufferRingSetup(libc::EINVAL))?;
        // SAFETY: The nonzero checked layout bounds all initialized payload bytes and any page
        // padding.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or(UringError::BufferRingSetup(libc::ENOMEM))?;
        if bytes >= 2 * 1024 * 1024 {
            // SAFETY: This page-aligned, page-rounded allocation owns the entire advised interval.
            unsafe { libc::madvise(pointer.as_ptr().cast(), layout.size(), libc::MADV_HUGEPAGE) };
        }
        Ok(Self { pointer, layout })
    }
}

impl Drop for BufferBytes {
    fn drop(&mut self) {
        // SAFETY: This guard owns unregistered storage allocated with the identical layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

pub(super) struct BufferRingStorage {
    entries: NonNull<BufferRingEntry>,
    layout: Layout,
}

impl BufferRingStorage {
    pub(super) fn new(entries: u16) -> Result<Self> {
        // SAFETY: sysconf has no pointer arguments and only queries page size.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page).map_err(|_| UringError::BufferRingSetup(libc::EINVAL))?;
        let layout =
            Layout::from_size_align(usize::from(entries) * size_of::<BufferRingEntry>(), page)
                .map_err(|_| UringError::BufferRingSetup(libc::EINVAL))?;
        // SAFETY: Layout has nonzero validated dimensions and page alignment.
        // Zero is a valid initial representation of every descriptor field.
        let pointer = unsafe { alloc_zeroed(layout) };
        let entries =
            NonNull::new(pointer.cast()).ok_or(UringError::BufferRingSetup(libc::ENOMEM))?;
        Ok(Self { entries, layout })
    }

    pub(super) fn address(&self) -> u64 {
        self.entries.as_ptr() as u64
    }

    fn shared_tail(&self) -> *mut u16 {
        // SAFETY: Native 16-byte descriptor layout places the aligned shared tail at byte 14.
        unsafe { self.entries.as_ptr().cast::<u8>().add(14).cast() }
    }

    pub(super) fn tail(&self) -> u16 {
        // SAFETY: Allocation is live and aligned; only atomic accesses touch the shared tail.
        unsafe { AtomicU16::from_ptr(self.shared_tail()) }.load(Ordering::Relaxed)
    }

    #[inline]
    pub(super) fn advance(&self, count: u16) {
        let next = self.tail().wrapping_add(count);
        // SAFETY: The initialized descriptors precede publication; the tail is aligned,
        // exclusively user-written, and never overlaps the descriptor field writes.
        unsafe { AtomicU16::from_ptr(self.shared_tail()) }.store(next, Ordering::Release);
    }

    pub(super) fn id_at(&self, position: u16, mask: u16) -> u16 {
        // SAFETY: Position is bounded by the allocated mask. The owner writes bid only
        // before publishing; the kernel never modifies the bid field.
        unsafe { (*self.entries.as_ptr().add(usize::from(position & mask))).bid }
    }

    #[inline]
    pub(super) fn publish(&self, address: *mut u8, len: u32, id: u16, offset: u16, mask: u16) {
        let index = self.tail().wrapping_add(offset) & mask;
        // SAFETY: The caller owns this unpublished descriptor and index is
        // masked to its allocated capacity. BufferRingEntry has the kernel's
        // 16-byte addr/len/bid/reserved layout; only its first 14 bytes change,
        // preserving the kernel-read tail overlapping entry zero.
        unsafe {
            let entry = self.entries.as_ptr().add(usize::from(index)).cast::<u8>();
            entry.cast::<u64>().write(address as u64);
            entry.add(8).cast::<u32>().write(len);
            entry.add(12).cast::<u16>().write(id);
        }
    }

    pub(super) fn available(&self, target: RegisterTarget, group: u16) -> Result<u64> {
        let mut status = IoUringBufStatus {
            buf_group: u32::from(group),
            ..Default::default()
        };
        // SAFETY: The group and native target remain live; the initialized output is writable.
        unsafe {
            register::register_pbuf_status(target, &mut status)?;
        }
        Ok(u64::from(self.tail().wrapping_sub(status.head as u16)))
    }
}

impl Drop for BufferRingStorage {
    fn drop(&mut self) {
        // SAFETY: The owner unregisters and drains the group before dropping
        // this allocation; the pointer was allocated with precisely this layout.
        unsafe { dealloc(self.entries.as_ptr().cast(), self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_tail_survives_wraparound() -> Result<()> {
        let storage = BufferRingStorage::new(2)?;
        assert_eq!(size_of::<BufferRingEntry>(), 16);
        assert_eq!(storage.address() as usize % storage.layout.align(), 0);
        storage.advance(u16::MAX);
        let mut bytes = [0_u8; 8];
        storage.publish(bytes.as_mut_ptr(), 8, 7, 0, 1);
        assert_eq!(storage.tail(), u16::MAX);
        storage.advance(1);
        assert_eq!(storage.tail(), 0);
        storage.publish(bytes.as_mut_ptr(), 8, 9, 0, 1);
        assert_eq!(storage.tail(), 0);
        // SAFETY: No kernel registration exists and both entries have been
        // initialized; immutable inspection cannot race publication here.
        unsafe {
            let first = storage.entries.as_ref();
            let second = &*storage.entries.as_ptr().add(1);
            assert_eq!(
                (first.addr, first.len, first.bid),
                (bytes.as_ptr() as u64, 8, 9)
            );
            assert_eq!(
                (second.addr, second.len, second.bid),
                (bytes.as_ptr() as u64, 8, 7)
            );
        }
        storage.advance(1);
        assert_eq!(storage.tail(), 1);
        Ok(())
    }
}
