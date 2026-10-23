//! Page-aligned buffer descriptors and volatile publication to the Linux kernel.

use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    os::fd::AsRawFd,
    ptr::NonNull,
};

use io_uring::{IoUring, types::BufRingEntry as BufferRingEntry};

use crate::error::{Result, UringError};

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("buffer-ring publication requires Linux x86_64");

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

    fn tail(&self) -> u16 {
        // SAFETY: The zero-initialized, page-aligned allocation contains the ABI
        // tail at its naturally aligned u16 address. Only this owner writes it;
        // volatile access observes the kernel-shared page without creating aliases.
        unsafe { BufferRingEntry::tail(self.entries.as_ptr()).read_volatile() }
    }

    pub(super) fn advance(&self, count: u16) {
        let next = self.tail().wrapping_add(count);
        // Linux x86_64 preserves aligned store order. A compiler memory barrier
        // keeps initialized descriptors before the shared-page tail publication.
        // SAFETY: Empty assembly changes no registers or stack; its default memory
        // clobber prevents compiler reordering. The aligned tail belongs to this
        // owner and no descriptor-field write overlaps its final two bytes.
        unsafe {
            core::arch::asm!("", options(nostack, preserves_flags));
            BufferRingEntry::tail(self.entries.as_ptr())
                .cast_mut()
                .write_volatile(next);
        }
    }

    pub(super) fn publish(&self, address: *mut u8, len: u32, id: u16, offset: u16, mask: u16) {
        let index = self.tail().wrapping_add(offset) & mask;
        // SAFETY: The caller owns this unpublished descriptor and index is
        // masked to its allocated capacity. BufferRingEntry has the kernel's
        // 16-byte addr/len/bid/reserved layout; only its first 14 bytes change,
        // preserving the kernel-read tail overlapping entry zero.
        unsafe {
            let entry = self.entries.as_ptr().add(usize::from(index)).cast::<u8>();
            entry.cast::<u64>().write_volatile(address as u64);
            entry.add(8).cast::<u32>().write_volatile(len);
            entry.add(12).cast::<u16>().write_volatile(id);
        }
    }

    pub(super) fn available(&self, ring: &IoUring, group: u16) -> Result<u64> {
        #[repr(C)]
        struct Status {
            group: u32,
            head: u32,
            reserved: [u32; 8],
        }
        let mut status = Status {
            group: u32::from(group),
            head: 0,
            reserved: [0; 8],
        };
        // SAFETY: This is the kernel's 40-byte io_uring_buf_status ABI, writable
        // for the synchronous syscall. The live ring owns the queried group.
        // Opcode 26 is IORING_REGISTER_PBUF_STATUS, absent from Submitter's API.
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                ring.as_raw_fd(),
                26_u32,
                &mut status,
                1_u32,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
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
    fn descriptor_publication_preserves_tail_across_wraparound() -> Result<()> {
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
                (first.addr(), first.len(), first.bid()),
                (bytes.as_ptr() as u64, 8, 9)
            );
            assert_eq!(
                (second.addr(), second.len(), second.bid()),
                (bytes.as_ptr() as u64, 8, 7)
            );
        }
        storage.advance(1);
        assert_eq!(storage.tail(), 1);
        Ok(())
    }
}
