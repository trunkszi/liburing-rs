//! Stable statx UAPI fields shared by libc implementations.
use uarch::prelude::*;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}
assert_layout!(StatxTimestamp, size = 16, align = 8, fields = {
    tv_sec: 0, tv_nsec: 8, __reserved: 12,
});

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    // Kernel extensions after DIOALIGN remain opaque without changing the syscall's 256B extent.
    pub __reserved: [u64; 12],
}
assert_layout!(Statx, size = 256, align = 8, fields = {
    stx_mask: 0, stx_blksize: 4, stx_attributes: 8, stx_nlink: 16, stx_uid: 20,
    stx_gid: 24, stx_mode: 28, __spare0: 30, stx_ino: 32, stx_size: 40,
    stx_blocks: 48, stx_attributes_mask: 56, stx_atime: 64, stx_btime: 80,
    stx_ctime: 96, stx_mtime: 112, stx_rdev_major: 128, stx_rdev_minor: 132,
    stx_dev_major: 136, stx_dev_minor: 140, stx_mnt_id: 144, stx_dio_mem_align: 152,
    stx_dio_offset_align: 156, __reserved: 160,
});

pub const STATX_BASIC_STATS: u32 = 0x0000_07ff;
pub const STATX_DIOALIGN: u32 = 0x0000_2000;
