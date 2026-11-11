//! Raw zcrx ABI records. Integer addresses carry no ownership.
use uarch::prelude::*;

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringZcrxRqe {
    pub off: u64,
    pub len: u32,
    pub __pad: u32,
}
assert_layout!(IoUringZcrxRqe, size = 16, align = 8, fields = {
    off: 0, len: 8, __pad: 12,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringZcrxCqe {
    pub off: u64,
    pub __pad: u64,
}
assert_layout!(IoUringZcrxCqe, size = 16, align = 8, fields = {
    off: 0, __pad: 8,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringZcrxOffsets {
    pub head: u32,
    pub tail: u32,
    pub rqes: u32,
    pub __resv2: u32,
    pub __resv: [u64; 2],
}
assert_layout!(IoUringZcrxOffsets, size = 32, align = 8, fields = {
    head: 0, tail: 4, rqes: 8, __resv2: 12, __resv: 16,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringZcrxAreaReg {
    pub addr: u64,
    pub len: u64,
    pub rq_area_token: u64,
    pub flags: u32,
    pub dmabuf_fd: u32,
    pub __resv2: [u64; 2],
}
assert_layout!(IoUringZcrxAreaReg, size = 48, align = 8, fields = {
    addr: 0, len: 8, rq_area_token: 16, flags: 24, dmabuf_fd: 28, __resv2: 32,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringZcrxIfqReg {
    pub if_idx: u32,
    pub if_rxq: u32,
    pub rq_entries: u32,
    pub flags: u32,
    pub area_ptr: u64,
    pub region_ptr: u64,
    pub offsets: IoUringZcrxOffsets,
    pub zcrx_id: u32,
    pub rx_buf_len: u32,
    pub __resv: [u64; 3],
}
assert_layout!(IoUringZcrxIfqReg, size = 96, align = 8, fields = {
    if_idx: 0, if_rxq: 4, rq_entries: 8, flags: 12, area_ptr: 16, region_ptr: 24, offsets: 32, zcrx_id: 64, rx_buf_len: 68, __resv: 72,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ZcrxCtrlFlushRq {
    pub __resv: [u64; 6],
}
assert_layout!(ZcrxCtrlFlushRq, size = 48, align = 8, fields = {
    __resv: 0,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ZcrxCtrlExport {
    pub zcrx_fd: u32,
    pub __resv1: [u32; 11],
}
assert_layout!(ZcrxCtrlExport, size = 48, align = 4, fields = {
    zcrx_fd: 0, __resv1: 4,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ZcrxCtrl {
    pub zcrx_id: u32,
    pub op: u32,
    pub __resv: [u64; 2],
    pub payload: [u64; 6],
}
assert_layout!(ZcrxCtrl, size = 72, align = 8, fields = {
    zcrx_id: 0, op: 4, __resv: 8, payload: 24,
});

pub const IORING_ZCRX_AREA_SHIFT: u32 = 48;
pub const IORING_ZCRX_AREA_MASK: u64 = 0xffff_0000_0000_0000;
pub const IORING_ZCRX_AREA_DMABUF: u32 = 1;
pub const ZCRX_REG_IMPORT: u32 = 1;
pub const ZCRX_FEATURE_RX_PAGE_SIZE: u32 = 1;
pub const ZCRX_CTRL_FLUSH_RQ: u32 = 0;
pub const ZCRX_CTRL_EXPORT: u32 = 1;
pub const ZCRX_CTRL_LAST: u32 = 2;
