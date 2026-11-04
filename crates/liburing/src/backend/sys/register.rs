//! Registration ABI records; counts and lifetimes remain the caller's responsibility.
use uarch::prelude::*;

use super::params::KernelTimespec;

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringFilesUpdate {
    pub offset: u32,
    pub resv: u32,
    pub fds: u64,
}
assert_layout!(IoUringFilesUpdate, size = 16, align = 8, fields = {
    offset: 0, resv: 4, fds: 8,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringRsrcRegister {
    pub nr: u32,
    pub flags: u32,
    pub resv2: u64,
    pub data: u64,
    pub tags: u64,
}
assert_layout!(IoUringRsrcRegister, size = 32, align = 8, fields = {
    nr: 0, flags: 4, resv2: 8, data: 16, tags: 24,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringRsrcUpdate {
    pub offset: u32,
    pub resv: u32,
    pub data: u64,
}
assert_layout!(IoUringRsrcUpdate, size = 16, align = 8, fields = {
    offset: 0, resv: 4, data: 8,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringRsrcUpdate2 {
    pub offset: u32,
    pub resv: u32,
    pub data: u64,
    pub tags: u64,
    pub nr: u32,
    pub resv2: u32,
}
assert_layout!(IoUringRsrcUpdate2, size = 32, align = 8, fields = {
    offset: 0, resv: 4, data: 8, tags: 16, nr: 24, resv2: 28,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringProbeOp {
    pub op: u8,
    pub resv: u8,
    pub flags: u16,
    pub resv2: u32,
}
assert_layout!(IoUringProbeOp, size = 8, align = 4, fields = {
    op: 0, resv: 1, flags: 2, resv2: 4,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringProbeHeader {
    pub last_op: u8,
    pub ops_len: u8,
    pub resv: u16,
    pub resv2: [u32; 3],
}
assert_layout!(IoUringProbeHeader, size = 16, align = 4, fields = {
    last_op: 0, ops_len: 1, resv: 2, resv2: 4,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringRestriction {
    pub opcode: u16,
    pub register_op: u8,
    pub resv: u8,
    pub resv2: [u32; 3],
}
assert_layout!(IoUringRestriction, size = 16, align = 4, fields = {
    opcode: 0, register_op: 2, resv: 3, resv2: 4,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringTaskRestrictionHeader {
    pub flags: u16,
    pub nr_res: u16,
    pub resv: [u32; 3],
}
assert_layout!(IoUringTaskRestrictionHeader, size = 16, align = 4, fields = {
    flags: 0, nr_res: 2, resv: 4,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringClockRegister {
    pub clockid: u32,
    pub __resv: [u32; 3],
}
assert_layout!(IoUringClockRegister, size = 16, align = 4, fields = {
    clockid: 0, __resv: 4,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringCloneBuffers {
    pub src_fd: u32,
    pub flags: u32,
    pub src_off: u32,
    pub dst_off: u32,
    pub nr: u32,
    pub pad: [u32; 3],
}
assert_layout!(IoUringCloneBuffers, size = 32, align = 4, fields = {
    src_fd: 0, flags: 4, src_off: 8, dst_off: 12, nr: 16, pad: 20,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringBuf {
    pub addr: u64,
    pub len: u32,
    pub bid: u16,
    pub resv: u16,
}
assert_layout!(IoUringBuf, size = 16, align = 8, fields = {
    addr: 0, len: 8, bid: 12, resv: 14,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringBufRingHeader {
    pub resv1: u64,
    pub resv2: u32,
    pub resv3: u16,
    pub tail: u16,
}
assert_layout!(IoUringBufRingHeader, size = 16, align = 8, fields = {
    resv1: 0, resv2: 8, resv3: 12, tail: 14,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringBufReg {
    pub ring_addr: u64,
    pub ring_entries: u32,
    pub bgid: u16,
    pub flags: u16,
    pub min_left: u32,
    pub resv: [u32; 5],
}
assert_layout!(IoUringBufReg, size = 40, align = 8, fields = {
    ring_addr: 0, ring_entries: 8, bgid: 12, flags: 14, min_left: 16, resv: 20,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringBufStatus {
    pub buf_group: u32,
    pub head: u32,
    pub resv: [u32; 8],
}
assert_layout!(IoUringBufStatus, size = 40, align = 4, fields = {
    buf_group: 0, head: 4, resv: 8,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringNapi {
    pub busy_poll_to: u32,
    pub prefer_busy_poll: u8,
    pub opcode: u8,
    pub pad: [u8; 2],
    pub op_param: u32,
    pub resv: u32,
}
assert_layout!(IoUringNapi, size = 16, align = 4, fields = {
    busy_poll_to: 0, prefer_busy_poll: 4, opcode: 5, pad: 6, op_param: 8, resv: 12,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringSyncCancelReg {
    pub addr: u64,
    pub fd: i32,
    pub flags: u32,
    pub timeout: KernelTimespec,
    pub opcode: u8,
    pub pad: [u8; 7],
    pub pad2: [u64; 3],
}
assert_layout!(IoUringSyncCancelReg, size = 64, align = 8, fields = {
    addr: 0, fd: 8, flags: 12, timeout: 16, opcode: 32, pad: 33, pad2: 40,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringFileIndexRange {
    pub off: u32,
    pub len: u32,
    pub resv: u64,
}
assert_layout!(IoUringFileIndexRange, size = 16, align = 8, fields = {
    off: 0, len: 4, resv: 8,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringRecvmsgOut {
    pub namelen: u32,
    pub controllen: u32,
    pub payloadlen: u32,
    pub flags: u32,
}
assert_layout!(IoUringRecvmsgOut, size = 16, align = 4, fields = {
    namelen: 0, controllen: 4, payloadlen: 8, flags: 12,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringRegionDesc {
    pub user_addr: u64,
    pub size: u64,
    pub flags: u32,
    pub id: u32,
    pub mmap_offset: u64,
    pub __resv: [u64; 4],
}
assert_layout!(IoUringRegionDesc, size = 64, align = 8, fields = {
    user_addr: 0, size: 8, flags: 16, id: 20, mmap_offset: 24, __resv: 32,
});

/// Linux registration record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringMemRegionReg {
    pub region_uptr: u64,
    pub flags: u64,
    pub __resv: [u64; 2],
}
assert_layout!(IoUringMemRegionReg, size = 32, align = 8, fields = {
    region_uptr: 0, flags: 8, __resv: 16,
});

/// Frozen control inventory; unsupported operations still return kernel errno.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOpcode {
    RegisterBuffers = 0,
    UnregisterBuffers = 1,
    RegisterFiles = 2,
    UnregisterFiles = 3,
    RegisterEventfd = 4,
    UnregisterEventfd = 5,
    RegisterFilesUpdate = 6,
    RegisterEventfdAsync = 7,
    RegisterProbe = 8,
    RegisterPersonality = 9,
    UnregisterPersonality = 10,
    RegisterRestrictions = 11,
    RegisterEnableRings = 12,
    RegisterFiles2 = 13,
    RegisterFilesUpdate2 = 14,
    RegisterBuffers2 = 15,
    RegisterBuffersUpdate = 16,
    RegisterIowqAff = 17,
    UnregisterIowqAff = 18,
    RegisterIowqMaxWorkers = 19,
    RegisterRingFds = 20,
    UnregisterRingFds = 21,
    RegisterPbufRing = 22,
    UnregisterPbufRing = 23,
    RegisterSyncCancel = 24,
    RegisterFileAllocRange = 25,
    RegisterPbufStatus = 26,
    RegisterNapi = 27,
    UnregisterNapi = 28,
    RegisterClock = 29,
    RegisterCloneBuffers = 30,
    RegisterSendMsgRing = 31,
    RegisterZcrxIfq = 32,
    RegisterResizeRings = 33,
    RegisterMemRegion = 34,
    RegisterQuery = 35,
    RegisterZcrxCtrl = 36,
    RegisterBpfFilter = 37,
}
pub const IORING_REGISTER_BUFFERS: u32 = 0;
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;
pub const IORING_REGISTER_FILES: u32 = 2;
pub const IORING_UNREGISTER_FILES: u32 = 3;
pub const IORING_REGISTER_EVENTFD: u32 = 4;
pub const IORING_UNREGISTER_EVENTFD: u32 = 5;
pub const IORING_REGISTER_FILES_UPDATE: u32 = 6;
pub const IORING_REGISTER_EVENTFD_ASYNC: u32 = 7;
pub const IORING_REGISTER_PROBE: u32 = 8;
pub const IORING_REGISTER_PERSONALITY: u32 = 9;
pub const IORING_UNREGISTER_PERSONALITY: u32 = 10;
pub const IORING_REGISTER_RESTRICTIONS: u32 = 11;
pub const IORING_REGISTER_ENABLE_RINGS: u32 = 12;
pub const IORING_REGISTER_FILES2: u32 = 13;
pub const IORING_REGISTER_FILES_UPDATE2: u32 = 14;
pub const IORING_REGISTER_BUFFERS2: u32 = 15;
pub const IORING_REGISTER_BUFFERS_UPDATE: u32 = 16;
pub const IORING_REGISTER_IOWQ_AFF: u32 = 17;
pub const IORING_UNREGISTER_IOWQ_AFF: u32 = 18;
pub const IORING_REGISTER_IOWQ_MAX_WORKERS: u32 = 19;
pub const IORING_REGISTER_RING_FDS: u32 = 20;
pub const IORING_UNREGISTER_RING_FDS: u32 = 21;
pub const IORING_REGISTER_PBUF_RING: u32 = 22;
pub const IORING_UNREGISTER_PBUF_RING: u32 = 23;
pub const IORING_REGISTER_SYNC_CANCEL: u32 = 24;
pub const IORING_REGISTER_FILE_ALLOC_RANGE: u32 = 25;
pub const IORING_REGISTER_PBUF_STATUS: u32 = 26;
pub const IORING_REGISTER_NAPI: u32 = 27;
pub const IORING_UNREGISTER_NAPI: u32 = 28;
pub const IORING_REGISTER_CLOCK: u32 = 29;
pub const IORING_REGISTER_CLONE_BUFFERS: u32 = 30;
pub const IORING_REGISTER_SEND_MSG_RING: u32 = 31;
pub const IORING_REGISTER_ZCRX_IFQ: u32 = 32;
pub const IORING_REGISTER_RESIZE_RINGS: u32 = 33;
pub const IORING_REGISTER_MEM_REGION: u32 = 34;
pub const IORING_REGISTER_QUERY: u32 = 35;
pub const IORING_REGISTER_ZCRX_CTRL: u32 = 36;
pub const IORING_REGISTER_BPF_FILTER: u32 = 37;
pub const IORING_REGISTER_LAST: u32 = 38;
pub const IORING_REGISTER_USE_REGISTERED_RING: u32 = 1 << 31;
pub const IORING_REGISTER_FILES_SKIP: i32 = -2;
pub const IORING_RSRC_REGISTER_SPARSE: u32 = 1;
pub const IO_URING_OP_SUPPORTED: u16 = 1;
pub const IORING_MEM_REGION_TYPE_USER: u32 = 1;
pub const IORING_MEM_REGION_REG_WAIT_ARG: u64 = 1;
pub const IORING_REGISTER_SRC_REGISTERED: u32 = 1;
pub const IORING_REGISTER_DST_REPLACE: u32 = 2;
pub const IOU_PBUF_RING_MMAP: u16 = 1;
pub const IOU_PBUF_RING_INC: u16 = 2;
pub const IO_WQ_BOUND: u32 = 0;
pub const IO_WQ_UNBOUND: u32 = 1;
pub const IO_URING_NAPI_REGISTER_OP: u8 = 0;
pub const IO_URING_NAPI_STATIC_ADD_ID: u8 = 1;
pub const IO_URING_NAPI_STATIC_DEL_ID: u8 = 2;
pub const IO_URING_NAPI_TRACKING_DYNAMIC: u32 = 0;
pub const IO_URING_NAPI_TRACKING_STATIC: u32 = 1;
pub const IO_URING_NAPI_TRACKING_INACTIVE: u32 = 255;
pub const IORING_RESTRICTION_REGISTER_OP: u16 = 0;
pub const IORING_RESTRICTION_SQE_OP: u16 = 1;
pub const IORING_RESTRICTION_SQE_FLAGS_ALLOWED: u16 = 2;
pub const IORING_RESTRICTION_SQE_FLAGS_REQUIRED: u16 = 3;
pub const IORING_RESTRICTION_LAST: u16 = 4;

impl TryFrom<u32> for RegisterOpcode {
    type Error = u32;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value < IORING_REGISTER_LAST {
            // SAFETY: The enum has every discriminant in 0..IORING_REGISTER_LAST.
            Ok(unsafe { core::mem::transmute::<u32, Self>(value) })
        } else {
            Err(value)
        }
    }
}
