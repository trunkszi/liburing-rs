//! Ring setup, mapping offsets, and extended wait argument records.
use uarch::prelude::*;

/// Linux `IoSqringOffsets` ABI storage. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoSqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}
assert_layout!(IoSqringOffsets, size = 40, align = 8, fields = {
    head: 0, tail: 4, ring_mask: 8, ring_entries: 12, flags: 16, dropped: 20, array: 24, resv1: 28, user_addr: 32,
});

/// Linux `IoCqringOffsets` ABI storage. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoCqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}
assert_layout!(IoCqringOffsets, size = 40, align = 8, fields = {
    head: 0, tail: 4, ring_mask: 8, ring_entries: 12, overflow: 16, cqes: 20, flags: 24, resv1: 28, user_addr: 32,
});

/// Linux `IoUringParams` ABI storage. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: IoSqringOffsets,
    pub cq_off: IoCqringOffsets,
}
assert_layout!(IoUringParams, size = 120, align = 8, fields = {
    sq_entries: 0, cq_entries: 4, flags: 8, sq_thread_cpu: 12, sq_thread_idle: 16, features: 20, wq_fd: 24, resv: 28, sq_off: 40, cq_off: 80,
});

/// Linux `KernelTimespec` ABI storage. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
assert_layout!(KernelTimespec, size = 16, align = 8, fields = {
    tv_sec: 0, tv_nsec: 8,
});

/// Linux `IoTimespec` ABI storage. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoTimespec {
    pub tv_sec: u64,
    pub tv_nsec: u64,
}
assert_layout!(IoTimespec, size = 16, align = 8, fields = {
    tv_sec: 0, tv_nsec: 8,
});

/// Linux `IoUringGeteventsArg` ABI storage. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringGeteventsArg {
    pub sigmask: u64,
    pub sigmask_sz: u32,
    pub min_wait_usec: u32,
    pub ts: u64,
}
assert_layout!(IoUringGeteventsArg, size = 24, align = 8, fields = {
    sigmask: 0, sigmask_sz: 8, min_wait_usec: 12, ts: 16,
});

/// Linux `IoUringRegWait` ABI storage. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringRegWait {
    pub ts: KernelTimespec,
    pub min_wait_usec: u32,
    pub flags: u32,
    pub sigmask: u64,
    pub sigmask_sz: u32,
    pub pad: [u32; 3],
    pub pad2: [u64; 2],
}
assert_layout!(IoUringRegWait, size = 64, align = 8, fields = {
    ts: 0, min_wait_usec: 16, flags: 20, sigmask: 24, sigmask_sz: 32, pad: 36, pad2: 48,
});
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
pub const IORING_SETUP_SUBMIT_ALL: u32 = 1 << 7;
pub const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
pub const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;
pub const IORING_SETUP_SQE128: u32 = 1 << 10;
pub const IORING_SETUP_CQE32: u32 = 1 << 11;
pub const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
pub const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
pub const IORING_SETUP_NO_MMAP: u32 = 1 << 14;
pub const IORING_SETUP_REGISTERED_FD_ONLY: u32 = 1 << 15;
pub const IORING_SETUP_NO_SQARRAY: u32 = 1 << 16;
pub const IORING_SETUP_HYBRID_IOPOLL: u32 = 1 << 17;
pub const IORING_SETUP_CQE_MIXED: u32 = 1 << 18;
pub const IORING_SETUP_SQE_MIXED: u32 = 1 << 19;
pub const IORING_SETUP_SQ_REWIND: u32 = 1 << 20;
pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
pub const IORING_FEAT_NODROP: u32 = 1 << 1;
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
pub const IORING_FEAT_FAST_POLL: u32 = 1 << 5;
pub const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;
pub const IORING_FEAT_SQPOLL_NONFIXED: u32 = 1 << 7;
pub const IORING_FEAT_EXT_ARG: u32 = 1 << 8;
pub const IORING_FEAT_NATIVE_WORKERS: u32 = 1 << 9;
pub const IORING_FEAT_RSRC_TAGS: u32 = 1 << 10;
pub const IORING_FEAT_CQE_SKIP: u32 = 1 << 11;
pub const IORING_FEAT_LINKED_FILE: u32 = 1 << 12;
pub const IORING_FEAT_REG_REG_RING: u32 = 1 << 13;
pub const IORING_FEAT_RECVSEND_BUNDLE: u32 = 1 << 14;
pub const IORING_FEAT_MIN_TIMEOUT: u32 = 1 << 15;
pub const IORING_FEAT_RW_ATTR: u32 = 1 << 16;
pub const IORING_FEAT_NO_IOWAIT: u32 = 1 << 17;
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;
pub const IORING_ENTER_SQ_WAIT: u32 = 1 << 2;
pub const IORING_ENTER_EXT_ARG: u32 = 1 << 3;
pub const IORING_ENTER_REGISTERED_RING: u32 = 1 << 4;
pub const IORING_ENTER_ABS_TIMER: u32 = 1 << 5;
pub const IORING_ENTER_EXT_ARG_REG: u32 = 1 << 6;
pub const IORING_ENTER_NO_IOWAIT: u32 = 1 << 7;
pub const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;
pub const IORING_SQ_CQ_OVERFLOW: u32 = 1 << 1;
pub const IORING_SQ_TASKRUN: u32 = 1 << 2;
pub const IORING_CQ_EVENTFD_DISABLED: u32 = 1 << 0;
pub const IORING_OFF_SQ_RING: u64 = 0;
pub const IORING_OFF_CQ_RING: u64 = 0x0800_0000;
pub const IORING_OFF_SQES: u64 = 0x1000_0000;
pub const IORING_OFF_PBUF_RING: u64 = 0x8000_0000;
pub const IORING_OFF_PBUF_SHIFT: u32 = 16;
pub const IORING_OFF_MMAP_MASK: u64 = 0xf800_0000;
pub const IORING_REG_WAIT_TS: u32 = 1;
