//! Raw query/bpf ABI records. Integer addresses carry no ownership.
use uarch::prelude::*;

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringQueryHdr {
    pub next_entry: u64,
    pub query_data: u64,
    pub query_op: u32,
    pub size: u32,
    pub result: i32,
    pub __resv: [u32; 3],
}
assert_layout!(IoUringQueryHdr, size = 40, align = 8, fields = {
    next_entry: 0, query_data: 8, query_op: 16, size: 20, result: 24, __resv: 28,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringQueryOpcode {
    pub nr_request_opcodes: u32,
    pub nr_register_opcodes: u32,
    pub feature_flags: u64,
    pub ring_setup_flags: u64,
    pub enter_flags: u64,
    pub sqe_flags: u64,
    pub nr_query_opcodes: u32,
    pub __pad: u32,
}
assert_layout!(IoUringQueryOpcode, size = 48, align = 8, fields = {
    nr_request_opcodes: 0, nr_register_opcodes: 4, feature_flags: 8, ring_setup_flags: 16, enter_flags: 24, sqe_flags: 32, nr_query_opcodes: 40, __pad: 44,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringQueryZcrx {
    pub register_flags: u64,
    pub area_flags: u64,
    pub nr_ctrl_opcodes: u32,
    pub features: u32,
    pub rq_hdr_size: u32,
    pub rq_hdr_alignment: u32,
    pub __resv2: u64,
}
assert_layout!(IoUringQueryZcrx, size = 40, align = 8, fields = {
    register_flags: 0, area_flags: 8, nr_ctrl_opcodes: 16, features: 20, rq_hdr_size: 24, rq_hdr_alignment: 28, __resv2: 32,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringQueryScq {
    pub hdr_size: u64,
    pub hdr_alignment: u64,
}
assert_layout!(IoUringQueryScq, size = 16, align = 8, fields = {
    hdr_size: 0, hdr_alignment: 8,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringBpfCtx {
    pub user_data: u64,
    pub opcode: u8,
    pub sqe_flags: u8,
    pub pdu_size: u8,
    pub pad: [u8; 5],
    pub pdu: [u64; 3],
}
assert_layout!(IoUringBpfCtx, size = 40, align = 8, fields = {
    user_data: 0, opcode: 8, sqe_flags: 9, pdu_size: 10, pad: 11, pdu: 16,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringBpfFilter {
    pub opcode: u32,
    pub flags: u32,
    pub filter_len: u32,
    pub pdu_size: u8,
    pub resv: [u8; 3],
    pub filter_ptr: u64,
    pub resv2: [u64; 5],
}
assert_layout!(IoUringBpfFilter, size = 64, align = 8, fields = {
    opcode: 0, flags: 4, filter_len: 8, pdu_size: 12, resv: 13, filter_ptr: 16, resv2: 24,
});

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringBpf {
    pub cmd_type: u16,
    pub cmd_flags: u16,
    pub resv: u32,
    pub filter: IoUringBpfFilter,
}
assert_layout!(IoUringBpf, size = 72, align = 8, fields = {
    cmd_type: 0, cmd_flags: 2, resv: 4, filter: 8,
});

pub const IO_URING_QUERY_OPCODES: u32 = 0;
pub const IO_URING_QUERY_ZCRX: u32 = 1;
pub const IO_URING_QUERY_SCQ: u32 = 2;
pub const IO_URING_QUERY_MAX: u32 = 3;
pub const IO_URING_BPF_FILTER_DENY_REST: u32 = 1;
pub const IO_URING_BPF_FILTER_SZ_STRICT: u32 = 2;
pub const IO_URING_BPF_CMD_FILTER: u16 = 1;
