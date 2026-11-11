//! Raw futex ABI records. Integer addresses carry no ownership.
use uarch::prelude::*;

/// Linux UAPI record. Reserved fields must remain zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FutexWaitv {
    pub val: u64,
    pub uaddr: u64,
    pub flags: u32,
    pub __reserved: u32,
}
assert_layout!(FutexWaitv, size = 24, align = 8, fields = {
    val: 0, uaddr: 8, flags: 16, __reserved: 20,
});

/// UAPI size encodings; Linux currently implements only the U32 operational size.
pub const FUTEX2_SIZE_U8: u32 = 0;
pub const FUTEX2_SIZE_U16: u32 = 1;
pub const FUTEX2_SIZE_U32: u32 = 2;
pub const FUTEX2_SIZE_U64: u32 = 3;
pub const FUTEX2_SIZE_MASK: u32 = 3;
pub const FUTEX2_NUMA: u32 = 4;
pub const FUTEX2_MPOL: u32 = 8;
pub const FUTEX2_PRIVATE: u32 = 128;
pub const FUTEX_NO_NODE: i32 = -1;
pub const FUTEX_WAITV_MAX: u32 = 128;
pub const FUTEX_BITSET_MATCH_ANY: u32 = u32::MAX;
