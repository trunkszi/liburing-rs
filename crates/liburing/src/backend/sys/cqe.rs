//! Copied completion records and a two-scalar register representation.
use uarch::prelude::*;

/// Standard kernel completion record. A negative result can also be notification usage bits.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}
assert_layout!(RawCqe, size = 16, align = 8, fields = { user_data: 0, res: 8, flags: 12 });

/// Extended completion record; mixed queues consume two physical 16-byte units.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawCqe32 {
    pub base: RawCqe,
    pub big_cqe: [u64; 2],
}
assert_layout!(RawCqe32, size = 32, align = 8, fields = { base: 0, big_cqe: 16 });

bitword! {
    /// Rotated little-endian result/flags word with hot flags in the low half.
    #[derive(Debug)]
    pub struct CqeWord(u64) {
        [0] pub BUFFER,
        [1] pub MORE,
        [2] pub SOCK_NONEMPTY,
        [3] pub NOTIF,
        [4] pub BUF_MORE,
        [5] pub SKIP,
        [15] pub BIG,
        [16..=31] pub BID: u16,
        [32..=63] pub RESULT: u32,
    }
}
assert_layout!(CqeWord, size = 8, align = 8);

/// Two scalar leaves for Rust register passing; wire layout remains RawCqe.
#[register_pass]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletionWords {
    pub user_data: u64,
    pub word: CqeWord,
}
assert_layout!(CompletionWords, size = 16, align = 8, fields = { user_data: 0, word: 8 });

impl From<RawCqe> for CompletionWords {
    #[hot_inline]
    fn from(cqe: RawCqe) -> Self {
        let wire = u64::from(cqe.res as u32) | (u64::from(cqe.flags) << 32);
        Self {
            user_data: cqe.user_data,
            word: CqeWord::new(wire.rotate_left(32)),
        }
    }
}
impl From<CompletionWords> for RawCqe {
    #[hot_inline]
    fn from(words: CompletionWords) -> Self {
        Self {
            user_data: words.user_data,
            res: words.result(),
            flags: words.flags(),
        }
    }
}
impl CompletionWords {
    /// Reads the original signed result without classifying notification usage as errno.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn result(self) -> i32 {
        self.word.get(CqeWord::RESULT) as i32
    }
    /// Reads the original flags, including unknown future flag bits.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn flags(self) -> u32 {
        self.word.raw() as u32
    }
}

pub const IORING_CQE_F_BUFFER: u32 = 1;
pub const IORING_CQE_F_MORE: u32 = 1 << 1;
pub const IORING_CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;
pub const IORING_CQE_F_NOTIF: u32 = 1 << 3;
pub const IORING_CQE_F_BUF_MORE: u32 = 1 << 4;
pub const IORING_CQE_F_SKIP: u32 = 1 << 5;
pub const IORING_CQE_F_32: u32 = 1 << 15;
pub const IORING_CQE_BUFFER_SHIFT: u32 = 16;
pub const IORING_NOTIF_USAGE_ZC_COPIED: u32 = 1 << 31;
