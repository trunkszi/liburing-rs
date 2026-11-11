//! futex2 flag word and the plain and NUMA futex operands.
//!
//! Linux implements only the 32-bit size. With `FUTEX2_NUMA`, the kernel writes
//! the resolved node into the second word on both wait and wake when that word
//! is `FUTEX_NO_NODE`.

use core::{
    marker::PhantomData,
    sync::atomic::{AtomicI32, AtomicU32},
};

use uarch::prelude::*;

use crate::backend::sys::futex::{
    FUTEX_NO_NODE, FUTEX2_MPOL, FUTEX2_NUMA, FUTEX2_PRIVATE, FUTEX2_SIZE_U8, FUTEX2_SIZE_U16,
    FUTEX2_SIZE_U32, FUTEX2_SIZE_U64,
};

bitword! {
    /// futex2 flags. Size occupies bits 0..=1; NUMA, MPOL, and PRIVATE are single bits.
    #[derive(Debug)]
    pub struct FutexFlags(u32) {
        [0] SIZE_LO,
        [1] SIZE_HI,
        [2] NUMA_BIT,
        [3] MPOL_BIT,
        [7] PRIVATE_BIT,
    }
}

impl FutexFlags {
    /// `FUTEX2_SIZE_U8`. Linux rejects this size at runtime.
    pub const SIZE_U8: Self = Self(0);
    /// `FUTEX2_SIZE_U16`. Linux rejects this size at runtime.
    pub const SIZE_U16: Self = Self(Self::SIZE_LO.mask() as u32);
    /// `FUTEX2_SIZE_U32`, the only size Linux implements.
    pub const SIZE_U32: Self = Self(Self::SIZE_HI.mask() as u32);
    /// `FUTEX2_SIZE_U64`. Linux rejects this size at runtime.
    pub const SIZE_U64: Self = Self((Self::SIZE_LO.mask() | Self::SIZE_HI.mask()) as u32);
    /// `FUTEX2_NUMA`. The operand is an 8-byte value/node pair.
    pub const NUMA: Self = Self(Self::NUMA_BIT.mask() as u32);
    /// `FUTEX2_MPOL`. Accepted with or without `NUMA`.
    pub const MPOL: Self = Self(Self::MPOL_BIT.mask() as u32);
    /// `FUTEX2_PRIVATE`. Selects the process-private futex key.
    pub const PRIVATE: Self = Self(Self::PRIVATE_BIT.mask() as u32);
    /// Private 32-bit word.
    pub const PRIVATE_U32: Self = Self(Self::SIZE_U32.raw() | Self::PRIVATE.raw());
    /// Private 32-bit NUMA double word.
    pub const PRIVATE_U32_NUMA: Self = Self(Self::PRIVATE_U32.raw() | Self::NUMA.raw());
    /// Private 32-bit NUMA double word with memory-policy placement.
    pub const PRIVATE_U32_NUMA_MPOL: Self = Self(Self::PRIVATE_U32_NUMA.raw() | Self::MPOL.raw());
    /// Shared 32-bit word.
    pub const SHARED_U32: Self = Self::SIZE_U32;
    /// Shared 32-bit NUMA double word.
    pub const SHARED_U32_NUMA: Self = Self(Self::SIZE_U32.raw() | Self::NUMA.raw());
    /// Shared 32-bit NUMA double word with memory-policy placement.
    pub const SHARED_U32_NUMA_MPOL: Self = Self(Self::SHARED_U32_NUMA.raw() | Self::MPOL.raw());

    /// Returns the raw futex2 flag bits stored in an SQE `fd` or a syscall argument.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline(always)]
    pub const fn bits(self) -> u32 {
        self.raw()
    }

    /// Flags legal for a 4-byte [`FutexWord`].
    ///
    /// Forces `FUTEX2_SIZE_U32` and keeps only `FUTEX2_PRIVATE`. `FUTEX2_NUMA`
    /// makes the kernel store a node in the four bytes after the value, and a
    /// plain word does not own that storage.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline(always)]
    #[must_use]
    pub const fn for_u32(self) -> Self {
        Self(Self::u32_flag_bits(self.raw()))
    }

    /// Flags legal for a [`FutexNumaU32`].
    ///
    /// Forces `FUTEX2_SIZE_U32 | FUTEX2_NUMA` and keeps only `FUTEX2_PRIVATE`
    /// and `FUTEX2_MPOL`. The 8-byte operand owns the node word.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline(always)]
    #[must_use]
    pub const fn for_numa_u32(self) -> Self {
        Self(Self::numa_flag_bits(self.raw()))
    }

    /// [`Self::for_u32`] applied to a raw flag word.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline(always)]
    #[must_use]
    pub const fn u32_flag_bits(bits: u32) -> u32 {
        FUTEX2_SIZE_U32 | (bits & FUTEX2_PRIVATE)
    }

    /// [`Self::for_numa_u32`] applied to a raw flag word.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline(always)]
    #[must_use]
    pub const fn numa_flag_bits(bits: u32) -> u32 {
        FUTEX2_SIZE_U32 | FUTEX2_NUMA | (bits & (FUTEX2_PRIVATE | FUTEX2_MPOL))
    }
}

const _: () = {
    assert!(FutexFlags::SIZE_U8.raw() == FUTEX2_SIZE_U8);
    assert!(FutexFlags::SIZE_U16.raw() == FUTEX2_SIZE_U16);
    assert!(FutexFlags::SIZE_U32.raw() == FUTEX2_SIZE_U32);
    assert!(FutexFlags::SIZE_U64.raw() == FUTEX2_SIZE_U64);
    assert!(FutexFlags::NUMA.raw() == FUTEX2_NUMA);
    assert!(FutexFlags::MPOL.raw() == FUTEX2_MPOL);
    assert!(FutexFlags::PRIVATE.raw() == FUTEX2_PRIVATE);
    assert!(FutexFlags::PRIVATE_U32.raw() == (FUTEX2_SIZE_U32 | FUTEX2_PRIVATE));
    assert!(FutexFlags::PRIVATE_U32_NUMA.raw() == (FUTEX2_SIZE_U32 | FUTEX2_NUMA | FUTEX2_PRIVATE));
    assert!(
        FutexFlags::PRIVATE_U32_NUMA_MPOL.raw()
            == (FUTEX2_SIZE_U32 | FUTEX2_NUMA | FUTEX2_MPOL | FUTEX2_PRIVATE)
    );
    assert!(FutexFlags::SHARED_U32.raw() == FUTEX2_SIZE_U32);
    assert!(FutexFlags::SHARED_U32_NUMA.raw() == (FUTEX2_SIZE_U32 | FUTEX2_NUMA));
    assert!(
        FutexFlags::SHARED_U32_NUMA_MPOL.raw() == (FUTEX2_SIZE_U32 | FUTEX2_NUMA | FUTEX2_MPOL)
    );
    assert!(FutexFlags::PRIVATE_U32_NUMA.for_u32().raw() == FutexFlags::PRIVATE_U32.raw());
    assert!(FutexFlags::SIZE_U64.for_u32().raw() == FUTEX2_SIZE_U32);
    assert!(FutexFlags::SHARED_U32.for_u32().raw() == FUTEX2_SIZE_U32);
    assert!(
        FutexFlags::PRIVATE_U32_NUMA_MPOL.for_numa_u32().raw()
            == FutexFlags::PRIVATE_U32_NUMA_MPOL.raw()
    );
    assert!(FutexFlags::SIZE_U8.for_numa_u32().raw() == (FUTEX2_SIZE_U32 | FUTEX2_NUMA));
    assert!(
        FutexFlags::u32_flag_bits(FUTEX2_SIZE_U64 | FUTEX2_NUMA | FUTEX2_MPOL) == FUTEX2_SIZE_U32
    );
    assert!(
        FutexFlags::numa_flag_bits(FUTEX2_PRIVATE | FUTEX2_MPOL)
            == (FUTEX2_SIZE_U32 | FUTEX2_NUMA | FUTEX2_PRIVATE | FUTEX2_MPOL)
    );
};

/// Process-private or shared 32-bit futex word.
#[repr(transparent)]
#[derive(Debug)]
pub struct FutexWord(pub AtomicU32);

impl FutexWord {
    /// Stores `value` in a 4-byte-aligned word.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(AtomicU32::new(value))
    }

    /// Address passed to futex2. The pointer remains valid for the borrow of `self`.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.0.as_ptr().cast()
    }
}

/// Eight-byte NUMA futex: the value word followed by the node word.
///
/// Both wait and wake require writable storage. When `node` is `FUTEX_NO_NODE`,
/// the kernel replaces it with the resolved node id.
#[repr(C, align(8))]
#[derive(Debug)]
pub struct FutexNumaU32 {
    /// Futex value compared by wait and published by the application.
    pub value: AtomicU32,
    /// NUMA node. `FUTEX_NO_NODE` asks the kernel to write the resolved node.
    pub node: AtomicI32,
}
assert_layout!(FutexNumaU32, size = 8, align = 8, fields = { value: 0, node: 4 });

impl FutexNumaU32 {
    /// Stores `value` and sets `node` to `FUTEX_NO_NODE`.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self {
            value: AtomicU32::new(value),
            node: AtomicI32::new(FUTEX_NO_NODE),
        }
    }

    /// Stores both the value and an explicit node id.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn with_node(value: u32, node: i32) -> Self {
        Self {
            value: AtomicU32::new(value),
            node: AtomicI32::new(node),
        }
    }

    /// Address of the 8-byte pair. The kernel may store through this pointer.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn as_ptr(&self) -> *mut core::ffi::c_void {
        core::ptr::from_ref(self).cast_mut().cast()
    }
}

/// One `futex_waitv` record. Fields match the Linux UAPI order.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FutexWaitV {
    /// Expected futex value, or the compare value for requeue.
    pub val: u64,
    /// Futex address as an integer. NUMA uses the address of the 8-byte pair.
    pub uaddr: u64,
    /// Per-record futex2 flags.
    pub flags: u32,
    /// Must stay zero. The kernel rejects a nonzero reserved word.
    pub __reserved: u32,
}
assert_layout!(FutexWaitV, size = 24, align = 8, fields = {
    val: 0, uaddr: 8, flags: 16, __reserved: 20,
});

const _: () = {
    use crate::backend::sys::futex::FutexWaitv;
    assert!(core::mem::size_of::<FutexWaitV>() == core::mem::size_of::<FutexWaitv>());
    assert!(core::mem::align_of::<FutexWaitV>() == core::mem::align_of::<FutexWaitv>());
};

impl FutexWaitV {
    /// Zero record. The reserved word stays zero.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn new() -> Self {
        Self {
            val: 0,
            uaddr: 0,
            flags: 0,
            __reserved: 0,
        }
    }

    /// Sets the expected value.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn val(mut self, val: u64) -> Self {
        self.val = val;
        self
    }

    /// Sets the futex address.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn uaddr(mut self, uaddr: u64) -> Self {
        self.uaddr = uaddr;
        self
    }

    /// Sets the per-record futex2 flags.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }
}

/// Wait record borrowed from a live `FutexWord` or `FutexNumaU32`.
#[derive(Debug, Clone, Copy)]
pub struct FutexWaiter<'a> {
    record: FutexWaitV,
    _word: PhantomData<&'a ()>,
}

impl<'a> FutexWaiter<'a> {
    /// Points a wait record at a plain 32-bit word.
    ///
    /// Stored flags are [`FutexFlags::for_u32`]: size is `FUTEX2_SIZE_U32`, and
    /// only `FUTEX2_PRIVATE` is kept. A NUMA bit here would let the kernel write
    /// the four bytes that follow `word`.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub fn from_u32(word: &'a FutexWord, val: u64, flags: FutexFlags) -> Self {
        Self {
            record: FutexWaitV::new()
                .uaddr(word.as_ptr() as u64)
                .val(val)
                .flags(flags.for_u32().bits()),
            _word: PhantomData,
        }
    }

    /// Points a wait record at a NUMA double word.
    ///
    /// Stored flags are [`FutexFlags::for_numa_u32`]: size and NUMA are forced
    /// on, and only `FUTEX2_PRIVATE` and `FUTEX2_MPOL` are kept. The kernel may
    /// write `word.node`.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub fn from_numa_u32(word: &'a FutexNumaU32, val: u64, flags: FutexFlags) -> Self {
        Self {
            record: FutexWaitV::new()
                .uaddr(word.as_ptr() as u64)
                .val(val)
                .flags(flags.for_numa_u32().bits()),
            _word: PhantomData,
        }
    }

    /// Copies the UAPI record. The borrow still tracks the source word.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub const fn as_waitv(self) -> FutexWaitV {
        self.record
    }
}
