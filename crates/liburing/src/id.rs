//! Allocation-free operation identifiers shared by all ring users.

use crate::error::UringError;

/// Routing index in the high byte of an operation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SubsystemId(pub u8);

impl SubsystemId {
    /// Reserved routing slot for proactor-owned operations.
    pub const INTERNAL: Self = Self(0);

    /// Accepts public subsystem indices `1..=255`; zero is reserved.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn new(id: u8) -> Option<Self> {
        if id == 0 { None } else { Some(Self(id)) }
    }

    /// Constructs an identifier including the reserved internal slot.
    ///
    /// Callers registering public handlers should use [`Self::new`].
    ///
    /// # Panics
    /// Does not panic.
    pub const fn new_unchecked(id: u8) -> Self {
        Self(id)
    }

    /// Returns the routing byte.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn raw(self) -> u8 {
        self.0
    }
}

/// Subsystem-defined payload occupying the low 56 bits of an operation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct OpPayload(pub u64);

impl OpPayload {
    /// Largest value representable without losing payload bits.
    pub const MAX_RAW: u64 = 0x00FF_FFFF_FFFF_FFFF;

    /// Rejects values whose high byte is nonzero.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn new(raw: u64) -> Option<Self> {
        if raw <= Self::MAX_RAW {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// Constructs a payload without checking its width.
    ///
    /// Callers should supply a value at most [`Self::MAX_RAW`]. Packing an
    /// oversized value discards its high byte without altering the routing byte.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn new_unchecked(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the stored payload value.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Kernel `user_data`: `[8-bit SubsystemId | 56-bit OpPayload]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct OpId(pub u64);

impl OpId {
    /// Combines a routing byte and payload without allocation.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn pack(subsystem: SubsystemId, payload: OpPayload) -> Self {
        Self(((subsystem.raw() as u64) << 56) | (payload.raw() & OpPayload::MAX_RAW))
    }

    /// Interprets a kernel `user_data` value as an operation identifier.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the exact value written to kernel `user_data`.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Extracts the routing byte, including the reserved internal index.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn subsystem_id(self) -> SubsystemId {
        SubsystemId::new_unchecked((self.0 >> 56) as u8)
    }

    /// Extracts the low 56 payload bits.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn payload(self) -> OpPayload {
        OpPayload::new_unchecked(self.0 & OpPayload::MAX_RAW)
    }

    /// Splits an identifier into its routing byte and subsystem payload.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn unpack(self) -> (SubsystemId, OpPayload) {
        (self.subsystem_id(), self.payload())
    }
}

/// Index in a ring's registered-file table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct UringFileSlot(pub u32);

/// Index in a registered or provided buffer pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BufferId(pub u16);

/// Kernel provided-buffer group identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BufGroupId(pub u16);

impl UringFileSlot {
    /// Returns the registered-file table index.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl BufferId {
    /// Returns the buffer pool index.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl BufGroupId {
    /// Returns the kernel provided-buffer group index.
    ///
    /// # Panics
    /// Does not panic.
    pub const fn raw(self) -> u16 {
        self.0
    }
}

/// A subsystem's allocation-free conversion to and from its 56-bit payload.
pub trait OpPayloadCodec: Sized {
    /// Encodes a value as a valid 56-bit payload.
    ///
    /// # Panics
    /// Implementations must document any encoding preconditions that can panic.
    fn encode_payload(&self) -> OpPayload;

    /// Decodes and validates a subsystem-specific operation payload.
    ///
    /// # Errors
    /// Returns [`UringError::InvalidPayload`] for unsupported encodings.
    fn decode_payload(payload: OpPayload) -> Result<Self, UringError>;
}

#[cfg(test)]
mod unit {
    use super::{OpId, OpPayload, SubsystemId};

    #[test]
    fn every_routing_byte_preserves_payload_boundaries() {
        for route in 0..=u8::MAX {
            for raw in [0, 1, 0x0023_4567_89ab_cdef, OpPayload::MAX_RAW] {
                let payload = OpPayload::new(raw).expect("test payload fits 56 bits");
                let subsystem = SubsystemId::new_unchecked(route);
                let packed = OpId::pack(subsystem, payload);
                assert_eq!(packed.unpack(), (subsystem, payload));
                assert_eq!(OpId::from_raw(packed.raw()), packed);
            }
        }
    }

    #[test]
    fn invalid_payload_cannot_overwrite_routing_byte() {
        assert_eq!(OpPayload::new(OpPayload::MAX_RAW + 1), None);
        let route = SubsystemId::new_unchecked(7);
        let packed = OpId::pack(route, OpPayload::new_unchecked(u64::MAX));
        assert_eq!(packed.subsystem_id(), route);
        assert_eq!(packed.payload().raw(), OpPayload::MAX_RAW);
        assert_eq!(SubsystemId::new(0), None);
    }
}
