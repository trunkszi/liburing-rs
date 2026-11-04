//! Supported submission opcodes and optional kernel-wide registration inventory.
use uarch::prelude::{Bitmap64, cold_sink, hot_inline};

use super::RegisterTarget;
use crate::{
    Result, UringError,
    backend::sys::{query_bpf::*, register::*},
};

#[repr(C)]
struct ProbeStorage {
    header: IoUringProbeHeader,
    ops: [IoUringProbeOp; 256],
}

uarch::layout::assert_layout!(ProbeStorage, size = 2064, align = 4, fields = { header: 0, ops: 16 });

/// A complete byte-opcode lookup, including the full 0..=255 input domain.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpcodeProbe {
    supported: [u64; 4],
}
impl OpcodeProbe {
    /// Tests the opcode byte without allocation or out-of-range indexing.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn supports(&self, opcode: u8) -> bool {
        Bitmap64::new(self.supported[(opcode >> 6) as usize]).test((opcode & 63) as u32)
    }
    /// Borrows the four words of the supported opcode bitset.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn words(&self) -> &[u64; 4] {
        &self.supported
    }
}

/// Reads `IORING_REGISTER_PROBE` into bounded, initialized storage.
/// # Errors
/// Propagates the registration syscall's error.
/// # Panics
/// Does not panic.
#[cold_sink]
pub fn register_probe(target: RegisterTarget) -> Result<OpcodeProbe> {
    let mut storage = ProbeStorage {
        header: IoUringProbeHeader::default(),
        ops: [IoUringProbeOp::default(); 256],
    };
    // SAFETY: The contiguous repr(C) record has a header and capacity for all 256 entries.
    unsafe {
        target.register(
            RegisterOpcode::RegisterProbe,
            (&raw mut storage).cast(),
            256,
        )
    }?;
    let mut probe = OpcodeProbe::default();
    for entry in &storage.ops[..usize::from(storage.header.ops_len)] {
        if entry.flags & IO_URING_OP_SUPPORTED != 0 {
            let word = &mut probe.supported[(entry.op >> 6) as usize];
            *word = Bitmap64::new(*word).set(u32::from(entry.op & 63)).raw();
        }
    }
    Ok(probe)
}

/// Queries a caller-provided linked UAPI query record.
/// # Errors
/// Returns syscall errors; individual queries also report errors in `header.result`.
/// # Panics
/// Does not panic.
/// # Safety
/// Each linked header and query_data range must be initialized and writable for
/// its declared size during the call; links must not outlive their storage.
#[cold_sink]
pub unsafe fn register_query(target: RegisterTarget, header: &mut IoUringQueryHdr) -> Result<u32> {
    // SAFETY: The caller guarantees all linked records and pointed-to buffers.
    unsafe {
        target.register(
            RegisterOpcode::RegisterQuery,
            (header as *mut IoUringQueryHdr).cast(),
            0,
        )
    }
}

/// Reads the kernel-wide opcode inventory, independently of per-ring feature negotiation.
/// # Errors
/// Returns syscall errors, per-query errors, or a truncated inventory error.
/// # Panics
/// Does not panic.
#[cold_sink]
pub fn query_opcode_inventory(target: RegisterTarget) -> Result<IoUringQueryOpcode> {
    let mut data = IoUringQueryOpcode::default();
    let mut header = IoUringQueryHdr {
        query_data: (&raw mut data) as u64,
        query_op: IO_URING_QUERY_OPCODES,
        size: size_of::<IoUringQueryOpcode>() as u32,
        ..Default::default()
    };
    // SAFETY: The sole header names initialized writable stack data with no next link.
    unsafe { register_query(target, &mut header) }?;
    if header.result < 0 {
        return Err(UringError::syscalls("io_uring_query", header.result));
    }
    if header.size < size_of::<IoUringQueryOpcode>() as u32 {
        return Err(UringError::UnsupportedCapability(
            "truncated opcode inventory",
        ));
    }
    Ok(data)
}

/// Per-ring feature bits and submission probe, plus optional kernel-wide inventory.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    features: u32,
    opcodes: OpcodeProbe,
    inventory: Option<IoUringQueryOpcode>,
}
impl Capabilities {
    /// Discovers submission support and queries inventory when the kernel implements it.
    /// # Errors
    /// Propagates probe errors and query errors other than unsupported query interfaces.
    /// # Panics
    /// Does not panic.
    #[cold_sink]
    pub fn discover(target: RegisterTarget, features: u32) -> Result<Self> {
        let opcodes = register_probe(target)?;
        let inventory = match query_opcode_inventory(target) {
            Ok(value) => Some(value),
            Err(UringError::Syscall {
                errno: libc::EINVAL | libc::EOPNOTSUPP | libc::ENOSYS,
                ..
            }) => None,
            Err(error) => return Err(error),
        };
        Ok(Self {
            features,
            opcodes,
            inventory,
        })
    }
    /// Returns negotiated per-ring feature bits supplied by setup.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn features(&self) -> u32 {
        self.features
    }
    /// Borrows the per-ring opcode probe.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn opcodes(&self) -> &OpcodeProbe {
        &self.opcodes
    }
    /// Reports membership in the kernel's registration inventory, when query is available.
    /// This is not a guarantee that a resource, privilege or configuration is supported.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn register_opcode_known(&self, opcode: u32) -> Option<bool> {
        match self.inventory {
            Some(info) => Some(opcode < info.nr_register_opcodes),
            None => None,
        }
    }
}
