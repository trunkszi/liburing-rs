//! Exact SQE storage; extended layout support does not imply kernel availability.
use uarch::prelude::*;

/// Linux SQE union storage. All pointer operands are integer addresses, not owners.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RawSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub operation_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub pad2: u64,
}
assert_layout!(RawSqe, size = 64, align = 8, fields = {
    opcode: 0, flags: 1, ioprio: 2, fd: 4, off: 8,
    addr: 16, len: 24, operation_flags: 28, user_data: 32,
    buf_index: 40, personality: 42, splice_fd_in: 44,
    addr3: 48, pad2: 56,
});
// SAFETY: Integer fields occupy every byte; the offset and size assertions prove no padding.
unsafe impl NoPadding for RawSqe {}

/// Linux SQE128 storage, including the additional 64 command bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSqe128 {
    pub base: RawSqe,
    pub cmd_ext: [u8; 64],
}
impl Default for RawSqe128 {
    fn default() -> Self {
        Self {
            base: RawSqe::default(),
            cmd_ext: [0; 64],
        }
    }
}
assert_layout!(RawSqe128, size = 128, align = 8, fields = { base: 0, cmd_ext: 64 });
// SAFETY: Padding-free RawSqe is immediately followed by 64 initialized bytes with no tail padding.
unsafe impl NoPadding for RawSqe128 {}

/// Private-storage geometry; this alignment must not replace the wire type's alignment.
#[cache_line]
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheAlignedSqe {
    pub sqe: RawSqe,
}
assert_layout!(CacheAlignedSqe, size = 64, align = 64, fields = { sqe: 0 });

/// Two cache lines of private staging storage.
#[cache_line(lines = 2)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheAlignedSqe128 {
    pub sqe: RawSqe128,
}
assert_layout!(CacheAlignedSqe128, size = 128, align = 64, fields = { sqe: 0 });

impl RawSqe {
    /// Reads the `off_or_addr2` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn off_or_addr2(&self) -> u64 {
        self.off
    }
    /// Writes the `off_or_addr2` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_off_or_addr2(&mut self, value: u64) {
        self.off = value;
    }
    /// Reads the `addr_or_splice_off_in` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn addr_or_splice_off_in(&self) -> u64 {
        self.addr
    }
    /// Writes the `addr_or_splice_off_in` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_addr_or_splice_off_in(&mut self, value: u64) {
        self.addr = value;
    }
    /// Reads the `op_flags` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn op_flags(&self) -> u32 {
        self.operation_flags
    }
    /// Writes the `op_flags` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_op_flags(&mut self, value: u32) {
        self.operation_flags = value;
    }
    /// Reads the `buf_index_or_group` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn buf_index_or_group(&self) -> u16 {
        self.buf_index
    }
    /// Writes the `buf_index_or_group` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_buf_index_or_group(&mut self, value: u16) {
        self.buf_index = value;
    }
    /// Reads the `splice_fd_in_or_file_index` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn splice_fd_in_or_file_index(&self) -> u32 {
        self.splice_fd_in as u32
    }
    /// Writes the `splice_fd_in_or_file_index` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_splice_fd_in_or_file_index(&mut self, value: u32) {
        self.splice_fd_in = value as i32;
    }
    /// Reads the `file_index` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn file_index(&self) -> u32 {
        self.splice_fd_in as u32
    }
    /// Writes the `file_index` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_file_index(&mut self, value: u32) {
        self.splice_fd_in = value as i32;
    }
    /// Reads the `addr3_or_cmd` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn addr3_or_cmd(&self) -> [u64; 2] {
        [self.addr3, self.pad2]
    }
    /// Writes the `addr3_or_cmd` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_addr3_or_cmd(&mut self, value: [u64; 2]) {
        self.addr3 = value[0];
        self.pad2 = value[1];
    }
    /// Reads the `cmd_op` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn cmd_op(&self) -> u32 {
        self.off as u32
    }
    /// Writes `cmd_op` while preserving the neighboring union bytes.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_cmd_op(&mut self, value: u32) {
        self.off = (self.off & 0xffff_ffff_0000_0000) | u64::from(value);
    }
    /// Reads the `level` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn level(&self) -> u32 {
        self.addr as u32
    }
    /// Writes `level` while preserving the neighboring union bytes.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_level(&mut self, value: u32) {
        self.addr = (self.addr & 0xffff_ffff_0000_0000) | u64::from(value);
    }
    /// Reads the `optname` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn optname(&self) -> u32 {
        (self.addr >> 32) as u32
    }
    /// Writes `optname` while preserving the neighboring union bytes.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_optname(&mut self, value: u32) {
        self.addr = (self.addr & 0xffff_ffff) | (u64::from(value) << 32);
    }
    /// Reads the `addr_len` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn addr_len(&self) -> u16 {
        self.splice_fd_in as u16
    }
    /// Writes `addr_len` while preserving the neighboring union bytes.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_addr_len(&mut self, value: u16) {
        self.splice_fd_in = ((self.splice_fd_in as u32 & 0xffff_0000) | u32::from(value)) as i32;
    }
    /// Reads the `write_stream` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn write_stream(&self) -> u8 {
        self.splice_fd_in as u8
    }
    /// Writes `write_stream` while preserving the neighboring union bytes.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_write_stream(&mut self, value: u8) {
        self.splice_fd_in = ((self.splice_fd_in as u32 & 0xffff_ff00) | u32::from(value)) as i32;
    }
    /// Reads the `attr_ptr` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn attr_ptr(&self) -> u64 {
        self.addr3
    }
    /// Writes `attr_ptr` while preserving the neighboring union bytes.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_attr_ptr(&mut self, value: u64) {
        self.addr3 = value;
    }
    /// Reads the `attr_type_mask` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn attr_type_mask(&self) -> u64 {
        self.pad2
    }
    /// Writes `attr_type_mask` while preserving the neighboring union bytes.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_attr_type_mask(&mut self, value: u64) {
        self.pad2 = value;
    }
    /// Reads the `optval` union overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub const fn optval(&self) -> u64 {
        self.addr3
    }
    /// Writes `optval` while preserving the neighboring union bytes.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_optval(&mut self, value: u64) {
        self.addr3 = value;
    }
    /// Writes the socket option pair in little-endian UAPI order.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_level_optname(&mut self, level: u32, optname: u32) {
        self.addr = u64::from(level) | (u64::from(optname) << 32);
    }
    /// Writes both extended attribute fields.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn set_attr(&mut self, pointer: u64, mask: u64) {
        self.addr3 = pointer;
        self.pad2 = mask;
    }
}
impl RawSqe128 {
    /// Borrows the full 80-byte command overlay, including the base SQE's final 16 bytes.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn command(&self) -> &[u8; 80] {
        // SAFETY: repr(C) and offset proofs place 80 initialized integer bytes at offset 48.
        // The shared borrow covers the entire record and prevents mutable aliases.
        unsafe {
            &*core::ptr::from_ref(self)
                .cast::<u8>()
                .add(48)
                .cast::<[u8; 80]>()
        }
    }
    /// Exclusively borrows the full command overlay.
    /// # Errors
    /// Does not return errors.
    /// # Panics
    /// Does not panic.
    #[hot_inline]
    pub fn command_mut(&mut self) -> &mut [u8; 80] {
        // SAFETY: The exclusive record borrow owns all 80 bytes starting at offset 48.
        // All bit patterns remain valid in the underlying integer fields and byte array.
        unsafe {
            &mut *core::ptr::from_mut(self)
                .cast::<u8>()
                .add(48)
                .cast::<[u8; 80]>()
        }
    }
}

/// Protection-information attribute record.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringAttrPi {
    pub flags: u16,
    pub app_tag: u16,
    pub len: u32,
    pub addr: u64,
    pub seed: u64,
    pub rsvd: u64,
}
assert_layout!(IoUringAttrPi, size = 32, align = 8, fields = {
    flags: 0, app_tag: 2, len: 4, addr: 8, seed: 16, rsvd: 24,
});
pub const IORING_RW_ATTR_FLAG_PI: u32 = 1;
pub const IORING_FILE_INDEX_ALLOC: u32 = u32::MAX;
pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
pub const IOSQE_IO_DRAIN: u8 = 1 << 1;
pub const IOSQE_IO_LINK: u8 = 1 << 2;
pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
pub const IOSQE_ASYNC: u8 = 1 << 4;
pub const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

/// Frozen instruction inventory; presence is not a runtime capability proof.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Fsync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SyncFileRange = 8,
    Sendmsg = 9,
    Recvmsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    Openat = 18,
    Close = 19,
    FilesUpdate = 20,
    Statx = 21,
    Read = 22,
    Write = 23,
    Fadvise = 24,
    Madvise = 25,
    Send = 26,
    Recv = 27,
    Openat2 = 28,
    EpollCtl = 29,
    Splice = 30,
    ProvideBuffers = 31,
    RemoveBuffers = 32,
    Tee = 33,
    Shutdown = 34,
    Renameat = 35,
    Unlinkat = 36,
    Mkdirat = 37,
    Symlinkat = 38,
    Linkat = 39,
    MsgRing = 40,
    Fsetxattr = 41,
    Setxattr = 42,
    Fgetxattr = 43,
    Getxattr = 44,
    Socket = 45,
    UringCmd = 46,
    SendZc = 47,
    SendmsgZc = 48,
    ReadMultishot = 49,
    Waitid = 50,
    FutexWait = 51,
    FutexWake = 52,
    FutexWaitv = 53,
    FixedFdInstall = 54,
    Ftruncate = 55,
    Bind = 56,
    Listen = 57,
    RecvZc = 58,
    EpollWait = 59,
    ReadvFixed = 60,
    WritevFixed = 61,
    Pipe = 62,
    Nop128 = 63,
    UringCmd128 = 64,
}

pub const IORING_OP_NOP: u8 = 0;
pub const IORING_OP_READV: u8 = 1;
pub const IORING_OP_WRITEV: u8 = 2;
pub const IORING_OP_FSYNC: u8 = 3;
pub const IORING_OP_READ_FIXED: u8 = 4;
pub const IORING_OP_WRITE_FIXED: u8 = 5;
pub const IORING_OP_POLL_ADD: u8 = 6;
pub const IORING_OP_POLL_REMOVE: u8 = 7;
pub const IORING_OP_SYNC_FILE_RANGE: u8 = 8;
pub const IORING_OP_SENDMSG: u8 = 9;
pub const IORING_OP_RECVMSG: u8 = 10;
pub const IORING_OP_TIMEOUT: u8 = 11;
pub const IORING_OP_TIMEOUT_REMOVE: u8 = 12;
pub const IORING_OP_ACCEPT: u8 = 13;
pub const IORING_OP_ASYNC_CANCEL: u8 = 14;
pub const IORING_OP_LINK_TIMEOUT: u8 = 15;
pub const IORING_OP_CONNECT: u8 = 16;
pub const IORING_OP_FALLOCATE: u8 = 17;
pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_CLOSE: u8 = 19;
pub const IORING_OP_FILES_UPDATE: u8 = 20;
pub const IORING_OP_STATX: u8 = 21;
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_WRITE: u8 = 23;
pub const IORING_OP_FADVISE: u8 = 24;
pub const IORING_OP_MADVISE: u8 = 25;
pub const IORING_OP_SEND: u8 = 26;
pub const IORING_OP_RECV: u8 = 27;
pub const IORING_OP_OPENAT2: u8 = 28;
pub const IORING_OP_EPOLL_CTL: u8 = 29;
pub const IORING_OP_SPLICE: u8 = 30;
pub const IORING_OP_PROVIDE_BUFFERS: u8 = 31;
pub const IORING_OP_REMOVE_BUFFERS: u8 = 32;
pub const IORING_OP_TEE: u8 = 33;
pub const IORING_OP_SHUTDOWN: u8 = 34;
pub const IORING_OP_RENAMEAT: u8 = 35;
pub const IORING_OP_UNLINKAT: u8 = 36;
pub const IORING_OP_MKDIRAT: u8 = 37;
pub const IORING_OP_SYMLINKAT: u8 = 38;
pub const IORING_OP_LINKAT: u8 = 39;
pub const IORING_OP_MSG_RING: u8 = 40;
pub const IORING_OP_FSETXATTR: u8 = 41;
pub const IORING_OP_SETXATTR: u8 = 42;
pub const IORING_OP_FGETXATTR: u8 = 43;
pub const IORING_OP_GETXATTR: u8 = 44;
pub const IORING_OP_SOCKET: u8 = 45;
pub const IORING_OP_URING_CMD: u8 = 46;
pub const IORING_OP_SEND_ZC: u8 = 47;
pub const IORING_OP_SENDMSG_ZC: u8 = 48;
pub const IORING_OP_READ_MULTISHOT: u8 = 49;
pub const IORING_OP_WAITID: u8 = 50;
pub const IORING_OP_FUTEX_WAIT: u8 = 51;
pub const IORING_OP_FUTEX_WAKE: u8 = 52;
pub const IORING_OP_FUTEX_WAITV: u8 = 53;
pub const IORING_OP_FIXED_FD_INSTALL: u8 = 54;
pub const IORING_OP_FTRUNCATE: u8 = 55;
pub const IORING_OP_BIND: u8 = 56;
pub const IORING_OP_LISTEN: u8 = 57;
pub const IORING_OP_RECV_ZC: u8 = 58;
pub const IORING_OP_EPOLL_WAIT: u8 = 59;
pub const IORING_OP_READV_FIXED: u8 = 60;
pub const IORING_OP_WRITEV_FIXED: u8 = 61;
pub const IORING_OP_PIPE: u8 = 62;
pub const IORING_OP_NOP128: u8 = 63;
pub const IORING_OP_URING_CMD128: u8 = 64;
pub const IORING_OP_LAST: u8 = 65;

impl TryFrom<u8> for Opcode {
    type Error = u8;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value < IORING_OP_LAST {
            // SAFETY: Opcode has one discriminant for every value in 0..IORING_OP_LAST.
            Ok(unsafe { core::mem::transmute::<u8, Self>(value) })
        } else {
            Err(value)
        }
    }
}

/// Requests multishot receive completions in the SQE ioprio word.
pub const IORING_RECV_MULTISHOT: u16 = 1 << 1;
