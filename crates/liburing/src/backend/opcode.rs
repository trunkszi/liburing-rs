//! Native SQE value builders. Building retains no pointer or descriptor ownership.
use super::{
    RawSqe,
    sys::sqe::*,
    types::{DestinationSlot, Target},
};
fn base<T: Target>(opcode: u8, fd: T) -> RawSqe {
    let flags = if fd.fixed() { IOSQE_FIXED_FILE } else { 0 };
    RawSqe {
        opcode,
        flags,
        fd: fd.raw(),
        ..Default::default()
    }
}
macro_rules! operation {
    ($name:ident,$code:ident,($($arg:ident:$ty:ty),*),$body:expr) => {
        /// Native operation builder; operands must be retained until final completion.
        pub struct $name(RawSqe);
        impl $name {
            pub const CODE:u8=$code;
            /// Creates an initialized native SQE builder without dereferencing operands.
            /// # Errors
            /// Validation is deferred to the kernel.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub fn new($($arg:$ty),*)->Self {Self($body)}
            /// Returns the initialized native SQE value.
            /// # Errors
            /// Validation is deferred to the kernel.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub fn build(self)->RawSqe {self.0}
            /// Sets the operation offset or secondary address word.
            /// # Errors
            /// Validation is deferred to the kernel.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub fn offset(mut self,value:u64)->Self {self.0.off=value;self}
            /// Sets operation-specific flags, not the SQE flags word.
            /// # Errors
            /// Validation is deferred to the kernel.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub fn flags(mut self,value:i32)->Self {self.0.operation_flags=value as u32;self}
            /// Sets the buffer-selection group.
            /// # Errors
            /// Validation is deferred to the kernel.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub fn buf_group(mut self,group:u16)->Self {self.0.buf_index=group;self}
            /// Sets zero-copy send flags.
            /// # Errors
            /// Validation is deferred to the kernel.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub fn zc_flags(mut self,flags:u16)->Self {self.0.ioprio=flags;self}
            /// Selects a fixed zero-copy send buffer.
            /// # Errors
            /// Validation is deferred to the kernel.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub fn buf_index(mut self,index:Option<u16>)->Self {if let Some(index)=index {self.0.buf_index=index;self.0.ioprio|=4;}self}
            /// Enables multishot poll behavior.
            /// # Errors
            /// Validation is deferred to the kernel.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub fn multi(mut self,value:bool)->Self {self.0.len=u32::from(value);self}
            /// Selects direct-file output allocation.
            /// # Errors
            /// Validation is deferred to the kernel.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub fn file_index(mut self,index:Option<DestinationSlot>)->Self {if let Some(index)=index {self.0.set_file_index(index.0);}self}
        }
    }
}
operation!(Read,IORING_OP_READ,(fd:impl Target,addr:*mut u8,len:u32),{let mut sqe=base(IORING_OP_READ,fd);sqe.addr=addr as u64;sqe.len=len;sqe});
operation!(Write,IORING_OP_WRITE,(fd:impl Target,addr:*const u8,len:u32),{let mut sqe=base(IORING_OP_WRITE,fd);sqe.addr=addr as u64;sqe.len=len;sqe});
operation!(Readv,IORING_OP_READV,(fd:impl Target,addr:*const libc::iovec,len:u32),{let mut sqe=base(IORING_OP_READV,fd);sqe.addr=addr as u64;sqe.len=len;sqe});
operation!(Writev,IORING_OP_WRITEV,(fd:impl Target,addr:*const libc::iovec,len:u32),{let mut sqe=base(IORING_OP_WRITEV,fd);sqe.addr=addr as u64;sqe.len=len;sqe});
operation!(Send,IORING_OP_SEND,(fd:impl Target,addr:*const u8,len:u32),{let mut sqe=base(IORING_OP_SEND,fd);sqe.addr=addr as u64;sqe.len=len;sqe});
operation!(Recv,IORING_OP_RECV,(fd:impl Target,addr:*mut u8,len:u32),{let mut sqe=base(IORING_OP_RECV,fd);sqe.addr=addr as u64;sqe.len=len;sqe});
operation!(SendZc,IORING_OP_SEND_ZC,(fd:impl Target,addr:*const u8,len:u32),{let mut sqe=base(IORING_OP_SEND_ZC,fd);sqe.addr=addr as u64;sqe.len=len;sqe});
operation!(ReadFixed,IORING_OP_READ_FIXED,(fd:impl Target,addr:*mut u8,len:u32,index:u16),{let mut sqe=base(IORING_OP_READ_FIXED,fd);sqe.addr=addr as u64;sqe.len=len;sqe.buf_index=index;sqe});
operation!(WriteFixed,IORING_OP_WRITE_FIXED,(fd:impl Target,addr:*const u8,len:u32,index:u16),{let mut sqe=base(IORING_OP_WRITE_FIXED,fd);sqe.addr=addr as u64;sqe.len=len;sqe.buf_index=index;sqe});
operation!(ReadvFixed,IORING_OP_READV_FIXED,(fd:impl Target,addr:*const libc::iovec,len:u32,index:u16),{let mut sqe=base(IORING_OP_READV_FIXED,fd);sqe.addr=addr as u64;sqe.len=len;sqe.buf_index=index;sqe});
operation!(WritevFixed,IORING_OP_WRITEV_FIXED,(fd:impl Target,addr:*const libc::iovec,len:u32,index:u16),{let mut sqe=base(IORING_OP_WRITEV_FIXED,fd);sqe.addr=addr as u64;sqe.len=len;sqe.buf_index=index;sqe});
operation!(SendMsg,IORING_OP_SENDMSG,(fd:impl Target,addr:*const libc::msghdr),{let mut sqe=base(IORING_OP_SENDMSG,fd);sqe.addr=addr as u64;sqe.len=1;sqe});
operation!(RecvMsg,IORING_OP_RECVMSG,(fd:impl Target,addr:*mut libc::msghdr),{let mut sqe=base(IORING_OP_RECVMSG,fd);sqe.addr=addr as u64;sqe.len=1;sqe});
operation!(SendMsgZc,IORING_OP_SENDMSG_ZC,(fd:impl Target,addr:*const libc::msghdr),{let mut sqe=base(IORING_OP_SENDMSG_ZC,fd);sqe.addr=addr as u64;sqe.len=1;sqe});
operation!(
    Nop,
    IORING_OP_NOP,
    (),
    RawSqe {
        fd: -1,
        ..Default::default()
    }
);
operation!(RecvMulti,IORING_OP_RECV,(fd:impl Target,group:u16),{let mut sqe=base(IORING_OP_RECV,fd);sqe.buf_index=group;sqe.ioprio=2;sqe.flags|=IOSQE_BUFFER_SELECT;sqe});
operation!(Accept,IORING_OP_ACCEPT,(fd:impl Target,addr:*mut libc::sockaddr,len:*mut libc::socklen_t),{let mut sqe=base(IORING_OP_ACCEPT,fd);sqe.addr=addr as u64;sqe.off=len as u64;sqe});
operation!(Connect,IORING_OP_CONNECT,(fd:impl Target,addr:*const libc::sockaddr,len:libc::socklen_t),{let mut sqe=base(IORING_OP_CONNECT,fd);sqe.addr=addr as u64;sqe.off=u64::from(len);sqe});
operation!(Close,IORING_OP_CLOSE,(fd:impl Target),if fd.fixed(){let mut sqe=RawSqe{opcode:IORING_OP_CLOSE,..Default::default()};sqe.set_file_index((fd.raw() as u32).saturating_add(1));sqe}else{base(IORING_OP_CLOSE,fd)});
operation!(OpenAt,IORING_OP_OPENAT,(fd:impl Target,path:*const libc::c_char),{let mut sqe=base(IORING_OP_OPENAT,fd);sqe.addr=path as u64;sqe});
operation!(Fsync,IORING_OP_FSYNC,(fd:impl Target),base(IORING_OP_FSYNC,fd));
operation!(PollAdd,IORING_OP_POLL_ADD,(fd:impl Target,events:u32),{let mut sqe=base(IORING_OP_POLL_ADD,fd);sqe.operation_flags=events;sqe});
operation!(AsyncCancel,IORING_OP_ASYNC_CANCEL,(id:u64),RawSqe{opcode:IORING_OP_ASYNC_CANCEL,fd:-1,addr:id,..Default::default()});
operation!(PollRemove,IORING_OP_POLL_REMOVE,(id:u64),RawSqe{opcode:IORING_OP_POLL_REMOVE,fd:-1,addr:id,..Default::default()});
operation!(MsgRingData,IORING_OP_MSG_RING,(fd:impl Target,len:u32,data:u64),{let mut sqe=base(IORING_OP_MSG_RING,fd);sqe.len=len;sqe.off=data;sqe});
operation!(Timeout,IORING_OP_TIMEOUT,(ts:*const super::types::Timespec),RawSqe{opcode:IORING_OP_TIMEOUT,fd:-1,addr:ts as u64,len:1,..Default::default()});
// Opcode markers expose admission constants; operand preparation lives in ops.
macro_rules! marker {
    ($name:ident,$code:ident) => {
        /// Native opcode admission marker; prepare operands through the ops modules.
        pub enum $name {}
        impl $name {
            pub const CODE: u8 = $code;
        }
    };
}
marker!(UringCmd16, IORING_OP_URING_CMD);
marker!(FutexWait, IORING_OP_FUTEX_WAIT);
marker!(FutexWake, IORING_OP_FUTEX_WAKE);
marker!(FutexWaitV, IORING_OP_FUTEX_WAITV);
impl Default for Nop {
    fn default() -> Self {
        Self::new()
    }
}
