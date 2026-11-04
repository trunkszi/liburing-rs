//! Native SQE byte images and kernel execution contracts.
use liburing::{backend::RawSqe, ops};

fn image(sqe: RawSqe) -> [u8; 64] {
    // SAFETY: RawSqe's proven padding-free integer layout initializes all 64 bytes.
    unsafe { core::mem::transmute(sqe) }
}

#[test]
fn pipe_image_keeps_identity() {
    // SAFETY: Every byte pattern is valid in the padding-free integer SQE record.
    let mut sqe: RawSqe = unsafe { core::mem::transmute([0xa5u8; 64]) };
    let mut fds = [-1i32; 2];
    // SAFETY: SQE is exclusive initialized storage; this encoding is not submitted.
    unsafe { ops::storage::prep_pipe(&mut sqe, fds.as_mut_ptr(), libc::O_CLOEXEC) };
    let mut expected = [0u8; 64];
    expected[0] = 62;
    expected[1] = 0xa5;
    expected[16..24].copy_from_slice(&(fds.as_mut_ptr() as u64).to_le_bytes());
    expected[28..32].copy_from_slice(&(libc::O_CLOEXEC as u32).to_le_bytes());
    expected[32..40].fill(0xa5);
    expected[42..44].fill(0xa5);
    assert_eq!(image(sqe), expected);
}

#[test]
fn recvmsg_parser_bounds() {
    use liburing::ops::net::parse_recvmsg;
    let mut bytes = [0_u8; 48];
    bytes[0..4].copy_from_slice(&3_u32.to_ne_bytes());
    bytes[4..8].copy_from_slice(&5_u32.to_ne_bytes());
    bytes[8..12].copy_from_slice(&40_u32.to_ne_bytes());
    bytes[12..16].copy_from_slice(&(libc::MSG_TRUNC as u32).to_ne_bytes());
    bytes[16..19].copy_from_slice(b"abc");
    bytes[24..29].copy_from_slice(b"cmsg!");
    bytes[32..48].fill(7);
    let output = parse_recvmsg(&bytes, 8, 8).unwrap();
    assert_eq!(output.name, b"abc");
    assert_eq!(output.control, b"cmsg!");
    assert_eq!(output.payload, &[7; 16]);
    assert_eq!(output.flags, libc::MSG_TRUNC as u32);
    assert!(parse_recvmsg(&bytes[..15], 0, 0).is_none());
    assert!(parse_recvmsg(&bytes, usize::MAX, 1).is_none());
    assert!(parse_recvmsg(&bytes[..31], 8, 8).is_none());
    bytes[0..4].copy_from_slice(&20_u32.to_ne_bytes());
    assert_eq!(parse_recvmsg(&bytes, 8, 8).unwrap().name.len(), 8);
}

// Byte offsets and opcode numbers follow Linux's SQE UAPI, independently of builders.
#[test]
fn wire_image_covers_opcodes() {
    use liburing::{
        BufferGroupId, BufferId, OperationId, UringFileSlot,
        ops::{fs as f, net as n, poll_time as p, storage as s},
    };
    let b = 0x1000_usize as *mut u8;
    let v = 0x2000_usize as *const libc::iovec;
    let ts = 0x3000_usize as *const ops::KernelTimespec;
    let path = b.cast::<libc::c_char>();
    let mut seen = [false; 65];
    macro_rules! check {
        ($op:literal, $prep:path, ($($arg:expr),*), {$($field:ident = $value:expr),* $(,)?}) => {{
            // SAFETY: Every bit pattern is valid for the integer-only wire record.
            let mut actual: RawSqe = unsafe { core::mem::transmute([0xa5_u8; 64]) };
            actual.flags = 0x14;
            actual.user_data = 0x1234_5678_9abc_def0;
            actual.personality = 0x3456;
            let mut expected = RawSqe { opcode: $op, fd: -1, flags: actual.flags,
                user_data: actual.user_data, personality: actual.personality, ..RawSqe::default() };
            $(expected.$field = $value;)*
            // SAFETY: SQE storage is initialized and exclusive. Operand addresses are only encoded;
            // none of these test entries is submitted or dereferenced by the encoders.
            unsafe { $prep(&mut actual, $($arg),*) };
            assert_eq!(image(actual), image(expected), "opcode {}: {}", $op, stringify!($prep));
            seen[$op] = true;
        }};
    }
    check!(0, p::prep_nop, (), { fd = -1 });
    check!(1, s::prep_readv, (7, v, 3, 99), {fd=7, addr=0x2000, len=3, off=99});
    check!(2, s::prep_writev, (7, v, 3, 99), {fd=7, addr=0x2000, len=3, off=99});
    check!(3, s::prep_fsync, (7, 1), {fd=7, operation_flags=1});
    check!(4, s::prep_read_fixed, (7, b, 23, 99, BufferId(9)), {fd=7,addr=0x1000,len=23,off=99,buf_index=9});
    check!(5, s::prep_write_fixed, (7, b, 23, 99, BufferId(9)), {fd=7,addr=0x1000,len=23,off=99,buf_index=9});
    check!(6, p::prep_poll_add, (7, 0x2019), {fd=7, operation_flags=0x2019});
    check!(7, p::prep_poll_remove, (OperationId::from_raw(123)), {
        addr = 123
    });
    check!(8, s::prep_sync_file_range, (7, 23, 99, 3), {fd=7,len=23,off=99,operation_flags=3});
    check!(9, n::prep_sendmsg, (7, b.cast(), 4), {fd=7,addr=0x1000,len=1,operation_flags=4});
    check!(10, n::prep_recvmsg, (7, b.cast(), 4), {fd=7,addr=0x1000,len=1,operation_flags=4});
    check!(11, p::prep_timeout, (ts, 3, 4), {addr=0x3000,len=1,off=3,operation_flags=4});
    check!(12, p::prep_timeout_remove, (123, 4), {addr=123,operation_flags=4});
    check!(13, n::prep_accept, (7, b.cast(), v.cast_mut().cast(), 4), {fd=7,addr=0x1000,off=0x2000,operation_flags=4});
    check!(14, p::prep_cancel_user_data, (123, 4), {addr=123,operation_flags=4});
    check!(15, p::prep_link_timeout, (ts, 4), {addr=0x3000,len=1,operation_flags=4});
    check!(16, n::prep_connect, (7, b.cast(), 16), {fd=7,addr=0x1000,off=16});
    check!(17, s::prep_fallocate, (7, 3, 99, 4096), {fd=7,len=3,off=99,addr=4096});
    check!(18, f::prep_openat, (-100, path, 4, 0o600), {fd=-100,addr=0x1000,len=0o600,operation_flags=4});
    check!(19, f::prep_close, (7), { fd = 7 });
    check!(20, f::prep_files_update, (b.cast(), 3, 9), {addr=0x1000,len=3,off=9});
    check!(21, f::prep_statx, (-100, path, 4, 0x7ff, v.cast_mut().cast()), {fd=-100,addr=0x1000,off=0x2000,len=0x7ff,operation_flags=4});
    check!(22, s::prep_read, (7, b, 23, 99), {fd=7,addr=0x1000,len=23,off=99});
    check!(23, s::prep_write, (7, b, 23, 99), {fd=7,addr=0x1000,len=23,off=99});
    check!(24, s::prep_fadvise, (7, 99, 23, 4), {fd=7,off=99,len=23,operation_flags=4});
    check!(25, s::prep_madvise, (b.cast(), 4096, 4), {addr=0x1000,len=4096,operation_flags=4});
    check!(26, n::prep_send, (7, b, 23, 4), {fd=7,addr=0x1000,len=23,operation_flags=4});
    check!(27, n::prep_recv, (7, b, 23, 4), {fd=7,addr=0x1000,len=23,operation_flags=4});
    check!(28, f::prep_openat2, (-100, path, v.cast()), {fd=-100,addr=0x1000,off=0x2000,len=24});
    check!(29, p::prep_epoll_ctl, (7, 8, 3, b.cast()), {fd=7,off=8,len=3,addr=0x1000});
    check!(30, s::prep_splice, (8, -1, 7, 99, 23, 4), {fd=7,splice_fd_in=8,addr=u64::MAX,off=99,len=23,operation_flags=4});
    check!(31, n::prep_provide_buffers, (b, 4096, 3, BufferGroupId(9), 10), {fd=3,addr=0x1000,len=4096,buf_index=9,off=10});
    check!(32, n::prep_remove_buffers, (3, BufferGroupId(9)), {fd=3,buf_index=9});
    check!(33, s::prep_tee, (8, 7, 23, 4), {fd=7,splice_fd_in=8,len=23,operation_flags=4});
    check!(34, n::prep_shutdown, (7, 2), {fd=7,len=2});
    check!(35, f::prep_renameat, (7, path, 8, v.cast(), 4), {fd=7,addr=0x1000,len=8,off=0x2000,operation_flags=4});
    check!(36, f::prep_unlinkat, (7, path, 4), {fd=7,addr=0x1000,operation_flags=4});
    check!(37, f::prep_mkdirat, (7, path, 0o700), {fd=7,addr=0x1000,len=0o700});
    check!(38, f::prep_symlinkat, (path, 7, v.cast()), {fd=7,addr=0x1000,off=0x2000});
    check!(39, f::prep_linkat, (7, path, 8, v.cast(), 4), {fd=7,addr=0x1000,len=8,off=0x2000,operation_flags=4});
    check!(40, ops::prep_msg_ring, (7, 23, 99, 4), {fd=7,len=23,off=99,operation_flags=4});
    check!(41, f::prep_fsetxattr, (7, path, v.cast(), 23, 4), {fd=7,addr=0x1000,off=0x2000,len=23,operation_flags=4});
    check!(42, f::prep_setxattr, (ts.cast(), path, v.cast(), 23, 4), {fd=0,addr=0x1000,off=0x2000,addr3=0x3000,len=23,operation_flags=4});
    check!(43, f::prep_fgetxattr, (7, path, v.cast_mut().cast(), 23), {fd=7,addr=0x1000,off=0x2000,len=23});
    check!(44, f::prep_getxattr, (ts.cast(), path, v.cast_mut().cast(), 23), {fd=0,addr=0x1000,off=0x2000,addr3=0x3000,len=23});
    check!(45, n::prep_socket, (2, 1, 6, 4), {fd=2,off=1,len=6,operation_flags=4});
    check!(46, ops::prep_uring_cmd, (5, 7), {fd=7,off=5});
    check!(47, n::prep_send_zc, (7, b, 23, 4, 8), {fd=7,addr=0x1000,len=23,operation_flags=4,ioprio=8});
    check!(48, n::prep_sendmsg_zc, (7, b.cast(), 4), {fd=7,addr=0x1000,len=1,operation_flags=4});
    check!(49, s::prep_read_multishot, (7, 23, 99, BufferGroupId(9)), {fd=7,len=23,off=99,buf_index=9,flags=0x34});
    check!(50, ops::prep_waitid, (1, 42, b.cast(), 4, 8), {fd=42,len=1,off=0x1000,splice_fd_in=4,operation_flags=8});
    check!(51, ops::prep_futex_wait, (b.cast(), 3, 7, 2), {fd=2,addr=0x1000,off=3,addr3=7});
    check!(52, ops::prep_futex_wake, (b.cast(), 3, 7, 2), {fd=2,addr=0x1000,off=3,addr3=7});
    check!(53, ops::prep_futex_waitv, (b.cast(), 3), {fd=0,addr=0x1000,len=3});
    check!(54, f::prep_fixed_fd_install, (UringFileSlot(7), 1), {fd=7,flags=0x15,operation_flags=1});
    check!(55, f::prep_ftruncate, (7, 99), {fd=7,off=99});
    check!(56, n::prep_bind, (7, b.cast(), 16), {fd=7,addr=0x1000,off=16});
    check!(57, n::prep_listen, (7, 16), {fd=7,len=16});
    check!(58, n::prep_recv_zc, (7, 4096, 9, 0), {fd=7,len=4096,splice_fd_in=9,ioprio=2});
    check!(59, p::prep_epoll_wait, (7, b.cast(), 3, 4), {fd=7,addr=0x1000,len=3,operation_flags=4});
    check!(60, s::prep_readv_fixed, (7, v, 3, 99, BufferId(9)), {fd=7,addr=0x2000,len=3,off=99,buf_index=9});
    check!(61, s::prep_writev_fixed, (7, v, 3, 99, BufferId(9)), {fd=7,addr=0x2000,len=3,off=99,buf_index=9});
    check!(62, s::prep_pipe, (b.cast(), 4), {fd=0,addr=0x1000,operation_flags=4});
    for (op, command) in [(63, None), (64, Some(5))] {
        use liburing::backend::sys::sqe::RawSqe128;
        let mut actual = RawSqe128 {
            base: RawSqe {
                flags: 0x14,
                user_data: 123,
                personality: 7,
                ..RawSqe::default()
            },
            cmd_ext: [0xa5; 64],
        };
        // SAFETY: The full 128-byte storage is initialized and exclusive; never submitted.
        unsafe {
            if let Some(cmd) = command {
                ops::prep_uring_cmd128(&mut actual, cmd, 7);
            } else {
                ops::prep_nop128(&mut actual);
            }
        }
        let expected = RawSqe {
            opcode: op,
            fd: if command.is_some() { 7 } else { -1 },
            off: command.unwrap_or(0) as u64,
            flags: 0x14,
            user_data: 123,
            personality: 7,
            ..RawSqe::default()
        };
        assert_eq!(image(actual.base), image(expected));
        assert_eq!(actual.cmd_ext, [0; 64]);
        seen[op as usize] = true;
    }
    assert!(seen.into_iter().all(|covered| covered));
}

#[test]
fn union_overlays_keep_identity() {
    use liburing::{
        BufferGroupId, OperationId, UringFileSlot,
        ops::{fs as f, net as n, poll_time as p, storage as s},
    };
    let b = 0x1000_usize as *mut u8;
    macro_rules! variant {
        ($prep:path, ($($arg:expr),*), $op:literal, {$($field:ident = $value:expr),*}) => {{
            let mut actual = RawSqe {user_data:123, flags:0x10,personality:9,..RawSqe::default()};
            let mut expected = RawSqe {opcode:$op,fd:-1,user_data:123,flags:0x10,personality:9,..RawSqe::default()};
            $(expected.$field=$value;)*
            // SAFETY: Initialized exclusive SQE; pointer operands are encoded without submission.
            unsafe { $prep(&mut actual, $($arg),*) };
            assert_eq!(image(actual), image(expected), "{}", stringify!($prep));
        }};
    }
    variant!(f::prep_openat_direct, (7,b.cast(),4,0,9),18,{fd=7,addr=0x1000,operation_flags=4,splice_fd_in=10});
    variant!(f::prep_openat2_direct, (7,b.cast(),b.cast(),u32::MAX),28,{fd=7,addr=0x1000,off=0x1000,len=24,splice_fd_in=-1});
    variant!(f::prep_close_direct,(UringFileSlot(9)),19,{fd=0,splice_fd_in=10});
    variant!(s::prep_pipe_direct,(b.cast(),4,u32::MAX),62,{fd=0,addr=0x1000,operation_flags=4,splice_fd_in=-1});
    variant!(n::prep_socket_direct,(2,1,6,0,9),45,{fd=2,off=1,len=6,splice_fd_in=10});
    variant!(n::prep_accept_direct,(7,b.cast(),b.cast(),4,9),13,{fd=7,addr=0x1000,off=0x1000,operation_flags=4,splice_fd_in=10});
    variant!(n::prep_multishot_accept_direct,(7,4),13,{fd=7,ioprio=1,operation_flags=4,splice_fd_in=-1});
    variant!(n::prep_recv_multishot_buffer_select,(7,BufferGroupId(9),4),27,{fd=7,flags=0x30,ioprio=2,buf_index=9,operation_flags=4});
    variant!(n::prep_recvmsg_multishot,(7,b.cast(),4,BufferGroupId(9)),10,{fd=7,addr=0x1000,len=1,flags=0x30,ioprio=2,buf_index=9,operation_flags=4});
    variant!(n::prep_send_bundle,(7,BufferGroupId(9),23,4),26,{fd=7,len=23,flags=0x30,ioprio=16,buf_index=9,operation_flags=4});
    variant!(n::prep_recv_bundle,(7,BufferGroupId(9),23,4),27,{fd=7,len=23,flags=0x30,ioprio=16,buf_index=9,operation_flags=4});
    variant!(n::prep_send_vectored,(7,b.cast(),3,4),26,{fd=7,addr=0x1000,len=3,operation_flags=4,ioprio=32});
    variant!(n::prep_send_zc_vectored,(7,b.cast(),3,4,8),47,{fd=7,addr=0x1000,len=3,operation_flags=4,ioprio=40});
    variant!(n::prep_send_zc_report_usage,(7,b,23,4),47,{fd=7,addr=0x1000,len=23,operation_flags=4,ioprio=8});
    variant!(n::prep_send_zc_fixed,(7,b,23,4,8,liburing::BufferId(9)),47,{fd=7,addr=0x1000,len=23,operation_flags=4,ioprio=12,buf_index=9});
    variant!(p::prep_poll_multishot,(7,4),6,{fd=7,len=1,operation_flags=4});
    variant!(p::prep_poll_update,(12,13,4,6),7,{addr=12,off=13,len=6,operation_flags=4});
    variant!(p::prep_timeout_update,(b.cast(),12,4),12,{addr=12,off=0x1000,operation_flags=6});
    variant!(p::prep_cancel,(OperationId::from_raw(12),4),14,{addr=12,operation_flags=4});
    variant!(p::prep_cancel_fd,(7,4),14,{fd=7,operation_flags=6});
    variant!(p::prep_cancel_fixed_fd,(UringFileSlot(7),4),14,{fd=7,operation_flags=14});
    variant!(p::prep_cancel_any, (8), 14, { operation_flags = 12 });
    variant!(p::prep_cancel_op,(22,4),14,{len=22,operation_flags=36});
    variant!(ops::prep_msg_ring_fd,(7,9,u32::MAX,12,4),40,{fd=7,addr=1,addr3=9,off=12,operation_flags=4,splice_fd_in=-1});
    variant!(ops::prep_cmd_siocinq, (7), 46, { fd = 7 });
    variant!(ops::prep_cmd_siocoutq,(7),46,{fd=7,off=1});
    variant!(ops::prep_cmd_getsockopt,(7,1,2,b.cast(),23),46,{fd=7,off=2,addr=0x0000_0002_0000_0001,addr3=0x1000,splice_fd_in=23});
    variant!(ops::prep_cmd_setsockopt,(7,1,2,b.cast(),23),46,{fd=7,off=3,addr=0x0000_0002_0000_0001,addr3=0x1000,splice_fd_in=23});
    variant!(ops::prep_cmd_tx_timestamp,(7),46,{fd=7,off=4});
    variant!(ops::prep_cmd_getsockname,(7,b.cast(),b.cast(),true),46,{fd=7,off=5,addr=0x1000,addr3=0x1000,splice_fd_in=1});
    let mut sqe = RawSqe {
        opcode: 22,
        fd: 7,
        addr: 0x2000,
        len: 23,
        user_data: 123,
        personality: 9,
        ..RawSqe::default()
    };
    let expected = RawSqe {
        addr3: 0x1000,
        pad2: 1,
        ..sqe
    };
    // SAFETY: Exclusive SQE; the test only encodes the protection-information address.
    unsafe { s::prep_rw_attr_pi(&mut sqe, b.cast()) };
    assert_eq!(image(sqe), image(expected));
}

// SAFETY contract: callers retain all SQE operands until this function receives its final CQE.
unsafe fn execute(ring: &mut liburing::backend::IoUring, sqe: RawSqe) -> i32 {
    // SAFETY: The ring owns free SQ storage; caller retains operands until the completion below.
    unsafe { ring.submission().push(&sqe).unwrap() };
    ring.submit_and_wait(1).unwrap();
    let cqe = ring.completion().next().expect("one completion");
    assert_eq!(
        cqe.flags() & 2,
        0,
        "representative operations must be single-shot"
    );
    cqe.result()
}

#[test]
fn live_nop_pipe_socket() {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut ring = liburing::backend::IoUring::new(8).unwrap();
    let mut sqe = RawSqe::default();
    // SAFETY: Operands live until each synchronous execute call observes its final CQE.
    unsafe {
        ops::prep_nop(&mut sqe);
        assert_eq!(execute(&mut ring, sqe), 0);
        let mut pipes = [-1; 2];
        ops::storage::prep_pipe(&mut sqe, pipes.as_mut_ptr(), libc::O_CLOEXEC);
        assert_eq!(execute(&mut ring, sqe), 0);
        let _read = OwnedFd::from_raw_fd(pipes[0]);
        let _write = OwnedFd::from_raw_fd(pipes[1]);
        ops::net::prep_socket(
            &mut sqe,
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            0,
        );
        let fd = execute(&mut ring, sqe);
        assert!(fd >= 0, "socket CQE: {fd}");
        let _socket = OwnedFd::from_raw_fd(fd);
    }
}

#[test]
fn live_statx_timeout_poll() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let mut ring = liburing::backend::IoUring::new(8).unwrap();
    let mut sqe = RawSqe::default();
    // SAFETY: Operands live until each synchronous execute call observes its final CQE.
    unsafe {
        let mut stat = core::mem::zeroed::<libc::statx>();
        ops::fs::prep_statx(
            &mut sqe,
            libc::AT_FDCWD,
            c"/proc/self/exe".as_ptr(),
            0,
            libc::STATX_BASIC_STATS,
            &mut stat,
        );
        assert_eq!(execute(&mut ring, sqe), 0);
        assert!(stat.stx_size > 0);
        let ts = ops::KernelTimespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        ops::prep_timeout(&mut sqe, &ts, 0, 0);
        assert_eq!(execute(&mut ring, sqe), -libc::ETIME);
        let mut pipes = [-1; 2];
        ops::storage::prep_pipe(&mut sqe, pipes.as_mut_ptr(), libc::O_CLOEXEC);
        assert_eq!(execute(&mut ring, sqe), 0);
        let read = OwnedFd::from_raw_fd(pipes[0]);
        let write = OwnedFd::from_raw_fd(pipes[1]);
        assert_eq!(libc::write(write.as_raw_fd(), b"x".as_ptr().cast(), 1), 1);
        ops::net::prep_poll_add(&mut sqe, read.as_raw_fd(), libc::POLLIN as u32);
        assert_ne!(execute(&mut ring, sqe) & libc::POLLIN as i32, 0);
    }
}

#[test]
fn live_msg_ring_siocinq() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let mut ring = liburing::backend::IoUring::new(8).unwrap();
    let mut target = liburing::backend::IoUring::new(8).unwrap();
    let mut sqe = RawSqe::default();
    // SAFETY: Operands live until each synchronous execute call observes its final CQE.
    unsafe {
        ops::prep_msg_ring(&mut sqe, target.as_raw_fd(), 17, 0x55, 0);
        assert_eq!(execute(&mut ring, sqe), 0);
        target.submit_and_wait(1).unwrap();
        let cqe = target.completion().next().unwrap();
        assert_eq!(cqe.result(), 17);
        assert_eq!(cqe.user_data(), 0x55);
        let listener = OwnedFd::from_raw_fd(libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        ));
        let mut addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        assert_eq!(
            libc::bind(
                listener.as_raw_fd(),
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            0
        );
        assert_eq!(libc::listen(listener.as_raw_fd(), 1), 0);
        let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        assert_eq!(
            libc::getsockname(listener.as_raw_fd(), (&raw mut addr).cast(), &raw mut len),
            0
        );
        let client = OwnedFd::from_raw_fd(libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        ));
        assert_eq!(
            libc::connect(
                client.as_raw_fd(),
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            0
        );
        let accepted = OwnedFd::from_raw_fd(libc::accept(
            listener.as_raw_fd(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        ));
        assert_eq!(
            libc::send(client.as_raw_fd(), b"ping".as_ptr().cast(), 4, 0),
            4
        );
        ops::prep_cmd_siocinq(&mut sqe, accepted.as_raw_fd());
        assert_eq!(execute(&mut ring, sqe), 4);
        let mut socket_type = -1_i32;
        ops::prep_cmd_getsockopt(
            &mut sqe,
            accepted.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut socket_type).cast(),
            size_of::<i32>() as u32,
        );
        assert_eq!(execute(&mut ring, sqe), size_of::<i32>() as i32);
        assert_eq!(socket_type, libc::SOCK_STREAM);

        let mut peer = core::mem::zeroed::<libc::sockaddr_in>();
        let mut peer_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        ops::prep_cmd_getsockname(
            &mut sqe,
            client.as_raw_fd(),
            (&raw mut peer).cast(),
            &raw mut peer_len,
            true,
        );
        match execute(&mut ring, sqe) {
            0 => {
                assert_eq!(peer_len as usize, size_of::<libc::sockaddr_in>());
                assert_eq!(peer.sin_family, libc::AF_INET as libc::sa_family_t);
                assert_ne!(peer.sin_port, 0);
                assert_eq!(peer.sin_port, addr.sin_port);
                assert_eq!(peer.sin_addr.s_addr, addr.sin_addr.s_addr);
            }
            rc if rc == -libc::EOPNOTSUPP || rc == -libc::EINVAL => {}
            rc => panic!("unexpected getsockname CQE: {rc}"),
        }
    }
}
