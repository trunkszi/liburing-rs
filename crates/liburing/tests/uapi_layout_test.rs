//! Native UAPI contracts against the selected Linux header inventory.
use liburing::backend::sys::sqe::{RawSqe, RawSqe128};

#[test]
fn sqe_overlays_preserve_wire_bytes() {
    let mut sqe = RawSqe::default();
    sqe.set_cmd_op(0x1234_5678);
    sqe.set_level_optname(0x1122_3344, 0x5566_7788);
    sqe.set_addr_len(0xabcd);
    sqe.set_attr(0x1234, 0x5678);
    assert_eq!(sqe.off_or_addr2(), 0x1234_5678);
    assert_eq!(sqe.addr_or_splice_off_in(), 0x5566_7788_1122_3344);
    assert_eq!(sqe.splice_fd_in_or_file_index(), 0xabcd);
    assert_eq!(sqe.addr3_or_cmd(), [0x1234, 0x5678]);
    assert_eq!(size_of::<RawSqe128>(), 128);
}

#[test]
fn completion_words_preserve_signed_result() {
    use liburing::backend::sys::cqe::{CompletionWords, CqeWord, RawCqe};
    let raw = RawCqe {
        user_data: 17,
        res: i32::MIN,
        flags: 0xbeef_800b,
    };
    let words = CompletionWords::from(raw);
    assert_eq!(words.result(), i32::MIN);
    assert_eq!(words.flags(), 0xbeef_800b);
    assert_eq!(words.word.get(CqeWord::BID), 0xbeef);
    assert!(words.word.test(CqeWord::BIG));
    assert!(words.word.test(CqeWord::NOTIF));
    assert_eq!(RawCqe::from(words), raw);
}

#[test]
fn params_match_linux_header() {
    use liburing::backend::sys::params::*;
    assert_eq!(size_of::<IoUringParams>(), 120);
    assert_eq!(std::mem::offset_of!(IoUringRegWait, sigmask), 24);
    assert_eq!(IORING_SETUP_SQ_REWIND, 0x10_0000);
    assert_eq!(IORING_ENTER_EXT_ARG_REG, 0x40);
}

#[test]
fn registration_records_match_wire() {
    use liburing::backend::sys::register::*;
    assert_eq!(size_of::<IoUringBufReg>(), 40);
    assert_eq!(std::mem::offset_of!(IoUringBufReg, min_left), 16);
    assert_eq!(size_of::<IoUringSyncCancelReg>(), 64);
    assert_eq!(RegisterOpcode::try_from(37).unwrap() as u32, 37);
    assert!(RegisterOpcode::try_from(38).is_err());
}

#[test]
fn auxiliary_records_match_inventory() {
    use liburing::backend::sys::{futex::*, query_bpf::*, zcrx::*};
    assert_eq!(size_of::<FutexWaitv>(), 24);
    assert_eq!((FUTEX2_NUMA, FUTEX2_MPOL, FUTEX_NO_NODE), (4, 8, -1));
    assert_eq!(size_of::<IoUringZcrxIfqReg>(), 96);
    assert_eq!(size_of::<ZcrxCtrl>(), 72);
    assert_eq!(size_of::<IoUringQueryHdr>(), 40);
    assert_eq!(size_of::<IoUringBpfFilter>(), 64);
}

#[test]
fn baseline_rejects_old_or_invalid_release() {
    use liburing::backend::sys::validate_kernel_release;
    assert!(validate_kernel_release(b"6.15.99-vendor").is_err());
    assert!(validate_kernel_release(b"6.16.0-vendor").is_ok());
    assert!(validate_kernel_release(b"7.0.0").is_ok());
    for release in [b"unknown".as_slice(), b"6.", b"6.16bad", b"9999999999999.0"] {
        assert!(validate_kernel_release(release).is_err());
    }
}

#[test]
fn syscalls_preserve_errno_and_results() {
    use liburing::backend::sys::{self, futex::*};
    let mut value = 7u32;
    let waiters = [FutexWaitv {
        val: 6,
        uaddr: (&raw mut value) as u64,
        flags: FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
        __reserved: 0,
    }; 2];
    // SAFETY: Each synchronous call uses live aligned stack storage, nonmatching values or
    // zero counts so it cannot block. Invalid fd calls contain no dereferenced pointer.
    unsafe {
        assert_eq!(
            sys::sys_futex_wait(
                (&raw mut value).cast(),
                6,
                u32::MAX as _,
                FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
                std::ptr::null(),
                libc::CLOCK_MONOTONIC
            ),
            -libc::EAGAIN
        );
        assert_eq!(
            sys::sys_futex_wake(
                (&raw mut value).cast(),
                u32::MAX as _,
                0,
                FUTEX2_SIZE_U32 | FUTEX2_PRIVATE
            ),
            0
        );
        assert_eq!(
            sys::sys_futex_waitv(
                waiters.as_ptr(),
                1,
                0,
                std::ptr::null(),
                libc::CLOCK_MONOTONIC
            ),
            -libc::EAGAIN
        );
        assert_eq!(
            sys::sys_futex_requeue(waiters.as_ptr(), 0, 0, 0),
            -libc::EAGAIN
        );
        assert_eq!(
            sys::sys_io_uring_enter(-1, 0, 0, 0, std::ptr::null(), 0),
            -libc::EBADF
        );
        assert_eq!(
            sys::sys_io_uring_register(-2, 0, std::ptr::null_mut(), 0),
            -libc::EBADF
        );
    }
}

fn linux_header_source() -> String {
    let root = std::env::var_os("LIBURING_UAPI_INCLUDE_DIR")
        .map(std::path::PathBuf::from)
        .filter(|root| root.join("linux/io_uring.h").is_file());
    let pinned = [
        concat!(
            include_str!("fixtures/uapi_7_0/io_uring_part1.h"),
            include_str!("fixtures/uapi_7_0/io_uring_part2.h")
        ),
        include_str!("fixtures/uapi_7_0/futex.h"),
        include_str!("fixtures/uapi_7_0/query.h"),
        include_str!("fixtures/uapi_7_0/bpf_filter.h"),
    ];
    let mut source = String::from(
        "#include <stddef.h>\n#include <linux/stddef.h>\n#include <asm/unistd.h>\n#define __user\n",
    );
    for (name, fixture) in [
        "linux/io_uring.h",
        "linux/futex.h",
        "linux/io_uring/query.h",
        "linux/io_uring/bpf_filter.h",
    ]
    .into_iter()
    .zip(pinned)
    {
        let header = root.as_ref().map_or_else(
            || fixture.to_owned(),
            |root| {
                std::fs::read_to_string(root.join(name))
                    .expect("selected UAPI header must be readable")
            },
        );
        // compiler.h supplies kernel-only annotations, not UAPI layout. __user is erased above.
        source.push_str(&header.replace("#include <linux/compiler.h>", ""));
        source.push('\n');
    }
    source.push_str(
        "struct sqe128_fixture { struct io_uring_sqe base; unsigned char cmd_ext[64]; };\n",
    );
    source.push_str(
        "struct cqe32_fixture { struct io_uring_cqe base; unsigned long long big_cqe[2]; };\n",
    );
    source
}

fn compile_header_contract(source: String) {
    use std::io::Write as _;
    let mut child = std::process::Command::new("cc")
        .args(["-std=gnu11", "-Werror", "-fsyntax-only", "-x", "c", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("a C compiler is required for independent UAPI verification");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

macro_rules! c_layout {
    ($source:ident, $rust:ty, $c:literal, { $($rf:ident => $cf:literal),* $(,)? }) => {{
        use std::fmt::Write as _;
        writeln!($source, "_Static_assert(sizeof(struct {}) == {}, \"size {}\");", $c, size_of::<$rust>(), $c).unwrap();
        writeln!($source, "_Static_assert(_Alignof(struct {}) == {}, \"align {}\");", $c, align_of::<$rust>(), $c).unwrap();
        $(writeln!($source, "_Static_assert(offsetof(struct {}, {}) == {}, \"offset {}.{}\");", $c, $cf, std::mem::offset_of!($rust, $rf), $c, $cf).unwrap();)*
    }};
}

#[test]
fn records_match_independent_c_layout() {
    use liburing::backend::sys::{
        cqe::*, futex::*, params::*, query_bpf::*, register::*, sqe::*, zcrx::*,
    };
    let mut source = linux_header_source();
    c_layout!(source, FutexWaitv, "futex_waitv", {val => "val", uaddr => "uaddr", flags => "flags", __reserved => "__reserved"});
    c_layout!(source, RawCqe, "io_uring_cqe", {user_data => "user_data", res => "res", flags => "flags"});
    c_layout!(source, RawCqe32, "cqe32_fixture", {base => "base", big_cqe => "big_cqe"});
    c_layout!(source, IoUringZcrxRqe, "io_uring_zcrx_rqe", {off => "off", len => "len", __pad => "__pad"});
    c_layout!(source, IoUringZcrxCqe, "io_uring_zcrx_cqe", {off => "off", __pad => "__pad"});
    c_layout!(source, IoUringZcrxOffsets, "io_uring_zcrx_offsets", {head => "head", tail => "tail", rqes => "rqes", __resv2 => "__resv2", __resv => "__resv"});
    c_layout!(source, IoUringZcrxAreaReg, "io_uring_zcrx_area_reg", {addr => "addr", len => "len", rq_area_token => "rq_area_token", flags => "flags", dmabuf_fd => "dmabuf_fd", __resv2 => "__resv2"});
    c_layout!(source, IoUringZcrxIfqReg, "io_uring_zcrx_ifq_reg", {if_idx => "if_idx", if_rxq => "if_rxq", rq_entries => "rq_entries", flags => "flags", area_ptr => "area_ptr", region_ptr => "region_ptr", offsets => "offsets", zcrx_id => "zcrx_id", rx_buf_len => "rx_buf_len", __resv => "__resv"});
    c_layout!(source, ZcrxCtrlFlushRq, "zcrx_ctrl_flush_rq", {__resv => "__resv"});
    c_layout!(source, ZcrxCtrlExport, "zcrx_ctrl_export", {zcrx_fd => "zcrx_fd", __resv1 => "__resv1"});
    c_layout!(source, ZcrxCtrl, "zcrx_ctrl", {zcrx_id => "zcrx_id", op => "op", __resv => "__resv", payload => "zc_export"});
    c_layout!(source, IoUringQueryHdr, "io_uring_query_hdr", {next_entry => "next_entry", query_data => "query_data", query_op => "query_op", size => "size", result => "result", __resv => "__resv"});
    c_layout!(source, IoUringQueryOpcode, "io_uring_query_opcode", {nr_request_opcodes => "nr_request_opcodes", nr_register_opcodes => "nr_register_opcodes", feature_flags => "feature_flags", ring_setup_flags => "ring_setup_flags", enter_flags => "enter_flags", sqe_flags => "sqe_flags", nr_query_opcodes => "nr_query_opcodes", __pad => "__pad"});
    c_layout!(source, IoUringQueryZcrx, "io_uring_query_zcrx", {register_flags => "register_flags", area_flags => "area_flags", nr_ctrl_opcodes => "nr_ctrl_opcodes", features => "features", rq_hdr_size => "rq_hdr_size", rq_hdr_alignment => "rq_hdr_alignment", __resv2 => "__resv2"});
    c_layout!(source, IoUringQueryScq, "io_uring_query_scq", {hdr_size => "hdr_size", hdr_alignment => "hdr_alignment"});
    c_layout!(source, IoUringBpfCtx, "io_uring_bpf_ctx", {user_data => "user_data", opcode => "opcode", sqe_flags => "sqe_flags", pdu_size => "pdu_size", pad => "pad", pdu => "open"});
    c_layout!(source, IoUringBpfFilter, "io_uring_bpf_filter", {opcode => "opcode", flags => "flags", filter_len => "filter_len", pdu_size => "pdu_size", resv => "resv", filter_ptr => "filter_ptr", resv2 => "resv2"});
    c_layout!(source, IoUringBpf, "io_uring_bpf", {cmd_type => "cmd_type", cmd_flags => "cmd_flags", resv => "resv", filter => "filter"});
    c_layout!(source, IoSqringOffsets, "io_sqring_offsets", {head => "head", tail => "tail", ring_mask => "ring_mask", ring_entries => "ring_entries", flags => "flags", dropped => "dropped", array => "array", resv1 => "resv1", user_addr => "user_addr"});
    c_layout!(source, IoCqringOffsets, "io_cqring_offsets", {head => "head", tail => "tail", ring_mask => "ring_mask", ring_entries => "ring_entries", overflow => "overflow", cqes => "cqes", flags => "flags", resv1 => "resv1", user_addr => "user_addr"});
    c_layout!(source, IoUringParams, "io_uring_params", {sq_entries => "sq_entries", cq_entries => "cq_entries", flags => "flags", sq_thread_cpu => "sq_thread_cpu", sq_thread_idle => "sq_thread_idle", features => "features", wq_fd => "wq_fd", resv => "resv", sq_off => "sq_off", cq_off => "cq_off"});
    c_layout!(source, KernelTimespec, "__kernel_timespec", {tv_sec => "tv_sec", tv_nsec => "tv_nsec"});
    c_layout!(source, IoTimespec, "io_timespec", {tv_sec => "tv_sec", tv_nsec => "tv_nsec"});
    c_layout!(source, IoUringGeteventsArg, "io_uring_getevents_arg", {sigmask => "sigmask", sigmask_sz => "sigmask_sz", min_wait_usec => "min_wait_usec", ts => "ts"});
    c_layout!(source, IoUringRegWait, "io_uring_reg_wait", {ts => "ts", min_wait_usec => "min_wait_usec", flags => "flags", sigmask => "sigmask", sigmask_sz => "sigmask_sz", pad => "pad", pad2 => "pad2"});
    c_layout!(source, RawSqe, "io_uring_sqe", {opcode => "opcode", flags => "flags", ioprio => "ioprio", fd => "fd", off => "off", addr => "addr", len => "len", operation_flags => "rw_flags", user_data => "user_data", buf_index => "buf_index", personality => "personality", splice_fd_in => "file_index", addr3 => "addr3", pad2 => "__pad2"});
    c_layout!(source, RawSqe128, "sqe128_fixture", {base => "base", cmd_ext => "cmd_ext"});
    c_layout!(source, IoUringAttrPi, "io_uring_attr_pi", {flags => "flags", app_tag => "app_tag", len => "len", addr => "addr", seed => "seed", rsvd => "rsvd"});
    c_layout!(source, IoUringFilesUpdate, "io_uring_files_update", {offset => "offset", resv => "resv", fds => "fds"});
    c_layout!(source, IoUringRsrcRegister, "io_uring_rsrc_register", {nr => "nr", flags => "flags", resv2 => "resv2", data => "data", tags => "tags"});
    c_layout!(source, IoUringRsrcUpdate, "io_uring_rsrc_update", {offset => "offset", resv => "resv", data => "data"});
    c_layout!(source, IoUringRsrcUpdate2, "io_uring_rsrc_update2", {offset => "offset", resv => "resv", data => "data", tags => "tags", nr => "nr", resv2 => "resv2"});
    c_layout!(source, IoUringProbeOp, "io_uring_probe_op", {op => "op", resv => "resv", flags => "flags", resv2 => "resv2"});
    c_layout!(source, IoUringProbeHeader, "io_uring_probe", {last_op => "last_op", ops_len => "ops_len", resv => "resv", resv2 => "resv2"});
    c_layout!(source, IoUringRestriction, "io_uring_restriction", {opcode => "opcode", register_op => "register_op", resv => "resv", resv2 => "resv2"});
    c_layout!(source, IoUringTaskRestrictionHeader, "io_uring_task_restriction", {flags => "flags", nr_res => "nr_res", resv => "resv"});
    c_layout!(source, IoUringClockRegister, "io_uring_clock_register", {clockid => "clockid", __resv => "__resv"});
    c_layout!(source, IoUringCloneBuffers, "io_uring_clone_buffers", {src_fd => "src_fd", flags => "flags", src_off => "src_off", dst_off => "dst_off", nr => "nr", pad => "pad"});
    c_layout!(source, IoUringBuf, "io_uring_buf", {addr => "addr", len => "len", bid => "bid", resv => "resv"});
    c_layout!(source, IoUringBufRingHeader, "io_uring_buf_ring", {resv1 => "resv1", resv2 => "resv2", resv3 => "resv3", tail => "tail"});
    c_layout!(source, IoUringBufReg, "io_uring_buf_reg", {ring_addr => "ring_addr", ring_entries => "ring_entries", bgid => "bgid", flags => "flags", min_left => "min_left", resv => "resv"});
    c_layout!(source, IoUringBufStatus, "io_uring_buf_status", {buf_group => "buf_group", head => "head", resv => "resv"});
    c_layout!(source, IoUringNapi, "io_uring_napi", {busy_poll_to => "busy_poll_to", prefer_busy_poll => "prefer_busy_poll", opcode => "opcode", pad => "pad", op_param => "op_param", resv => "resv"});
    c_layout!(source, IoUringSyncCancelReg, "io_uring_sync_cancel_reg", {addr => "addr", fd => "fd", flags => "flags", timeout => "timeout", opcode => "opcode", pad => "pad", pad2 => "pad2"});
    c_layout!(source, IoUringFileIndexRange, "io_uring_file_index_range", {off => "off", len => "len", resv => "resv"});
    c_layout!(source, IoUringRecvmsgOut, "io_uring_recvmsg_out", {namelen => "namelen", controllen => "controllen", payloadlen => "payloadlen", flags => "flags"});
    c_layout!(source, IoUringRegionDesc, "io_uring_region_desc", {user_addr => "user_addr", size => "size", flags => "flags", id => "id", mmap_offset => "mmap_offset", __resv => "__resv"});
    c_layout!(source, IoUringMemRegionReg, "io_uring_mem_region_reg", {region_uptr => "region_uptr", flags => "flags", __resv => "__resv"});
    compile_header_contract(source);
}

#[test]
fn raw_setup_probe_and_enter_smoke() {
    use std::os::fd::{AsRawFd, FromRawFd};

    use liburing::backend::sys::{self, params::IoUringParams, register::*};
    sys::ensure_kernel_baseline_6_16().unwrap();
    let mut params = IoUringParams::default();
    // SAFETY: params is an exclusive initialized record; default flags request ordinary fd
    // ownership.
    let fd = unsafe { sys::sys_io_uring_setup(2, &raw mut params) };
    assert!(fd >= 0, "io_uring_setup failed: {fd}");
    // SAFETY: Successful setup returned a new VFS descriptor which this owner adopts exactly once.
    let ring = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    #[repr(C)]
    struct Probe {
        header: IoUringProbeHeader,
        ops: [IoUringProbeOp; 65],
    }
    let mut probe = Probe {
        header: IoUringProbeHeader::default(),
        ops: [IoUringProbeOp::default(); 65],
    };
    // SAFETY: The live ring is an ordinary fd. The probe has capacity for nr_args records and
    // a writable header. Empty enter has no SQE operands, argument pointer or blocking wait.
    unsafe {
        assert_eq!(
            sys::sys_io_uring_register(
                ring.as_raw_fd(),
                IORING_REGISTER_PROBE,
                (&raw mut probe).cast(),
                65
            ),
            0
        );
        assert_eq!(
            sys::sys_io_uring_enter(ring.as_raw_fd(), 0, 0, 0, std::ptr::null(), 0),
            0
        );
    }
    assert!(probe.header.ops_len > 0);
    assert_eq!(probe.ops[0].op, 0);
    assert_ne!(probe.ops[0].flags & IO_URING_OP_SUPPORTED, 0);
}

#[test]
fn constants_match_kernel_inventory() {
    use std::fmt::Write as _;

    use liburing::backend::sys::{self, cqe, futex, params, query_bpf, register, sqe, zcrx};
    let mut source = linux_header_source();
    macro_rules! check {
        ($rust:expr, $c:literal) => {
            writeln!(
                source,
                "_Static_assert((unsigned long long)({}) == {}ULL, \"constant {}\");",
                $c, $rust as u64, $c
            )
            .unwrap();
        };
    }
    check!(futex::FUTEX2_SIZE_U8, "FUTEX2_SIZE_U8");
    check!(futex::FUTEX2_SIZE_U16, "FUTEX2_SIZE_U16");
    check!(futex::FUTEX2_SIZE_U32, "FUTEX2_SIZE_U32");
    check!(futex::FUTEX2_SIZE_U64, "FUTEX2_SIZE_U64");
    check!(futex::FUTEX2_SIZE_MASK, "FUTEX2_SIZE_MASK");
    check!(futex::FUTEX2_NUMA, "FUTEX2_NUMA");
    check!(futex::FUTEX2_MPOL, "FUTEX2_MPOL");
    check!(futex::FUTEX2_PRIVATE, "FUTEX2_PRIVATE");
    check!(futex::FUTEX_NO_NODE, "FUTEX_NO_NODE");
    check!(futex::FUTEX_WAITV_MAX, "FUTEX_WAITV_MAX");
    check!(futex::FUTEX_BITSET_MATCH_ANY, "FUTEX_BITSET_MATCH_ANY");
    check!(cqe::IORING_CQE_F_BUFFER, "IORING_CQE_F_BUFFER");
    check!(cqe::IORING_CQE_F_MORE, "IORING_CQE_F_MORE");
    check!(
        cqe::IORING_CQE_F_SOCK_NONEMPTY,
        "IORING_CQE_F_SOCK_NONEMPTY"
    );
    check!(cqe::IORING_CQE_F_NOTIF, "IORING_CQE_F_NOTIF");
    check!(cqe::IORING_CQE_F_BUF_MORE, "IORING_CQE_F_BUF_MORE");
    check!(cqe::IORING_CQE_F_SKIP, "IORING_CQE_F_SKIP");
    check!(cqe::IORING_CQE_F_32, "IORING_CQE_F_32");
    check!(cqe::IORING_CQE_BUFFER_SHIFT, "IORING_CQE_BUFFER_SHIFT");
    check!(
        cqe::IORING_NOTIF_USAGE_ZC_COPIED,
        "IORING_NOTIF_USAGE_ZC_COPIED"
    );
    check!(zcrx::IORING_ZCRX_AREA_SHIFT, "IORING_ZCRX_AREA_SHIFT");
    check!(zcrx::IORING_ZCRX_AREA_MASK, "IORING_ZCRX_AREA_MASK");
    check!(zcrx::IORING_ZCRX_AREA_DMABUF, "IORING_ZCRX_AREA_DMABUF");
    check!(zcrx::ZCRX_REG_IMPORT, "ZCRX_REG_IMPORT");
    check!(zcrx::ZCRX_FEATURE_RX_PAGE_SIZE, "ZCRX_FEATURE_RX_PAGE_SIZE");
    check!(zcrx::ZCRX_CTRL_FLUSH_RQ, "ZCRX_CTRL_FLUSH_RQ");
    check!(zcrx::ZCRX_CTRL_EXPORT, "ZCRX_CTRL_EXPORT");
    check!(zcrx::ZCRX_CTRL_LAST, "__ZCRX_CTRL_LAST");
    check!(sys::SYS_IO_URING_SETUP, "__NR_io_uring_setup");
    check!(sys::SYS_IO_URING_ENTER, "__NR_io_uring_enter");
    check!(sys::SYS_IO_URING_REGISTER, "__NR_io_uring_register");
    check!(sys::SYS_FUTEX_WAITV, "__NR_futex_waitv");
    check!(sys::SYS_FUTEX_WAKE, "__NR_futex_wake");
    check!(sys::SYS_FUTEX_WAIT, "__NR_futex_wait");
    check!(sys::SYS_FUTEX_REQUEUE, "__NR_futex_requeue");
    check!(params::IORING_SETUP_IOPOLL, "IORING_SETUP_IOPOLL");
    check!(params::IORING_SETUP_SQPOLL, "IORING_SETUP_SQPOLL");
    check!(params::IORING_SETUP_SQ_AFF, "IORING_SETUP_SQ_AFF");
    check!(params::IORING_SETUP_CQSIZE, "IORING_SETUP_CQSIZE");
    check!(params::IORING_SETUP_CLAMP, "IORING_SETUP_CLAMP");
    check!(params::IORING_SETUP_ATTACH_WQ, "IORING_SETUP_ATTACH_WQ");
    check!(params::IORING_SETUP_R_DISABLED, "IORING_SETUP_R_DISABLED");
    check!(params::IORING_SETUP_SUBMIT_ALL, "IORING_SETUP_SUBMIT_ALL");
    check!(
        params::IORING_SETUP_COOP_TASKRUN,
        "IORING_SETUP_COOP_TASKRUN"
    );
    check!(
        params::IORING_SETUP_TASKRUN_FLAG,
        "IORING_SETUP_TASKRUN_FLAG"
    );
    check!(params::IORING_SETUP_SQE128, "IORING_SETUP_SQE128");
    check!(params::IORING_SETUP_CQE32, "IORING_SETUP_CQE32");
    check!(
        params::IORING_SETUP_SINGLE_ISSUER,
        "IORING_SETUP_SINGLE_ISSUER"
    );
    check!(
        params::IORING_SETUP_DEFER_TASKRUN,
        "IORING_SETUP_DEFER_TASKRUN"
    );
    check!(params::IORING_SETUP_NO_MMAP, "IORING_SETUP_NO_MMAP");
    check!(
        params::IORING_SETUP_REGISTERED_FD_ONLY,
        "IORING_SETUP_REGISTERED_FD_ONLY"
    );
    check!(params::IORING_SETUP_NO_SQARRAY, "IORING_SETUP_NO_SQARRAY");
    check!(
        params::IORING_SETUP_HYBRID_IOPOLL,
        "IORING_SETUP_HYBRID_IOPOLL"
    );
    check!(params::IORING_SETUP_CQE_MIXED, "IORING_SETUP_CQE_MIXED");
    check!(params::IORING_SETUP_SQE_MIXED, "IORING_SETUP_SQE_MIXED");
    check!(params::IORING_SETUP_SQ_REWIND, "IORING_SETUP_SQ_REWIND");
    check!(params::IORING_FEAT_SINGLE_MMAP, "IORING_FEAT_SINGLE_MMAP");
    check!(params::IORING_FEAT_NODROP, "IORING_FEAT_NODROP");
    check!(
        params::IORING_FEAT_SUBMIT_STABLE,
        "IORING_FEAT_SUBMIT_STABLE"
    );
    check!(params::IORING_FEAT_RW_CUR_POS, "IORING_FEAT_RW_CUR_POS");
    check!(
        params::IORING_FEAT_CUR_PERSONALITY,
        "IORING_FEAT_CUR_PERSONALITY"
    );
    check!(params::IORING_FEAT_FAST_POLL, "IORING_FEAT_FAST_POLL");
    check!(params::IORING_FEAT_POLL_32BITS, "IORING_FEAT_POLL_32BITS");
    check!(
        params::IORING_FEAT_SQPOLL_NONFIXED,
        "IORING_FEAT_SQPOLL_NONFIXED"
    );
    check!(params::IORING_FEAT_EXT_ARG, "IORING_FEAT_EXT_ARG");
    check!(
        params::IORING_FEAT_NATIVE_WORKERS,
        "IORING_FEAT_NATIVE_WORKERS"
    );
    check!(params::IORING_FEAT_RSRC_TAGS, "IORING_FEAT_RSRC_TAGS");
    check!(params::IORING_FEAT_CQE_SKIP, "IORING_FEAT_CQE_SKIP");
    check!(params::IORING_FEAT_LINKED_FILE, "IORING_FEAT_LINKED_FILE");
    check!(params::IORING_FEAT_REG_REG_RING, "IORING_FEAT_REG_REG_RING");
    check!(
        params::IORING_FEAT_RECVSEND_BUNDLE,
        "IORING_FEAT_RECVSEND_BUNDLE"
    );
    check!(params::IORING_FEAT_MIN_TIMEOUT, "IORING_FEAT_MIN_TIMEOUT");
    check!(params::IORING_FEAT_RW_ATTR, "IORING_FEAT_RW_ATTR");
    check!(params::IORING_FEAT_NO_IOWAIT, "IORING_FEAT_NO_IOWAIT");
    check!(params::IORING_ENTER_GETEVENTS, "IORING_ENTER_GETEVENTS");
    check!(params::IORING_ENTER_SQ_WAKEUP, "IORING_ENTER_SQ_WAKEUP");
    check!(params::IORING_ENTER_SQ_WAIT, "IORING_ENTER_SQ_WAIT");
    check!(params::IORING_ENTER_EXT_ARG, "IORING_ENTER_EXT_ARG");
    check!(
        params::IORING_ENTER_REGISTERED_RING,
        "IORING_ENTER_REGISTERED_RING"
    );
    check!(params::IORING_ENTER_ABS_TIMER, "IORING_ENTER_ABS_TIMER");
    check!(params::IORING_ENTER_EXT_ARG_REG, "IORING_ENTER_EXT_ARG_REG");
    check!(params::IORING_ENTER_NO_IOWAIT, "IORING_ENTER_NO_IOWAIT");
    check!(params::IORING_SQ_NEED_WAKEUP, "IORING_SQ_NEED_WAKEUP");
    check!(params::IORING_SQ_CQ_OVERFLOW, "IORING_SQ_CQ_OVERFLOW");
    check!(params::IORING_SQ_TASKRUN, "IORING_SQ_TASKRUN");
    check!(
        params::IORING_CQ_EVENTFD_DISABLED,
        "IORING_CQ_EVENTFD_DISABLED"
    );
    check!(params::IORING_OFF_SQ_RING, "IORING_OFF_SQ_RING");
    check!(params::IORING_OFF_CQ_RING, "IORING_OFF_CQ_RING");
    check!(params::IORING_OFF_SQES, "IORING_OFF_SQES");
    check!(params::IORING_OFF_PBUF_RING, "IORING_OFF_PBUF_RING");
    check!(params::IORING_OFF_PBUF_SHIFT, "IORING_OFF_PBUF_SHIFT");
    check!(params::IORING_OFF_MMAP_MASK, "IORING_OFF_MMAP_MASK");
    check!(params::IORING_REG_WAIT_TS, "IORING_REG_WAIT_TS");
    check!(query_bpf::IO_URING_QUERY_OPCODES, "IO_URING_QUERY_OPCODES");
    check!(query_bpf::IO_URING_QUERY_ZCRX, "IO_URING_QUERY_ZCRX");
    check!(query_bpf::IO_URING_QUERY_SCQ, "IO_URING_QUERY_SCQ");
    check!(query_bpf::IO_URING_QUERY_MAX, "__IO_URING_QUERY_MAX");
    check!(
        query_bpf::IO_URING_BPF_FILTER_DENY_REST,
        "IO_URING_BPF_FILTER_DENY_REST"
    );
    check!(
        query_bpf::IO_URING_BPF_FILTER_SZ_STRICT,
        "IO_URING_BPF_FILTER_SZ_STRICT"
    );
    check!(
        query_bpf::IO_URING_BPF_CMD_FILTER,
        "IO_URING_BPF_CMD_FILTER"
    );
    check!(sqe::IORING_RW_ATTR_FLAG_PI, "IORING_RW_ATTR_FLAG_PI");
    check!(sqe::IORING_FILE_INDEX_ALLOC, "IORING_FILE_INDEX_ALLOC");
    check!(sqe::IOSQE_FIXED_FILE, "IOSQE_FIXED_FILE");
    check!(sqe::IOSQE_IO_DRAIN, "IOSQE_IO_DRAIN");
    check!(sqe::IOSQE_IO_LINK, "IOSQE_IO_LINK");
    check!(sqe::IOSQE_IO_HARDLINK, "IOSQE_IO_HARDLINK");
    check!(sqe::IOSQE_ASYNC, "IOSQE_ASYNC");
    check!(sqe::IOSQE_BUFFER_SELECT, "IOSQE_BUFFER_SELECT");
    check!(sqe::IOSQE_CQE_SKIP_SUCCESS, "IOSQE_CQE_SKIP_SUCCESS");
    check!(sqe::IORING_OP_NOP, "IORING_OP_NOP");
    check!(sqe::IORING_OP_READV, "IORING_OP_READV");
    check!(sqe::IORING_OP_WRITEV, "IORING_OP_WRITEV");
    check!(sqe::IORING_OP_FSYNC, "IORING_OP_FSYNC");
    check!(sqe::IORING_OP_READ_FIXED, "IORING_OP_READ_FIXED");
    check!(sqe::IORING_OP_WRITE_FIXED, "IORING_OP_WRITE_FIXED");
    check!(sqe::IORING_OP_POLL_ADD, "IORING_OP_POLL_ADD");
    check!(sqe::IORING_OP_POLL_REMOVE, "IORING_OP_POLL_REMOVE");
    check!(sqe::IORING_OP_SYNC_FILE_RANGE, "IORING_OP_SYNC_FILE_RANGE");
    check!(sqe::IORING_OP_SENDMSG, "IORING_OP_SENDMSG");
    check!(sqe::IORING_OP_RECVMSG, "IORING_OP_RECVMSG");
    check!(sqe::IORING_OP_TIMEOUT, "IORING_OP_TIMEOUT");
    check!(sqe::IORING_OP_TIMEOUT_REMOVE, "IORING_OP_TIMEOUT_REMOVE");
    check!(sqe::IORING_OP_ACCEPT, "IORING_OP_ACCEPT");
    check!(sqe::IORING_OP_ASYNC_CANCEL, "IORING_OP_ASYNC_CANCEL");
    check!(sqe::IORING_OP_LINK_TIMEOUT, "IORING_OP_LINK_TIMEOUT");
    check!(sqe::IORING_OP_CONNECT, "IORING_OP_CONNECT");
    check!(sqe::IORING_OP_FALLOCATE, "IORING_OP_FALLOCATE");
    check!(sqe::IORING_OP_OPENAT, "IORING_OP_OPENAT");
    check!(sqe::IORING_OP_CLOSE, "IORING_OP_CLOSE");
    check!(sqe::IORING_OP_FILES_UPDATE, "IORING_OP_FILES_UPDATE");
    check!(sqe::IORING_OP_STATX, "IORING_OP_STATX");
    check!(sqe::IORING_OP_READ, "IORING_OP_READ");
    check!(sqe::IORING_OP_WRITE, "IORING_OP_WRITE");
    check!(sqe::IORING_OP_FADVISE, "IORING_OP_FADVISE");
    check!(sqe::IORING_OP_MADVISE, "IORING_OP_MADVISE");
    check!(sqe::IORING_OP_SEND, "IORING_OP_SEND");
    check!(sqe::IORING_OP_RECV, "IORING_OP_RECV");
    check!(sqe::IORING_OP_OPENAT2, "IORING_OP_OPENAT2");
    check!(sqe::IORING_OP_EPOLL_CTL, "IORING_OP_EPOLL_CTL");
    check!(sqe::IORING_OP_SPLICE, "IORING_OP_SPLICE");
    check!(sqe::IORING_OP_PROVIDE_BUFFERS, "IORING_OP_PROVIDE_BUFFERS");
    check!(sqe::IORING_OP_REMOVE_BUFFERS, "IORING_OP_REMOVE_BUFFERS");
    check!(sqe::IORING_OP_TEE, "IORING_OP_TEE");
    check!(sqe::IORING_OP_SHUTDOWN, "IORING_OP_SHUTDOWN");
    check!(sqe::IORING_OP_RENAMEAT, "IORING_OP_RENAMEAT");
    check!(sqe::IORING_OP_UNLINKAT, "IORING_OP_UNLINKAT");
    check!(sqe::IORING_OP_MKDIRAT, "IORING_OP_MKDIRAT");
    check!(sqe::IORING_OP_SYMLINKAT, "IORING_OP_SYMLINKAT");
    check!(sqe::IORING_OP_LINKAT, "IORING_OP_LINKAT");
    check!(sqe::IORING_OP_MSG_RING, "IORING_OP_MSG_RING");
    check!(sqe::IORING_OP_FSETXATTR, "IORING_OP_FSETXATTR");
    check!(sqe::IORING_OP_SETXATTR, "IORING_OP_SETXATTR");
    check!(sqe::IORING_OP_FGETXATTR, "IORING_OP_FGETXATTR");
    check!(sqe::IORING_OP_GETXATTR, "IORING_OP_GETXATTR");
    check!(sqe::IORING_OP_SOCKET, "IORING_OP_SOCKET");
    check!(sqe::IORING_OP_URING_CMD, "IORING_OP_URING_CMD");
    check!(sqe::IORING_OP_SEND_ZC, "IORING_OP_SEND_ZC");
    check!(sqe::IORING_OP_SENDMSG_ZC, "IORING_OP_SENDMSG_ZC");
    check!(sqe::IORING_OP_READ_MULTISHOT, "IORING_OP_READ_MULTISHOT");
    check!(sqe::IORING_OP_WAITID, "IORING_OP_WAITID");
    check!(sqe::IORING_OP_FUTEX_WAIT, "IORING_OP_FUTEX_WAIT");
    check!(sqe::IORING_OP_FUTEX_WAKE, "IORING_OP_FUTEX_WAKE");
    check!(sqe::IORING_OP_FUTEX_WAITV, "IORING_OP_FUTEX_WAITV");
    check!(
        sqe::IORING_OP_FIXED_FD_INSTALL,
        "IORING_OP_FIXED_FD_INSTALL"
    );
    check!(sqe::IORING_OP_FTRUNCATE, "IORING_OP_FTRUNCATE");
    check!(sqe::IORING_OP_BIND, "IORING_OP_BIND");
    check!(sqe::IORING_OP_LISTEN, "IORING_OP_LISTEN");
    check!(sqe::IORING_OP_RECV_ZC, "IORING_OP_RECV_ZC");
    check!(sqe::IORING_OP_EPOLL_WAIT, "IORING_OP_EPOLL_WAIT");
    check!(sqe::IORING_OP_READV_FIXED, "IORING_OP_READV_FIXED");
    check!(sqe::IORING_OP_WRITEV_FIXED, "IORING_OP_WRITEV_FIXED");
    check!(sqe::IORING_OP_PIPE, "IORING_OP_PIPE");
    check!(sqe::IORING_OP_NOP128, "IORING_OP_NOP128");
    check!(sqe::IORING_OP_URING_CMD128, "IORING_OP_URING_CMD128");
    check!(sqe::IORING_OP_LAST, "IORING_OP_LAST");
    check!(register::IORING_REGISTER_BUFFERS, "IORING_REGISTER_BUFFERS");
    check!(
        register::IORING_UNREGISTER_BUFFERS,
        "IORING_UNREGISTER_BUFFERS"
    );
    check!(register::IORING_REGISTER_FILES, "IORING_REGISTER_FILES");
    check!(register::IORING_UNREGISTER_FILES, "IORING_UNREGISTER_FILES");
    check!(register::IORING_REGISTER_EVENTFD, "IORING_REGISTER_EVENTFD");
    check!(
        register::IORING_UNREGISTER_EVENTFD,
        "IORING_UNREGISTER_EVENTFD"
    );
    check!(
        register::IORING_REGISTER_FILES_UPDATE,
        "IORING_REGISTER_FILES_UPDATE"
    );
    check!(
        register::IORING_REGISTER_EVENTFD_ASYNC,
        "IORING_REGISTER_EVENTFD_ASYNC"
    );
    check!(register::IORING_REGISTER_PROBE, "IORING_REGISTER_PROBE");
    check!(
        register::IORING_REGISTER_PERSONALITY,
        "IORING_REGISTER_PERSONALITY"
    );
    check!(
        register::IORING_UNREGISTER_PERSONALITY,
        "IORING_UNREGISTER_PERSONALITY"
    );
    check!(
        register::IORING_REGISTER_RESTRICTIONS,
        "IORING_REGISTER_RESTRICTIONS"
    );
    check!(
        register::IORING_REGISTER_ENABLE_RINGS,
        "IORING_REGISTER_ENABLE_RINGS"
    );
    check!(register::IORING_REGISTER_FILES2, "IORING_REGISTER_FILES2");
    check!(
        register::IORING_REGISTER_FILES_UPDATE2,
        "IORING_REGISTER_FILES_UPDATE2"
    );
    check!(
        register::IORING_REGISTER_BUFFERS2,
        "IORING_REGISTER_BUFFERS2"
    );
    check!(
        register::IORING_REGISTER_BUFFERS_UPDATE,
        "IORING_REGISTER_BUFFERS_UPDATE"
    );
    check!(
        register::IORING_REGISTER_IOWQ_AFF,
        "IORING_REGISTER_IOWQ_AFF"
    );
    check!(
        register::IORING_UNREGISTER_IOWQ_AFF,
        "IORING_UNREGISTER_IOWQ_AFF"
    );
    check!(
        register::IORING_REGISTER_IOWQ_MAX_WORKERS,
        "IORING_REGISTER_IOWQ_MAX_WORKERS"
    );
    check!(
        register::IORING_REGISTER_RING_FDS,
        "IORING_REGISTER_RING_FDS"
    );
    check!(
        register::IORING_UNREGISTER_RING_FDS,
        "IORING_UNREGISTER_RING_FDS"
    );
    check!(
        register::IORING_REGISTER_PBUF_RING,
        "IORING_REGISTER_PBUF_RING"
    );
    check!(
        register::IORING_UNREGISTER_PBUF_RING,
        "IORING_UNREGISTER_PBUF_RING"
    );
    check!(
        register::IORING_REGISTER_SYNC_CANCEL,
        "IORING_REGISTER_SYNC_CANCEL"
    );
    check!(
        register::IORING_REGISTER_FILE_ALLOC_RANGE,
        "IORING_REGISTER_FILE_ALLOC_RANGE"
    );
    check!(
        register::IORING_REGISTER_PBUF_STATUS,
        "IORING_REGISTER_PBUF_STATUS"
    );
    check!(register::IORING_REGISTER_NAPI, "IORING_REGISTER_NAPI");
    check!(register::IORING_UNREGISTER_NAPI, "IORING_UNREGISTER_NAPI");
    check!(register::IORING_REGISTER_CLOCK, "IORING_REGISTER_CLOCK");
    check!(
        register::IORING_REGISTER_CLONE_BUFFERS,
        "IORING_REGISTER_CLONE_BUFFERS"
    );
    check!(
        register::IORING_REGISTER_SEND_MSG_RING,
        "IORING_REGISTER_SEND_MSG_RING"
    );
    check!(
        register::IORING_REGISTER_ZCRX_IFQ,
        "IORING_REGISTER_ZCRX_IFQ"
    );
    check!(
        register::IORING_REGISTER_RESIZE_RINGS,
        "IORING_REGISTER_RESIZE_RINGS"
    );
    check!(
        register::IORING_REGISTER_MEM_REGION,
        "IORING_REGISTER_MEM_REGION"
    );
    check!(register::IORING_REGISTER_QUERY, "IORING_REGISTER_QUERY");
    check!(
        register::IORING_REGISTER_ZCRX_CTRL,
        "IORING_REGISTER_ZCRX_CTRL"
    );
    check!(
        register::IORING_REGISTER_BPF_FILTER,
        "IORING_REGISTER_BPF_FILTER"
    );
    check!(register::IORING_REGISTER_LAST, "IORING_REGISTER_LAST");
    check!(
        register::IORING_REGISTER_USE_REGISTERED_RING,
        "IORING_REGISTER_USE_REGISTERED_RING"
    );
    check!(
        register::IORING_REGISTER_FILES_SKIP,
        "IORING_REGISTER_FILES_SKIP"
    );
    check!(
        register::IORING_RSRC_REGISTER_SPARSE,
        "IORING_RSRC_REGISTER_SPARSE"
    );
    check!(register::IO_URING_OP_SUPPORTED, "IO_URING_OP_SUPPORTED");
    check!(
        register::IORING_MEM_REGION_TYPE_USER,
        "IORING_MEM_REGION_TYPE_USER"
    );
    check!(
        register::IORING_MEM_REGION_REG_WAIT_ARG,
        "IORING_MEM_REGION_REG_WAIT_ARG"
    );
    check!(
        register::IORING_REGISTER_SRC_REGISTERED,
        "IORING_REGISTER_SRC_REGISTERED"
    );
    check!(
        register::IORING_REGISTER_DST_REPLACE,
        "IORING_REGISTER_DST_REPLACE"
    );
    check!(register::IOU_PBUF_RING_MMAP, "IOU_PBUF_RING_MMAP");
    check!(register::IOU_PBUF_RING_INC, "IOU_PBUF_RING_INC");
    check!(register::IO_WQ_BOUND, "IO_WQ_BOUND");
    check!(register::IO_WQ_UNBOUND, "IO_WQ_UNBOUND");
    check!(
        register::IO_URING_NAPI_REGISTER_OP,
        "IO_URING_NAPI_REGISTER_OP"
    );
    check!(
        register::IO_URING_NAPI_STATIC_ADD_ID,
        "IO_URING_NAPI_STATIC_ADD_ID"
    );
    check!(
        register::IO_URING_NAPI_STATIC_DEL_ID,
        "IO_URING_NAPI_STATIC_DEL_ID"
    );
    check!(
        register::IO_URING_NAPI_TRACKING_DYNAMIC,
        "IO_URING_NAPI_TRACKING_DYNAMIC"
    );
    check!(
        register::IO_URING_NAPI_TRACKING_STATIC,
        "IO_URING_NAPI_TRACKING_STATIC"
    );
    check!(
        register::IO_URING_NAPI_TRACKING_INACTIVE,
        "IO_URING_NAPI_TRACKING_INACTIVE"
    );
    check!(
        register::IORING_RESTRICTION_REGISTER_OP,
        "IORING_RESTRICTION_REGISTER_OP"
    );
    check!(
        register::IORING_RESTRICTION_SQE_OP,
        "IORING_RESTRICTION_SQE_OP"
    );
    check!(
        register::IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
        "IORING_RESTRICTION_SQE_FLAGS_ALLOWED"
    );
    check!(
        register::IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
        "IORING_RESTRICTION_SQE_FLAGS_REQUIRED"
    );
    check!(register::IORING_RESTRICTION_LAST, "IORING_RESTRICTION_LAST");
    compile_header_contract(source);
}

/// Code-generation seam for the two-leaf Rust return ABI.
/// # Errors
/// Does not return errors.
/// # Panics
/// Does not panic.
#[unsafe(no_mangle)]
pub fn uapi_completion_probe(
    user_data: u64,
    wire: u64,
) -> liburing::backend::sys::cqe::CompletionWords {
    liburing::backend::sys::cqe::CompletionWords {
        user_data,
        word: liburing::backend::sys::cqe::CqeWord::new(wire.rotate_left(32)),
    }
}

#[test]
fn opcode_bounds_and_command_extent() {
    use liburing::backend::sys::{cqe::RawCqe, sqe::Opcode};
    for code in 0..=255u8 {
        assert_eq!(Opcode::try_from(code).is_ok(), code < 65);
    }
    let mut sqe = RawSqe128::default();
    sqe.command_mut()[0] = 0x12;
    sqe.command_mut()[79] = 0x34;
    assert_eq!(sqe.base.addr3, 0x12);
    assert_eq!(sqe.cmd_ext[63], 0x34);
    let words = uapi_completion_probe(
        std::hint::black_box(7),
        std::hint::black_box(0x8000_0008_ffff_ffea),
    );
    assert_eq!(RawCqe::from(words).res, -22);
    assert_eq!(words.flags(), 0x8000_0008);
}
