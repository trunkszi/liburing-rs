//! Integration tests across the Rust/C ABI and the real kernel ring lifecycle.
//! Kernel operations require an environment that permits io_uring_setup.

use std::{
    mem::{MaybeUninit, align_of, offset_of, size_of},
    ptr,
};

use liburing_sys::*;

const _: unsafe extern "C" fn(*mut io_uring_sqe, u16) = uring_shim_sqe_set_buf_group;
const _: unsafe extern "C" fn(*mut io_uring_sqe, i32, *const libc::msghdr, u32) =
    uring_shim_prep_sendmsg;
const _: unsafe extern "C" fn(*mut io_uring_sqe, i32, *mut libc::msghdr, u32) =
    uring_shim_prep_recvmsg;
const _: unsafe extern "C" fn(*mut io_uring_sqe, i32, *const libc::sockaddr, libc::socklen_t) =
    uring_shim_prep_connect;
const _: unsafe extern "C" fn(*mut io_uring, *const libc::iovec, u32) -> i32 =
    uring_shim_register_buffers;
const _: unsafe extern "C" fn(*mut io_uring, *const i32, u32) -> i32 = uring_shim_register_files;
const _: unsafe extern "C" fn(*mut io_uring, u32) -> i32 = uring_shim_register_files_sparse;
const _: unsafe extern "C" fn(*mut io_uring) -> i32 = uring_shim_unregister_files;
const _: unsafe extern "C" fn(*mut io_uring, u32, *const i32, u32) -> i32 =
    uring_shim_register_files_update;

struct Ring(io_uring);

impl Ring {
    fn new() -> Self {
        let mut ring = MaybeUninit::<io_uring>::uninit();
        // SAFETY: The all-zero parameter representation requests default kernel options.
        let mut params: io_uring_params = unsafe { std::mem::zeroed() };
        // SAFETY: Both output pointers reference writable storage of the C types.
        let result = unsafe { uring_shim_queue_init_params(8, ring.as_mut_ptr(), &mut params) };
        assert_eq!(result, 0, "io_uring_setup failed: {}", -result);
        // SAFETY: Successful queue initialization fully initializes the ring.
        Self(unsafe { ring.assume_init() })
    }

    fn sqe(&mut self) -> *mut io_uring_sqe {
        // SAFETY: The ring remains live and exclusively accessed for this call.
        let sqe = unsafe { uring_shim_get_sqe(&mut self.0) };
        assert!(!sqe.is_null(), "submission queue unexpectedly full");
        sqe
    }

    fn completion(&mut self) -> *mut io_uring_cqe {
        let mut cqe = ptr::null_mut();
        let mut timeout = __kernel_timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        // SAFETY: Ring, output pointer, and timeout remain valid throughout the bounded wait.
        let result = unsafe { uring_shim_wait_cqe_timeout(&mut self.0, &mut cqe, &mut timeout) };
        assert_eq!(result, 0, "waiting for completion failed: {}", -result);
        assert!(!cqe.is_null());
        cqe
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: This wrapper uniquely owns a successfully initialized ring.
        unsafe { uring_shim_queue_exit(&mut self.0) };
    }
}

#[test]
fn integration_c_and_rust_layouts_match() {
    macro_rules! layout {
        ($ty:ty, $size:ident, $align:ident) => {
            // SAFETY: ABI measurement helpers take no pointers and have no preconditions.
            unsafe {
                assert_eq!(size_of::<$ty>(), $size(), stringify!($ty));
                assert_eq!(align_of::<$ty>(), $align(), stringify!($ty));
            }
        };
    }
    layout!(
        io_uring,
        uring_shim_sizeof_io_uring,
        uring_shim_alignof_io_uring
    );
    layout!(
        io_uring_params,
        uring_shim_sizeof_io_uring_params,
        uring_shim_alignof_io_uring_params
    );
    layout!(
        io_uring_sqe,
        uring_shim_sizeof_io_uring_sqe,
        uring_shim_alignof_io_uring_sqe
    );
    layout!(
        io_uring_cqe,
        uring_shim_sizeof_io_uring_cqe,
        uring_shim_alignof_io_uring_cqe
    );
    layout!(
        io_uring_buf_ring,
        uring_shim_sizeof_io_uring_buf_ring,
        uring_shim_alignof_io_uring_buf_ring
    );
    layout!(
        io_uring_buf,
        uring_shim_sizeof_io_uring_buf,
        uring_shim_alignof_io_uring_buf
    );
    layout!(
        __kernel_timespec,
        uring_shim_sizeof_kernel_timespec,
        uring_shim_alignof_kernel_timespec
    );
    // SAFETY: Offset helpers are pure C layout queries without preconditions.
    unsafe {
        assert_eq!(
            offset_of!(io_uring_sqe, user_data),
            uring_shim_offsetof_io_uring_sqe_user_data()
        );
        assert_eq!(
            offset_of!(io_uring_cqe, user_data),
            uring_shim_offsetof_io_uring_cqe_user_data()
        );
        assert_eq!(
            offset_of!(io_uring_cqe, res),
            uring_shim_offsetof_io_uring_cqe_res()
        );
        assert_eq!(
            offset_of!(io_uring_cqe, flags),
            uring_shim_offsetof_io_uring_cqe_flags()
        );
        assert_eq!(
            offset_of!(io_uring_buf, addr),
            uring_shim_offsetof_io_uring_buf_addr()
        );
        assert_eq!(
            offset_of!(io_uring_buf, len),
            uring_shim_offsetof_io_uring_buf_len()
        );
        assert_eq!(
            offset_of!(io_uring_buf, bid),
            uring_shim_offsetof_io_uring_buf_bid()
        );
        assert_eq!(
            offset_of!(io_uring_params, features),
            uring_shim_offsetof_io_uring_params_features()
        );
        assert_eq!(
            offset_of!(__kernel_timespec, tv_nsec),
            uring_shim_offsetof_kernel_timespec_tv_nsec()
        );
    }
}

#[test]
fn integration_lifecycle_nop_submission_and_harvest() {
    let mut ring = Ring::new();
    // SAFETY: The initialized ring and all returned SQE/CQE pointers remain live until teardown.
    unsafe {
        assert_eq!(uring_shim_sq_ready(&ring.0), 0);
        assert!(uring_shim_sq_space_left(&ring.0) >= 2);
        for token in [0x1234_u64, u64::MAX - 1] {
            let sqe = ring.sqe();
            uring_shim_prep_nop(sqe);
            uring_shim_sqe_set_data64(sqe, token);
            uring_shim_sqe_set_flags(sqe, 0);
        }
        assert_eq!(uring_shim_sq_ready(&ring.0), 2);
        assert_eq!(uring_shim_submit(&mut ring.0), 2);
        let mut completed = [0_u64; 2];
        for token in &mut completed {
            let cqe = ring.completion();
            assert_eq!((*cqe).res, 0);
            *token = uring_shim_cqe_get_data64(cqe);
            uring_shim_cqe_seen(&mut ring.0, cqe);
        }
        completed.sort_unstable();
        assert_eq!(completed, [0x1234_u64, u64::MAX - 1]);
        assert_eq!(uring_shim_cq_ready(&ring.0), 0);
        let mut cqe = ptr::null_mut();
        assert_eq!(uring_shim_peek_cqe(&mut ring.0, &mut cqe), -libc::EAGAIN);
        let probe = uring_shim_get_probe_ring(&mut ring.0);
        assert!(!probe.is_null());
        let supported = uring_shim_opcode_supported(probe, IORING_OP_NOP as i32);
        uring_shim_free_probe(probe);
        assert_ne!(supported, 0);
    }
}

#[test]
fn integration_scenario_submit_and_wait_distinguishes_completion_from_timeout() {
    let mut ring = Ring::new();
    let sqe = ring.sqe();
    let mut cqe = ptr::null_mut();
    let mut timeout = __kernel_timespec {
        tv_sec: 2,
        tv_nsec: 0,
    };
    // SAFETY: SQE and CQE storage belong to this live ring, and timeout outlives both waits.
    unsafe {
        uring_shim_prep_nop(sqe);
        uring_shim_sqe_set_data64(sqe, 0x1020_3040_5060_7080);
        assert_eq!(
            uring_shim_submit_and_wait_timeout(
                &mut ring.0,
                &mut cqe,
                1,
                &mut timeout,
                ptr::null_mut(),
            ),
            1,
        );
        assert!(!cqe.is_null());
        assert_eq!((*cqe).res, 0);
        assert_eq!(uring_shim_cqe_get_data64(cqe), 0x1020_3040_5060_7080);
        uring_shim_cqe_seen(&mut ring.0, cqe);

        cqe = ptr::null_mut();
        timeout = __kernel_timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        assert_eq!(
            uring_shim_submit_and_wait_timeout(
                &mut ring.0,
                &mut cqe,
                1,
                &mut timeout,
                ptr::null_mut(),
            ),
            -libc::ETIME,
        );
        assert!(cqe.is_null());
        assert_eq!(uring_shim_cq_ready(&ring.0), 0);
    }
}

#[test]
fn integration_scenario_timeout_completion_preserves_user_data() {
    let mut ring = Ring::new();
    let timeout = __kernel_timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    let sqe = ring.sqe();
    // SAFETY: The timeout stays in scope until its completion; SQE/CQE belong to the live ring.
    unsafe {
        uring_shim_prep_timeout(sqe, &timeout, 0, 0);
        uring_shim_sqe_set_data64(sqe, 0xaabb_ccdd_eeff_0011);
        assert_eq!(uring_shim_submit(&mut ring.0), 1);
        let cqe = ring.completion();
        assert_eq!((*cqe).res, -libc::ETIME);
        assert_eq!(uring_shim_cqe_get_data64(cqe), 0xaabb_ccdd_eeff_0011);
        uring_shim_cq_advance(&mut ring.0, 1);
        assert_eq!(uring_shim_cq_ready(&ring.0), 0);
    }
}

#[test]
fn integration_lifecycle_provided_buffer_ring_helpers() {
    let mut ring = Ring::new();
    let mut error = 0;
    let mut payload = [0_u8; 64];
    // SAFETY: The ring is live; the helper allocates storage for eight entries and registers it.
    let br = unsafe { uring_shim_setup_buf_ring(&mut ring.0, 8, 7, 0, &mut error) };
    assert!(!br.is_null(), "buffer ring setup failed: {error}");
    // SAFETY: The registered buffer ring contains eight entries; payload remains live until free.
    unsafe {
        uring_shim_buf_ring_init(br);
        let mask = uring_shim_buf_ring_mask(8);
        assert_eq!(mask, 7);
        uring_shim_buf_ring_add(br, payload.as_mut_ptr().cast(), 64, 42, mask, 0);
        let entry = br.cast::<io_uring_buf>();
        assert_eq!((*entry).addr, payload.as_mut_ptr() as u64);
        assert_eq!((*entry).len, 64);
        assert_eq!((*entry).bid, 42);
        uring_shim_buf_ring_advance(br, 1);
        let tail = br
            .cast::<u8>()
            .add(uring_shim_offsetof_io_uring_buf_ring_tail())
            .cast::<u16>();
        assert_eq!(tail.read_volatile(), 1);
        let result = uring_shim_free_buf_ring(&mut ring.0, br, 8, 7);
        assert_eq!(result, 0, "buffer ring teardown failed: {result}");
    }
}

#[test]
fn integration_scenario_provided_buffer_helpers_wrap_at_capacity() {
    let mut storage = MaybeUninit::<[io_uring_buf; 8]>::zeroed();
    let br = storage.as_mut_ptr().cast::<io_uring_buf_ring>();
    let mut payload = [0_u8; 64];
    assert!(br.is_aligned());
    // SAFETY: Storage is zeroed and aligned for eight buffer descriptors; no kernel owns it.
    unsafe {
        uring_shim_buf_ring_init(br);
        let mask = uring_shim_buf_ring_mask(8);
        assert_eq!(mask, 7);
        let tail = br
            .cast::<u8>()
            .add(uring_shim_offsetof_io_uring_buf_ring_tail())
            .cast::<u16>();
        assert_eq!(tail.read_volatile(), 0);
        let entries = br.cast::<io_uring_buf>();
        for offset in 0..8 {
            uring_shim_buf_ring_add(
                br,
                payload.as_mut_ptr().cast(),
                64,
                offset as u16,
                mask,
                offset,
            );
        }
        uring_shim_buf_ring_advance(br, 8);
        assert_eq!(tail.read_volatile(), 8);
        uring_shim_buf_ring_add(br, payload.as_mut_ptr().cast(), 32, 42, mask, 0);
        assert_eq!((*entries).addr, payload.as_mut_ptr() as u64);
        assert_eq!((*entries).len, 32);
        assert_eq!((*entries).bid, 42);
        assert_eq!((*entries.add(7)).bid, 7);
        uring_shim_buf_ring_advance(br, 1);
        assert_eq!(tail.read_volatile(), 9);
    }
}
