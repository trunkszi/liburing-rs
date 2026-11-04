/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * io_uring_enter(2) flags
 */
#define IORING_ENTER_GETEVENTS		(1U << 0)
#define IORING_ENTER_SQ_WAKEUP		(1U << 1)
#define IORING_ENTER_SQ_WAIT		(1U << 2)
#define IORING_ENTER_EXT_ARG		(1U << 3)
#define IORING_ENTER_REGISTERED_RING	(1U << 4)
#define IORING_ENTER_ABS_TIMER		(1U << 5)
#define IORING_ENTER_EXT_ARG_REG	(1U << 6)
#define IORING_ENTER_NO_IOWAIT		(1U << 7)

/*
 * Passed in for io_uring_setup(2). Copied back with updated info on success
 */
struct io_uring_params {
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;
	__u32 sq_thread_cpu;
	__u32 sq_thread_idle;
	__u32 features;
	__u32 wq_fd;
	__u32 resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

/*
 * io_uring_params->features flags
 */
#define IORING_FEAT_SINGLE_MMAP		(1U << 0)
#define IORING_FEAT_NODROP		(1U << 1)
#define IORING_FEAT_SUBMIT_STABLE	(1U << 2)
#define IORING_FEAT_RW_CUR_POS		(1U << 3)
#define IORING_FEAT_CUR_PERSONALITY	(1U << 4)
#define IORING_FEAT_FAST_POLL		(1U << 5)
#define IORING_FEAT_POLL_32BITS 	(1U << 6)
#define IORING_FEAT_SQPOLL_NONFIXED	(1U << 7)
#define IORING_FEAT_EXT_ARG		(1U << 8)
#define IORING_FEAT_NATIVE_WORKERS	(1U << 9)
#define IORING_FEAT_RSRC_TAGS		(1U << 10)
#define IORING_FEAT_CQE_SKIP		(1U << 11)
#define IORING_FEAT_LINKED_FILE		(1U << 12)
#define IORING_FEAT_REG_REG_RING	(1U << 13)
#define IORING_FEAT_RECVSEND_BUNDLE	(1U << 14)
#define IORING_FEAT_MIN_TIMEOUT		(1U << 15)
#define IORING_FEAT_RW_ATTR		(1U << 16)
#define IORING_FEAT_NO_IOWAIT		(1U << 17)

/*
 * io_uring_register(2) opcodes and arguments
 */
enum io_uring_register_op {
	IORING_REGISTER_BUFFERS			= 0,
	IORING_UNREGISTER_BUFFERS		= 1,
	IORING_REGISTER_FILES			= 2,
	IORING_UNREGISTER_FILES			= 3,
	IORING_REGISTER_EVENTFD			= 4,
	IORING_UNREGISTER_EVENTFD		= 5,
	IORING_REGISTER_FILES_UPDATE		= 6,
	IORING_REGISTER_EVENTFD_ASYNC		= 7,
	IORING_REGISTER_PROBE			= 8,
	IORING_REGISTER_PERSONALITY		= 9,
	IORING_UNREGISTER_PERSONALITY		= 10,
	IORING_REGISTER_RESTRICTIONS		= 11,
	IORING_REGISTER_ENABLE_RINGS		= 12,

	/* extended with tagging */
	IORING_REGISTER_FILES2			= 13,
	IORING_REGISTER_FILES_UPDATE2		= 14,
	IORING_REGISTER_BUFFERS2		= 15,
	IORING_REGISTER_BUFFERS_UPDATE		= 16,

	/* set/clear io-wq thread affinities */
	IORING_REGISTER_IOWQ_AFF		= 17,
	IORING_UNREGISTER_IOWQ_AFF		= 18,

	/* set/get max number of io-wq workers */
	IORING_REGISTER_IOWQ_MAX_WORKERS	= 19,

	/* register/unregister io_uring fd with the ring */
	IORING_REGISTER_RING_FDS		= 20,
	IORING_UNREGISTER_RING_FDS		= 21,

	/* register ring based provide buffer group */
	IORING_REGISTER_PBUF_RING		= 22,
	IORING_UNREGISTER_PBUF_RING		= 23,

	/* sync cancelation API */
	IORING_REGISTER_SYNC_CANCEL		= 24,

	/* register a range of fixed file slots for automatic slot allocation */
	IORING_REGISTER_FILE_ALLOC_RANGE	= 25,

	/* return status information for a buffer group */
	IORING_REGISTER_PBUF_STATUS		= 26,

	/* set/clear busy poll settings */
	IORING_REGISTER_NAPI			= 27,
	IORING_UNREGISTER_NAPI			= 28,

	IORING_REGISTER_CLOCK			= 29,

	/* clone registered buffers from source ring to current ring */
	IORING_REGISTER_CLONE_BUFFERS		= 30,

	/* send MSG_RING without having a ring */
	IORING_REGISTER_SEND_MSG_RING		= 31,

	/* register a netdev hw rx queue for zerocopy */
	IORING_REGISTER_ZCRX_IFQ		= 32,

	/* resize CQ ring */
	IORING_REGISTER_RESIZE_RINGS		= 33,

	IORING_REGISTER_MEM_REGION		= 34,

	/* query various aspects of io_uring, see linux/io_uring/query.h */
	IORING_REGISTER_QUERY			= 35,

	/* auxiliary zcrx configuration, see enum zcrx_ctrl_op */
	IORING_REGISTER_ZCRX_CTRL		= 36,

	/* register bpf filtering programs */
	IORING_REGISTER_BPF_FILTER		= 37,

	/* this goes last */
	IORING_REGISTER_LAST,

	/* flag added to the opcode to use a registered ring fd */
	IORING_REGISTER_USE_REGISTERED_RING	= 1U << 31
};

/* io-wq worker categories */
enum io_wq_type {
	IO_WQ_BOUND,
	IO_WQ_UNBOUND,
};

/* deprecated, see struct io_uring_rsrc_update */
struct io_uring_files_update {
	__u32 offset;
	__u32 resv;
	__aligned_u64 /* __s32 * */ fds;
};

enum {
	/* initialise with user provided memory pointed by user_addr */
	IORING_MEM_REGION_TYPE_USER		= 1,
};

struct io_uring_region_desc {
	__u64 user_addr;
	__u64 size;
	__u32 flags;
	__u32 id;
	__u64 mmap_offset;
	__u64 __resv[4];
};

enum {
	/* expose the region as registered wait arguments */
	IORING_MEM_REGION_REG_WAIT_ARG		= 1,
};

struct io_uring_mem_region_reg {
	__u64 region_uptr; /* struct io_uring_region_desc * */
	__u64 flags;
	__u64 __resv[2];
};

/*
 * Register a fully sparse file space, rather than pass in an array of all
 * -1 file descriptors.
 */
#define IORING_RSRC_REGISTER_SPARSE	(1U << 0)

struct io_uring_rsrc_register {
	__u32 nr;
	__u32 flags;
	__u64 resv2;
	__aligned_u64 data;
	__aligned_u64 tags;
};

struct io_uring_rsrc_update {
	__u32 offset;
	__u32 resv;
	__aligned_u64 data;
};

struct io_uring_rsrc_update2 {
	__u32 offset;
	__u32 resv;
	__aligned_u64 data;
	__aligned_u64 tags;
	__u32 nr;
	__u32 resv2;
};

/* Skip updating fd indexes set to this value in the fd table */
#define IORING_REGISTER_FILES_SKIP	(-2)

#define IO_URING_OP_SUPPORTED	(1U << 0)

struct io_uring_probe_op {
	__u8 op;
	__u8 resv;
	__u16 flags;	/* IO_URING_OP_* flags */
	__u32 resv2;
};

struct io_uring_probe {
	__u8 last_op;	/* last opcode supported */
	__u8 ops_len;	/* length of ops[] array below */
	__u16 resv;
	__u32 resv2[3];
	struct io_uring_probe_op ops[];
};

struct io_uring_restriction {
	__u16 opcode;
	union {
		__u8 register_op; /* IORING_RESTRICTION_REGISTER_OP */
		__u8 sqe_op;      /* IORING_RESTRICTION_SQE_OP */
		__u8 sqe_flags;   /* IORING_RESTRICTION_SQE_FLAGS_* */
	};
	__u8 resv;
	__u32 resv2[3];
};

struct io_uring_task_restriction {
	__u16 flags;
	__u16 nr_res;
	__u32 resv[3];
	__DECLARE_FLEX_ARRAY(struct io_uring_restriction, restrictions);
};

struct io_uring_clock_register {
	__u32	clockid;
	__u32	__resv[3];
};

enum {
	IORING_REGISTER_SRC_REGISTERED	= (1U << 0),
	IORING_REGISTER_DST_REPLACE	= (1U << 1),
};

struct io_uring_clone_buffers {
	__u32	src_fd;
	__u32	flags;
	__u32	src_off;
	__u32	dst_off;
	__u32	nr;
	__u32	pad[3];
};

struct io_uring_buf {
	__u64	addr;
	__u32	len;
	__u16	bid;
	__u16	resv;
};

struct io_uring_buf_ring {
	union {
		/*
		 * To avoid spilling into more pages than we need to, the
		 * ring tail is overlaid with the io_uring_buf->resv field.
		 */
		struct {
			__u64	resv1;
			__u32	resv2;
			__u16	resv3;
			__u16	tail;
		};
		__DECLARE_FLEX_ARRAY(struct io_uring_buf, bufs);
	};
};

/*
 * Flags for IORING_REGISTER_PBUF_RING.
 *
 * IOU_PBUF_RING_MMAP:	If set, kernel will allocate the memory for the ring.
 *			The application must not set a ring_addr in struct
 *			io_uring_buf_reg, instead it must subsequently call
 *			mmap(2) with the offset set as:
 *			IORING_OFF_PBUF_RING | (bgid << IORING_OFF_PBUF_SHIFT)
 *			to get a virtual mapping for the ring.
 * IOU_PBUF_RING_INC:	If set, buffers consumed from this buffer ring can be
 *			consumed incrementally. Normally one (or more) buffers
 *			are fully consumed. With incremental consumptions, it's
 *			feasible to register big ranges of buffers, and each
 *			use of it will consume only as much as it needs. This
 *			requires that both the kernel and application keep
 *			track of where the current read/recv index is at.
 */
enum io_uring_register_pbuf_ring_flags {
	IOU_PBUF_RING_MMAP	= 1,
	IOU_PBUF_RING_INC	= 2,
};

/* argument for IORING_(UN)REGISTER_PBUF_RING */
struct io_uring_buf_reg {
	__u64	ring_addr;
	__u32	ring_entries;
	__u16	bgid;
	__u16	flags;
	__u32	min_left;
	__u32	resv[5];
};

/* argument for IORING_REGISTER_PBUF_STATUS */
struct io_uring_buf_status {
	__u32	buf_group;	/* input */
	__u32	head;		/* output */
	__u32	resv[8];
};

enum io_uring_napi_op {
	/* register/ungister backward compatible opcode */
	IO_URING_NAPI_REGISTER_OP = 0,

	/* opcodes to update napi_list when static tracking is used */
	IO_URING_NAPI_STATIC_ADD_ID = 1,
	IO_URING_NAPI_STATIC_DEL_ID = 2
};

enum io_uring_napi_tracking_strategy {
	/* value must be 0 for backward compatibility */
	IO_URING_NAPI_TRACKING_DYNAMIC = 0,
	IO_URING_NAPI_TRACKING_STATIC = 1,
	IO_URING_NAPI_TRACKING_INACTIVE = 255
};

/* argument for IORING_(UN)REGISTER_NAPI */
struct io_uring_napi {
	__u32	busy_poll_to;
	__u8	prefer_busy_poll;

	/* a io_uring_napi_op value */
	__u8	opcode;
	__u8	pad[2];

	/*
	 * for IO_URING_NAPI_REGISTER_OP, it is a
	 * io_uring_napi_tracking_strategy value.
	 *
	 * for IO_URING_NAPI_STATIC_ADD_ID/IO_URING_NAPI_STATIC_DEL_ID
	 * it is the napi id to add/del from napi_list.
	 */
	__u32	op_param;
	__u32	resv;
};

/*
 * io_uring_restriction->opcode values
 */
enum io_uring_register_restriction_op {
	/* Allow an io_uring_register(2) opcode */
	IORING_RESTRICTION_REGISTER_OP		= 0,

	/* Allow an sqe opcode */
	IORING_RESTRICTION_SQE_OP		= 1,

	/* Allow sqe flags */
	IORING_RESTRICTION_SQE_FLAGS_ALLOWED	= 2,

	/* Require sqe flags (these flags must be set on each submission) */
	IORING_RESTRICTION_SQE_FLAGS_REQUIRED	= 3,

	IORING_RESTRICTION_LAST
};

enum {
	IORING_REG_WAIT_TS		= (1U << 0),
};

/*
 * Argument for io_uring_enter(2) with
 * IORING_GETEVENTS | IORING_ENTER_EXT_ARG_REG set, where the actual argument
 * is an index into a previously registered fixed wait region described by
 * the below structure.
 */
struct io_uring_reg_wait {
	struct __kernel_timespec	ts;
	__u32				min_wait_usec;
	__u32				flags;
	__u64				sigmask;
	__u32				sigmask_sz;
	__u32				pad[3];
	__u64				pad2[2];
};

/*
 * Argument for io_uring_enter(2) with IORING_GETEVENTS | IORING_ENTER_EXT_ARG
 */
struct io_uring_getevents_arg {
	__u64	sigmask;
	__u32	sigmask_sz;
	__u32	min_wait_usec;
	__u64	ts;
};

/*
 * Argument for IORING_REGISTER_SYNC_CANCEL
 */
struct io_uring_sync_cancel_reg {
	__u64				addr;
	__s32				fd;
	__u32				flags;
	struct __kernel_timespec	timeout;
	__u8				opcode;
	__u8				pad[7];
	__u64				pad2[3];
};

/*
 * Argument for IORING_REGISTER_FILE_ALLOC_RANGE
 * The range is specified as [off, off + len)
 */
struct io_uring_file_index_range {
	__u32	off;
	__u32	len;
	__u64	resv;
};

struct io_uring_recvmsg_out {
	__u32 namelen;
	__u32 controllen;
	__u32 payloadlen;
	__u32 flags;
};

/*
 * Argument for IORING_OP_URING_CMD when file is a socket
 */
enum io_uring_socket_op {
	SOCKET_URING_OP_SIOCINQ		= 0,
	SOCKET_URING_OP_SIOCOUTQ,
	SOCKET_URING_OP_GETSOCKOPT,
	SOCKET_URING_OP_SETSOCKOPT,
	SOCKET_URING_OP_TX_TIMESTAMP,
	SOCKET_URING_OP_GETSOCKNAME,
};

/*
 * SOCKET_URING_OP_TX_TIMESTAMP definitions
 */

#define IORING_TIMESTAMP_HW_SHIFT	16
/* The cqe->flags bit from which the timestamp type is stored */
#define IORING_TIMESTAMP_TYPE_SHIFT	(IORING_TIMESTAMP_HW_SHIFT + 1)
/* The cqe->flags flag signifying whether it's a hardware timestamp */
#define IORING_CQE_F_TSTAMP_HW		((__u32)1 << IORING_TIMESTAMP_HW_SHIFT)

struct io_timespec {
	__u64		tv_sec;
	__u64		tv_nsec;
};

/* Zero copy receive refill queue entry */
struct io_uring_zcrx_rqe {
	__u64	off;
	__u32	len;
	__u32	__pad;
};

struct io_uring_zcrx_cqe {
	__u64	off;
	__u64	__pad;
};

/* The bit from which area id is encoded into offsets */
#define IORING_ZCRX_AREA_SHIFT	48
#define IORING_ZCRX_AREA_MASK	(~(((__u64)1 << IORING_ZCRX_AREA_SHIFT) - 1))

struct io_uring_zcrx_offsets {
	__u32	head;
	__u32	tail;
	__u32	rqes;
	__u32	__resv2;
	__u64	__resv[2];
};

enum io_uring_zcrx_area_flags {
	IORING_ZCRX_AREA_DMABUF		= 1,
};

struct io_uring_zcrx_area_reg {
	__u64	addr;
	__u64	len;
	__u64	rq_area_token;
	__u32	flags;
	__u32	dmabuf_fd;
	__u64	__resv2[2];
};

enum zcrx_reg_flags {
	ZCRX_REG_IMPORT	= 1,
};

enum zcrx_features {
	/*
	 * The user can ask for the desired rx page size by passing the
	 * value in struct io_uring_zcrx_ifq_reg::rx_buf_len.
	 */
	ZCRX_FEATURE_RX_PAGE_SIZE	= 1 << 0,
};

/*
 * Argument for IORING_REGISTER_ZCRX_IFQ
 */
struct io_uring_zcrx_ifq_reg {
	__u32	if_idx;
	__u32	if_rxq;
	__u32	rq_entries;
	__u32	flags;

	__u64	area_ptr; /* pointer to struct io_uring_zcrx_area_reg */
	__u64	region_ptr; /* struct io_uring_region_desc * */

	struct io_uring_zcrx_offsets offsets;
	__u32	zcrx_id;
	__u32	rx_buf_len;
	__u64	__resv[3];
};

enum zcrx_ctrl_op {
	ZCRX_CTRL_FLUSH_RQ,
	ZCRX_CTRL_EXPORT,

	__ZCRX_CTRL_LAST,
};

struct zcrx_ctrl_flush_rq {
	__u64		__resv[6];
};

struct zcrx_ctrl_export {
	__u32		zcrx_fd;
	__u32 		__resv1[11];
};

struct zcrx_ctrl {
	__u32	zcrx_id;
	__u32	op; /* see enum zcrx_ctrl_op */
	__u64	__resv[2];

	union {
		struct zcrx_ctrl_export		zc_export;
		struct zcrx_ctrl_flush_rq	zc_flush;
	};
};

#ifdef __cplusplus
}
#endif

#endif
