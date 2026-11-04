//! Classification of all supported multi-completion operation families.
use super::*;
#[test]
fn multishot_opcode_labels_cover_all_kernel_families() {
    use backend::sys::sqe::*;
    for (opcode, ioprio, len, operation_flags) in [
        (IORING_OP_RECVMSG, IORING_RECV_MULTISHOT, 0, 0),
        (IORING_OP_READ_MULTISHOT, 0, 0, 0),
        (IORING_OP_RECV_ZC, 0, 0, 0),
        (IORING_OP_TIMEOUT, 0, 0, 1 << 6),
        (IORING_OP_URING_CMD, 0, 0, 1 << 1),
        (IORING_OP_RECV, IORING_RECV_MULTISHOT, 0, 0),
        (IORING_OP_ACCEPT, 1, 0, 0),
        (IORING_OP_POLL_ADD, 0, 1, 0),
    ] {
        assert_eq!(
            operation_kind(&RawSqe {
                opcode,
                ioprio,
                len,
                operation_flags,
                ..RawSqe::default()
            }),
            OperationKind::Multishot
        );
    }
    assert_eq!(
        operation_kind(&RawSqe {
            opcode: IORING_OP_RECVMSG,
            ..RawSqe::default()
        }),
        OperationKind::Single
    );
}
