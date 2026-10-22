/* Each wrapper retains the corresponding upstream liburing contract. */
#include "uring_shim.h"

int uring_shim_queue_init_params(
    unsigned entries,
    struct io_uring *ring,
    struct io_uring_params *params)
{
    return io_uring_queue_init_params(entries, ring, params);
}

void uring_shim_queue_exit(struct io_uring *ring)
{
    io_uring_queue_exit(ring);
}

struct io_uring_probe * uring_shim_get_probe_ring(struct io_uring *ring)
{
    return io_uring_get_probe_ring(ring);
}

void uring_shim_free_probe(struct io_uring_probe *probe)
{
    io_uring_free_probe(probe);
}

int uring_shim_opcode_supported(const struct io_uring_probe *probe, int op)
{
    return io_uring_opcode_supported(probe, op);
}

struct io_uring_sqe * uring_shim_get_sqe(struct io_uring *ring)
{
    return io_uring_get_sqe(ring);
}

unsigned uring_shim_sq_space_left(const struct io_uring *ring)
{
    return io_uring_sq_space_left(ring);
}

unsigned uring_shim_sq_ready(const struct io_uring *ring)
{
    return io_uring_sq_ready(ring);
}

unsigned uring_shim_cq_ready(const struct io_uring *ring)
{
    return io_uring_cq_ready(ring);
}

int uring_shim_submit(struct io_uring *ring)
{
    return io_uring_submit(ring);
}

int uring_shim_submit_and_wait_timeout(
    struct io_uring *ring,
    struct io_uring_cqe **cqe_ptr,
    unsigned wait_nr,
    struct __kernel_timespec *ts,
    sigset_t *sigmask)
{
    return io_uring_submit_and_wait_timeout(ring, cqe_ptr, wait_nr, ts, sigmask);
}

int uring_shim_peek_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_ptr)
{
    return io_uring_peek_cqe(ring, cqe_ptr);
}

int uring_shim_wait_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_ptr)
{
    return io_uring_wait_cqe(ring, cqe_ptr);
}

int uring_shim_wait_cqe_timeout(
    struct io_uring *ring,
    struct io_uring_cqe **cqe_ptr,
    struct __kernel_timespec *ts)
{
    return io_uring_wait_cqe_timeout(ring, cqe_ptr, ts);
}

void uring_shim_cqe_seen(struct io_uring *ring, struct io_uring_cqe *cqe)
{
    io_uring_cqe_seen(ring, cqe);
}

void uring_shim_cq_advance(struct io_uring *ring, unsigned nr)
{
    io_uring_cq_advance(ring, nr);
}

void uring_shim_sqe_set_data64(struct io_uring_sqe *sqe, uint64_t data)
{
    io_uring_sqe_set_data64(sqe, data);
}

uint64_t uring_shim_cqe_get_data64(const struct io_uring_cqe *cqe)
{
    return io_uring_cqe_get_data64(cqe);
}

void uring_shim_sqe_set_flags(struct io_uring_sqe *sqe, unsigned flags)
{
    io_uring_sqe_set_flags(sqe, flags);
}

void uring_shim_sqe_set_buf_group(struct io_uring_sqe *sqe, uint16_t group)
{
    sqe->buf_group = group;
}

void uring_shim_prep_nop(struct io_uring_sqe *sqe)
{
    io_uring_prep_nop(sqe);
}

void uring_shim_prep_timeout(
    struct io_uring_sqe *sqe,
    const struct __kernel_timespec *ts,
    unsigned count,
    unsigned flags)
{
    io_uring_prep_timeout(sqe, ts, count, flags);
}

void uring_shim_prep_timeout_remove(struct io_uring_sqe *sqe, uint64_t user_data, unsigned flags)
{
    io_uring_prep_timeout_remove(sqe, user_data, flags);
}

void uring_shim_prep_timeout_update(
    struct io_uring_sqe *sqe,
    struct __kernel_timespec *ts,
    uint64_t user_data,
    unsigned flags)
{
    io_uring_prep_timeout_update(sqe, ts, user_data, flags);
}

void uring_shim_prep_cancel64(struct io_uring_sqe *sqe, uint64_t user_data, int flags)
{
    io_uring_prep_cancel64(sqe, user_data, flags);
}

void uring_shim_prep_cancel_fd(struct io_uring_sqe *sqe, int fd, unsigned flags)
{
    io_uring_prep_cancel_fd(sqe, fd, flags);
}

void uring_shim_prep_poll_add(struct io_uring_sqe *sqe, int fd, unsigned poll_mask)
{
    io_uring_prep_poll_add(sqe, fd, poll_mask);
}

void uring_shim_prep_poll_multishot(struct io_uring_sqe *sqe, int fd, unsigned poll_mask)
{
    io_uring_prep_poll_multishot(sqe, fd, poll_mask);
}

void uring_shim_prep_poll_remove(struct io_uring_sqe *sqe, uint64_t user_data)
{
    io_uring_prep_poll_remove(sqe, user_data);
}

void uring_shim_prep_read(
    struct io_uring_sqe *sqe,
    int fd,
    void *buf,
    unsigned nbytes,
    uint64_t offset)
{
    io_uring_prep_read(sqe, fd, buf, nbytes, offset);
}

void uring_shim_prep_write(
    struct io_uring_sqe *sqe,
    int fd,
    const void *buf,
    unsigned nbytes,
    uint64_t offset)
{
    io_uring_prep_write(sqe, fd, buf, nbytes, offset);
}

void uring_shim_prep_read_fixed(
    struct io_uring_sqe *sqe,
    int fd,
    void *buf,
    unsigned nbytes,
    uint64_t offset,
    int buf_index)
{
    io_uring_prep_read_fixed(sqe, fd, buf, nbytes, offset, buf_index);
}

void uring_shim_prep_write_fixed(
    struct io_uring_sqe *sqe,
    int fd,
    const void *buf,
    unsigned nbytes,
    uint64_t offset,
    int buf_index)
{
    io_uring_prep_write_fixed(sqe, fd, buf, nbytes, offset, buf_index);
}

void uring_shim_prep_recv(struct io_uring_sqe *sqe, int sockfd, void *buf, size_t len, int flags)
{
    io_uring_prep_recv(sqe, sockfd, buf, len, flags);
}

void uring_shim_prep_recv_multishot(
    struct io_uring_sqe *sqe,
    int sockfd,
    void *buf,
    size_t len,
    int flags)
{
    io_uring_prep_recv_multishot(sqe, sockfd, buf, len, flags);
}

void uring_shim_prep_send(
    struct io_uring_sqe *sqe,
    int sockfd,
    const void *buf,
    size_t len,
    int flags)
{
    io_uring_prep_send(sqe, sockfd, buf, len, flags);
}

void uring_shim_prep_send_zc(
    struct io_uring_sqe *sqe,
    int sockfd,
    const void *buf,
    size_t len,
    int flags,
    unsigned zc_flags)
{
    io_uring_prep_send_zc(sqe, sockfd, buf, len, flags, zc_flags);
}

void uring_shim_prep_sendmsg(
    struct io_uring_sqe *sqe,
    int fd,
    const struct msghdr *msg,
    unsigned flags)
{
    io_uring_prep_sendmsg(sqe, fd, msg, flags);
}

void uring_shim_prep_recvmsg(struct io_uring_sqe *sqe, int fd, struct msghdr *msg, unsigned flags)
{
    io_uring_prep_recvmsg(sqe, fd, msg, flags);
}

void uring_shim_prep_connect(
    struct io_uring_sqe *sqe,
    int fd,
    const struct sockaddr *addr,
    socklen_t addrlen)
{
    io_uring_prep_connect(sqe, fd, addr, addrlen);
}

void uring_shim_prep_accept(
    struct io_uring_sqe *sqe,
    int fd,
    struct sockaddr *addr,
    socklen_t *addrlen,
    int flags)
{
    io_uring_prep_accept(sqe, fd, addr, addrlen, flags);
}

void uring_shim_prep_multishot_accept(
    struct io_uring_sqe *sqe,
    int fd,
    struct sockaddr *addr,
    socklen_t *addrlen,
    int flags)
{
    io_uring_prep_multishot_accept(sqe, fd, addr, addrlen, flags);
}

void uring_shim_prep_close(struct io_uring_sqe *sqe, int fd)
{
    io_uring_prep_close(sqe, fd);
}

void uring_shim_prep_close_direct(struct io_uring_sqe *sqe, unsigned file_index)
{
    io_uring_prep_close_direct(sqe, file_index);
}

int uring_shim_register_files(struct io_uring *ring, const int *files, unsigned nr_files)
{
    return io_uring_register_files(ring, files, nr_files);
}

int uring_shim_register_files_sparse(struct io_uring *ring, unsigned nr_files)
{
    return io_uring_register_files_sparse(ring, nr_files);
}

int uring_shim_unregister_files(struct io_uring *ring)
{
    return io_uring_unregister_files(ring);
}

int uring_shim_register_files_update(
    struct io_uring *ring,
    unsigned off,
    const int *files,
    unsigned nr_files)
{
    return io_uring_register_files_update(ring, off, files, nr_files);
}

int uring_shim_register_buffers(
    struct io_uring *ring,
    const struct iovec *iovecs,
    unsigned nr_iovecs)
{
    return io_uring_register_buffers(ring, iovecs, nr_iovecs);
}

int uring_shim_unregister_buffers(struct io_uring *ring)
{
    return io_uring_unregister_buffers(ring);
}

struct io_uring_buf_ring * uring_shim_setup_buf_ring(
    struct io_uring *ring,
    unsigned nentries,
    int bgid,
    unsigned flags,
    int *err)
{
    return io_uring_setup_buf_ring(ring, nentries, bgid, flags, err);
}

int uring_shim_free_buf_ring(
    struct io_uring *ring,
    struct io_uring_buf_ring *br,
    unsigned nentries,
    int bgid)
{
    return io_uring_free_buf_ring(ring, br, nentries, bgid);
}

void uring_shim_buf_ring_init(struct io_uring_buf_ring *br)
{
    io_uring_buf_ring_init(br);
}

void uring_shim_buf_ring_add(
    struct io_uring_buf_ring *br,
    void *addr,
    unsigned len,
    uint16_t bid,
    int mask,
    int buf_offset)
{
    io_uring_buf_ring_add(br, addr, len, bid, mask, buf_offset);
}

void uring_shim_buf_ring_advance(struct io_uring_buf_ring *br, int count)
{
    io_uring_buf_ring_advance(br, count);
}

int uring_shim_buf_ring_mask(uint32_t ring_entries)
{
    return io_uring_buf_ring_mask(ring_entries);
}

size_t uring_shim_sizeof_io_uring(void)
{
    return sizeof(struct io_uring);
}

size_t uring_shim_alignof_io_uring(void)
{
    return _Alignof(struct io_uring);
}

size_t uring_shim_sizeof_io_uring_params(void)
{
    return sizeof(struct io_uring_params);
}

size_t uring_shim_alignof_io_uring_params(void)
{
    return _Alignof(struct io_uring_params);
}

size_t uring_shim_sizeof_io_uring_sqe(void)
{
    return sizeof(struct io_uring_sqe);
}

size_t uring_shim_alignof_io_uring_sqe(void)
{
    return _Alignof(struct io_uring_sqe);
}

size_t uring_shim_sizeof_io_uring_cqe(void)
{
    return sizeof(struct io_uring_cqe);
}

size_t uring_shim_alignof_io_uring_cqe(void)
{
    return _Alignof(struct io_uring_cqe);
}

size_t uring_shim_sizeof_io_uring_buf_ring(void)
{
    return sizeof(struct io_uring_buf_ring);
}

size_t uring_shim_alignof_io_uring_buf_ring(void)
{
    return _Alignof(struct io_uring_buf_ring);
}

size_t uring_shim_sizeof_io_uring_buf(void)
{
    return sizeof(struct io_uring_buf);
}

size_t uring_shim_alignof_io_uring_buf(void)
{
    return _Alignof(struct io_uring_buf);
}

size_t uring_shim_sizeof_kernel_timespec(void)
{
    return sizeof(struct __kernel_timespec);
}

size_t uring_shim_alignof_kernel_timespec(void)
{
    return _Alignof(struct __kernel_timespec);
}

size_t uring_shim_offsetof_io_uring_sqe_user_data(void)
{
    return offsetof(struct io_uring_sqe, user_data);
}

size_t uring_shim_offsetof_io_uring_cqe_user_data(void)
{
    return offsetof(struct io_uring_cqe, user_data);
}

size_t uring_shim_offsetof_io_uring_cqe_res(void)
{
    return offsetof(struct io_uring_cqe, res);
}

size_t uring_shim_offsetof_io_uring_cqe_flags(void)
{
    return offsetof(struct io_uring_cqe, flags);
}

size_t uring_shim_offsetof_io_uring_buf_addr(void)
{
    return offsetof(struct io_uring_buf, addr);
}

size_t uring_shim_offsetof_io_uring_buf_len(void)
{
    return offsetof(struct io_uring_buf, len);
}

size_t uring_shim_offsetof_io_uring_buf_bid(void)
{
    return offsetof(struct io_uring_buf, bid);
}

size_t uring_shim_offsetof_io_uring_params_features(void)
{
    return offsetof(struct io_uring_params, features);
}

size_t uring_shim_offsetof_io_uring_buf_ring_tail(void)
{
    return offsetof(struct io_uring_buf_ring, tail);
}

size_t uring_shim_offsetof_kernel_timespec_tv_nsec(void)
{
    return offsetof(struct __kernel_timespec, tv_nsec);
}
