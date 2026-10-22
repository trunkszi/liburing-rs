/* Public wrappers for liburing static inline and ring operations. */
#ifndef LIBURING_RS_URING_SHIM_H
#define LIBURING_RS_URING_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <liburing.h>

#ifdef __cplusplus
extern "C" {
#endif

int uring_shim_queue_init_params(
    unsigned entries,
    struct io_uring *ring,
    struct io_uring_params *params);

void uring_shim_queue_exit(struct io_uring *ring);

struct io_uring_probe * uring_shim_get_probe_ring(struct io_uring *ring);

void uring_shim_free_probe(struct io_uring_probe *probe);

int uring_shim_opcode_supported(const struct io_uring_probe *probe, int op);

struct io_uring_sqe * uring_shim_get_sqe(struct io_uring *ring);

unsigned uring_shim_sq_space_left(const struct io_uring *ring);

unsigned uring_shim_sq_ready(const struct io_uring *ring);

unsigned uring_shim_cq_ready(const struct io_uring *ring);

int uring_shim_submit(struct io_uring *ring);

int uring_shim_submit_and_wait_timeout(
    struct io_uring *ring,
    struct io_uring_cqe **cqe_ptr,
    unsigned wait_nr,
    struct __kernel_timespec *ts,
    sigset_t *sigmask);

int uring_shim_peek_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_ptr);

int uring_shim_wait_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_ptr);

int uring_shim_wait_cqe_timeout(
    struct io_uring *ring,
    struct io_uring_cqe **cqe_ptr,
    struct __kernel_timespec *ts);

void uring_shim_cqe_seen(struct io_uring *ring, struct io_uring_cqe *cqe);

void uring_shim_cq_advance(struct io_uring *ring, unsigned nr);

void uring_shim_sqe_set_data64(struct io_uring_sqe *sqe, uint64_t data);

uint64_t uring_shim_cqe_get_data64(const struct io_uring_cqe *cqe);

void uring_shim_sqe_set_flags(struct io_uring_sqe *sqe, unsigned flags);

void uring_shim_sqe_set_buf_group(struct io_uring_sqe *sqe, uint16_t group);

void uring_shim_prep_nop(struct io_uring_sqe *sqe);

void uring_shim_prep_timeout(
    struct io_uring_sqe *sqe,
    const struct __kernel_timespec *ts,
    unsigned count,
    unsigned flags);

void uring_shim_prep_timeout_remove(struct io_uring_sqe *sqe, uint64_t user_data, unsigned flags);

void uring_shim_prep_timeout_update(
    struct io_uring_sqe *sqe,
    struct __kernel_timespec *ts,
    uint64_t user_data,
    unsigned flags);

void uring_shim_prep_cancel64(struct io_uring_sqe *sqe, uint64_t user_data, int flags);

void uring_shim_prep_cancel_fd(struct io_uring_sqe *sqe, int fd, unsigned flags);

void uring_shim_prep_poll_add(struct io_uring_sqe *sqe, int fd, unsigned poll_mask);

void uring_shim_prep_poll_multishot(struct io_uring_sqe *sqe, int fd, unsigned poll_mask);

void uring_shim_prep_poll_remove(struct io_uring_sqe *sqe, uint64_t user_data);

void uring_shim_prep_read(
    struct io_uring_sqe *sqe,
    int fd,
    void *buf,
    unsigned nbytes,
    uint64_t offset);

void uring_shim_prep_write(
    struct io_uring_sqe *sqe,
    int fd,
    const void *buf,
    unsigned nbytes,
    uint64_t offset);

void uring_shim_prep_read_fixed(
    struct io_uring_sqe *sqe,
    int fd,
    void *buf,
    unsigned nbytes,
    uint64_t offset,
    int buf_index);

void uring_shim_prep_write_fixed(
    struct io_uring_sqe *sqe,
    int fd,
    const void *buf,
    unsigned nbytes,
    uint64_t offset,
    int buf_index);

void uring_shim_prep_recv(struct io_uring_sqe *sqe, int sockfd, void *buf, size_t len, int flags);

void uring_shim_prep_recv_multishot(
    struct io_uring_sqe *sqe,
    int sockfd,
    void *buf,
    size_t len,
    int flags);

void uring_shim_prep_send(
    struct io_uring_sqe *sqe,
    int sockfd,
    const void *buf,
    size_t len,
    int flags);

void uring_shim_prep_send_zc(
    struct io_uring_sqe *sqe,
    int sockfd,
    const void *buf,
    size_t len,
    int flags,
    unsigned zc_flags);

void uring_shim_prep_sendmsg(
    struct io_uring_sqe *sqe,
    int fd,
    const struct msghdr *msg,
    unsigned flags);

void uring_shim_prep_recvmsg(struct io_uring_sqe *sqe, int fd, struct msghdr *msg, unsigned flags);

void uring_shim_prep_connect(
    struct io_uring_sqe *sqe,
    int fd,
    const struct sockaddr *addr,
    socklen_t addrlen);

void uring_shim_prep_accept(
    struct io_uring_sqe *sqe,
    int fd,
    struct sockaddr *addr,
    socklen_t *addrlen,
    int flags);

void uring_shim_prep_multishot_accept(
    struct io_uring_sqe *sqe,
    int fd,
    struct sockaddr *addr,
    socklen_t *addrlen,
    int flags);

void uring_shim_prep_close(struct io_uring_sqe *sqe, int fd);

void uring_shim_prep_close_direct(struct io_uring_sqe *sqe, unsigned file_index);

int uring_shim_register_files(struct io_uring *ring, const int *files, unsigned nr_files);

int uring_shim_register_files_sparse(struct io_uring *ring, unsigned nr_files);

int uring_shim_unregister_files(struct io_uring *ring);

int uring_shim_register_files_update(
    struct io_uring *ring,
    unsigned off,
    const int *files,
    unsigned nr_files);

int uring_shim_register_buffers(
    struct io_uring *ring,
    const struct iovec *iovecs,
    unsigned nr_iovecs);

int uring_shim_unregister_buffers(struct io_uring *ring);

struct io_uring_buf_ring * uring_shim_setup_buf_ring(
    struct io_uring *ring,
    unsigned nentries,
    int bgid,
    unsigned flags,
    int *err);

int uring_shim_free_buf_ring(
    struct io_uring *ring,
    struct io_uring_buf_ring *br,
    unsigned nentries,
    int bgid);

void uring_shim_buf_ring_init(struct io_uring_buf_ring *br);

void uring_shim_buf_ring_add(
    struct io_uring_buf_ring *br,
    void *addr,
    unsigned len,
    uint16_t bid,
    int mask,
    int buf_offset);

void uring_shim_buf_ring_advance(struct io_uring_buf_ring *br, int count);

int uring_shim_buf_ring_mask(uint32_t ring_entries);

size_t uring_shim_sizeof_io_uring(void);
size_t uring_shim_alignof_io_uring(void);
size_t uring_shim_sizeof_io_uring_params(void);
size_t uring_shim_alignof_io_uring_params(void);
size_t uring_shim_sizeof_io_uring_sqe(void);
size_t uring_shim_alignof_io_uring_sqe(void);
size_t uring_shim_sizeof_io_uring_cqe(void);
size_t uring_shim_alignof_io_uring_cqe(void);
size_t uring_shim_sizeof_io_uring_buf_ring(void);
size_t uring_shim_alignof_io_uring_buf_ring(void);
size_t uring_shim_sizeof_io_uring_buf(void);
size_t uring_shim_alignof_io_uring_buf(void);
size_t uring_shim_sizeof_kernel_timespec(void);
size_t uring_shim_alignof_kernel_timespec(void);

size_t uring_shim_offsetof_io_uring_sqe_user_data(void);
size_t uring_shim_offsetof_io_uring_cqe_user_data(void);
size_t uring_shim_offsetof_io_uring_cqe_res(void);
size_t uring_shim_offsetof_io_uring_cqe_flags(void);
size_t uring_shim_offsetof_io_uring_buf_addr(void);
size_t uring_shim_offsetof_io_uring_buf_len(void);
size_t uring_shim_offsetof_io_uring_buf_bid(void);
size_t uring_shim_offsetof_io_uring_params_features(void);
size_t uring_shim_offsetof_io_uring_buf_ring_tail(void);
size_t uring_shim_offsetof_kernel_timespec_tv_nsec(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBURING_RS_URING_SHIM_H */
