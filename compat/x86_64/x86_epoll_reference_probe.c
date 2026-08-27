/* Pinned-musl Linux/x86-64 epoll ABI and behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <unistd.h>

/* x86-64 Linux keeps epoll_event packed despite its 64-bit data union. */
_Static_assert(sizeof(struct epoll_event) == 12, "x86 epoll_event size");
_Static_assert(_Alignof(struct epoll_event) == 1, "x86 epoll_event alignment");
_Static_assert(offsetof(struct epoll_event, events) == 0,
               "x86 epoll_event events offset");
_Static_assert(offsetof(struct epoll_event, data) == 4,
               "x86 epoll_event data offset");

_Static_assert(SYS_epoll_create1 == 291, "x86 epoll_create1 syscall number");
_Static_assert(SYS_epoll_ctl == 233, "x86 epoll_ctl syscall number");
_Static_assert(SYS_epoll_pwait == 281, "x86 epoll_pwait syscall number");

_Static_assert(EPOLL_CLOEXEC == 0x00080000, "x86 EPOLL_CLOEXEC");
_Static_assert(EPOLL_NONBLOCK == 0x00000800, "x86 EPOLL_NONBLOCK");
_Static_assert(EPOLLIN == 0x0001, "x86 EPOLLIN");
_Static_assert(EPOLLPRI == 0x0002, "x86 EPOLLPRI");
_Static_assert(EPOLLOUT == 0x0004, "x86 EPOLLOUT");
_Static_assert(EPOLLERR == 0x0008, "x86 EPOLLERR");
_Static_assert(EPOLLHUP == 0x0010, "x86 EPOLLHUP");
_Static_assert(EPOLLNVAL == 0x0020, "x86 EPOLLNVAL");
_Static_assert(EPOLLRDNORM == 0x0040, "x86 EPOLLRDNORM");
_Static_assert(EPOLLRDBAND == 0x0080, "x86 EPOLLRDBAND");
_Static_assert(EPOLLWRNORM == 0x0100, "x86 EPOLLWRNORM");
_Static_assert(EPOLLWRBAND == 0x0200, "x86 EPOLLWRBAND");
_Static_assert(EPOLLMSG == 0x0400, "x86 EPOLLMSG");
_Static_assert(EPOLLRDHUP == 0x2000, "x86 EPOLLRDHUP");
_Static_assert(EPOLLEXCLUSIVE == (1U << 28), "x86 EPOLLEXCLUSIVE");
_Static_assert(EPOLLWAKEUP == (1U << 29), "x86 EPOLLWAKEUP");
_Static_assert(EPOLLONESHOT == (1U << 30), "x86 EPOLLONESHOT");
_Static_assert(EPOLLET == (1U << 31), "x86 EPOLLET");
_Static_assert(EPOLL_CTL_ADD == 1, "x86 EPOLL_CTL_ADD");
_Static_assert(EPOLL_CTL_DEL == 2, "x86 EPOLL_CTL_DEL");
_Static_assert(EPOLL_CTL_MOD == 3, "x86 EPOLL_CTL_MOD");

static int expect_error(int result, int error)
{
    return result == -1 && errno == error;
}

int main(void)
{
    const uint64_t added_data = UINT64_C(0x1122334455667788);
    const uint64_t modified_data = UINT64_C(0x8877665544332211);
    struct epoll_event interest;
    struct epoll_event observed;
    int pipe_fds[2] = {-1, -1};
    int epoll_fd = -1;
    char byte;

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0)
        return 10;
    if (fcntl(epoll_fd, F_GETFD) < 0 ||
        (fcntl(epoll_fd, F_GETFD) & FD_CLOEXEC) == 0)
        return 11;

    /* Only EPOLL_CLOEXEC is accepted by epoll_create1. */
    errno = 0;
    if (!expect_error(epoll_create1(EPOLL_NONBLOCK), EINVAL))
        return 12;

    memset(&observed, 0, sizeof(observed));
    if (epoll_pwait(epoll_fd, &observed, 1, 0, NULL) != 0)
        return 13;

    if (pipe(pipe_fds) != 0)
        return 14;
    /* Linux accepts unassigned event-mask bits; retain them for the kernel. */
    interest.events = EPOLLIN | UINT32_C(0x00000800);
    interest.data.u64 = added_data;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipe_fds[0], &interest) != 0)
        return 15;
    if (syscall(SYS_epoll_ctl, epoll_fd, EPOLL_CTL_MOD, pipe_fds[0],
                &interest) != 0)
        return 31;
    if (epoll_pwait(epoll_fd, &observed, 1, 0, NULL) != 0)
        return 16;

    if (write(pipe_fds[1], "x", 1) != 1)
        return 17;
    memset(&observed, 0, sizeof(observed));
    if (epoll_pwait(epoll_fd, &observed, 1, 0, NULL) != 1 ||
        (observed.events & EPOLLIN) == 0 || observed.data.u64 != added_data)
        return 18;
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 'x')
        return 19;

    interest.events = EPOLLIN | EPOLLET;
    interest.data.u64 = modified_data;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, pipe_fds[0], &interest) != 0)
        return 20;
    if (write(pipe_fds[1], "y", 1) != 1)
        return 21;
    memset(&observed, 0, sizeof(observed));
    if (epoll_pwait(epoll_fd, &observed, 1, 0, NULL) != 1 ||
        (observed.events & EPOLLIN) == 0 || observed.data.u64 != modified_data)
        return 22;
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 'y')
        return 23;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, pipe_fds[0], NULL) != 0)
        return 24;
    if (epoll_pwait(epoll_fd, &observed, 1, 0, NULL) != 0)
        return 25;

    /* Check representative kernel validation errors at the same boundary. */
    errno = 0;
    if (!expect_error(epoll_ctl(epoll_fd, 99, pipe_fds[0], &interest), EINVAL))
        return 26;
    errno = 0;
    if (!expect_error(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, -1, &interest), EBADF))
        return 27;
    errno = 0;
    if (!expect_error(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, pipe_fds[0], NULL),
                      ENOENT))
        return 28;
    errno = 0;
    if (!expect_error(epoll_pwait(epoll_fd, &observed, 0, 0, NULL), EINVAL))
        return 29;

    if (close(pipe_fds[0]) != 0 || close(pipe_fds[1]) != 0 ||
        close(epoll_fd) != 0)
        return 30;

    puts("layout=size12 align1 offsets=0,4 syscalls=291,233,281 cloexec=enabled future-event=musl+raw-accepted empty=0 add=readable data=u64-preserved modify=updated delete=removed errors=EINVAL,EBADF,ENOENT");
    return 0;
}
