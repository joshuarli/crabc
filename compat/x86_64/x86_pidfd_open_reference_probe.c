/* Pinned-musl Linux/x86-64 pidfd_open syscall behavior reference. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    PIDFD_NONBLOCK = 0x00000800,
};

_Static_assert(SYS_pidfd_open == 434, "x86 pidfd_open syscall number");

int main(void) {
    pid_t pid = getpid();
    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0u);
    if (pidfd < 0) {
        if (errno == ENOSYS) {
            puts("pidfd_open=unsupported");
            return 0;
        }
        return 1;
    }
    if (fcntl(pidfd, F_GETFD) < 0) {
        return 2;
    }
    if (close(pidfd) != 0) {
        return 3;
    }

    pidfd = (int)syscall(SYS_pidfd_open, pid, PIDFD_NONBLOCK);
    if (pidfd < 0) {
        return 4;
    }
    int status_flags = fcntl(pidfd, F_GETFL);
    if (status_flags < 0 || (status_flags & O_NONBLOCK) == 0) {
        return 5;
    }
    if (close(pidfd) != 0) {
        return 6;
    }

    errno = 0;
    if (syscall(SYS_pidfd_open, (pid_t)INT32_MAX, 0u) != -1 || errno != ESRCH) {
        return 7;
    }
    errno = 0;
    if (syscall(SYS_pidfd_open, pid, UINT32_MAX) != -1 || errno != EINVAL) {
        return 8;
    }

    puts("pidfd_open=available nonblock=enabled errors=preserved");
    return 0;
}
