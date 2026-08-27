/* Pinned-musl Linux/x86-64 lseek/fsync/fdatasync ABI and behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(SYS_lseek == 8, "x86 lseek syscall number");
_Static_assert(SYS_fsync == 74, "x86 fsync syscall number");
_Static_assert(SYS_fdatasync == 75, "x86 fdatasync syscall number");
_Static_assert(sizeof(off_t) == sizeof(int64_t), "x86 signed 64-bit off_t");
_Static_assert((off_t)-1 < (off_t)0, "x86 off_t is signed");
_Static_assert(SEEK_SET == 0, "x86 SEEK_SET value");
_Static_assert(SEEK_CUR == 1, "x86 SEEK_CUR value");
_Static_assert(SEEK_END == 2, "x86 SEEK_END value");
_Static_assert(SEEK_DATA == 3, "x86 SEEK_DATA value");
_Static_assert(SEEK_HOLE == 4, "x86 SEEK_HOLE value");

static int expect_error(long result, int error)
{
    return result == -1 && errno == error;
}

int main(void)
{
    static const char name[] = "crabc-x86-file-position-reference";
    static const char sparse_name[] = "crabc-x86-file-position-sparse";
    static const unsigned char payload[] = {'c', 'r', 'a', 'b', 'c', '!'};
    int fd = -1;
    int sparse_fd = -1;
    int pipe_fds[2] = {-1, -1};

    fd = memfd_create(name, MFD_CLOEXEC);
    if (fd < 0)
        return 10;
    if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload))
        return 11;

    /* Confirm the raw x86 syscall boundary before the musl position checks. */
    if (syscall(SYS_lseek, fd, 0L, SEEK_SET) != 0)
        return 12;
    if (lseek(fd, (off_t)1, SEEK_SET) != (off_t)1)
        return 13;
    if (lseek(fd, (off_t)2, SEEK_CUR) != (off_t)3)
        return 14;
    if (lseek(fd, (off_t)-1, SEEK_END) != (off_t)5)
        return 15;

    /* These prove accepted sync requests only, not host durability policy. */
    if (fsync(fd) != 0 || lseek(fd, 0, SEEK_CUR) != (off_t)5)
        return 16;
    if (fdatasync(fd) != 0 || lseek(fd, 0, SEEK_CUR) != (off_t)5)
        return 17;

    sparse_fd = memfd_create(sparse_name, MFD_CLOEXEC);
    if (sparse_fd < 0)
        return 18;
    if (lseek(sparse_fd, 4096, SEEK_SET) != (off_t)4096)
        return 19;
    if (write(sparse_fd, "tail", 4) != 4)
        return 20;
    if (lseek(sparse_fd, 0, SEEK_DATA) != (off_t)4096)
        return 21;
    if (lseek(sparse_fd, 0, SEEK_HOLE) != 0)
        return 22;

    errno = 0;
    if (!expect_error(lseek(fd, 0, 0x7fff), EINVAL))
        return 23;
    errno = 0;
    if (!expect_error(syscall(SYS_lseek, fd, INT64_MIN, SEEK_SET), EINVAL))
        return 24;
    errno = 0;
    if (!expect_error(lseek(fd, INT64_MIN, SEEK_DATA), ENXIO))
        return 25;
    errno = 0;
    if (!expect_error(lseek(fd, INT64_MIN, SEEK_HOLE), ENXIO))
        return 26;
    if (pipe(pipe_fds) != 0)
        return 27;
    errno = 0;
    if (!expect_error(lseek(pipe_fds[0], 0, SEEK_SET), ESPIPE))
        return 28;
    errno = 0;
    if (!expect_error(lseek(-1, 0, SEEK_SET), EBADF))
        return 29;
    errno = 0;
    if (!expect_error(fsync(-1), EBADF))
        return 30;
    errno = 0;
    if (!expect_error(fdatasync(-1), EBADF))
        return 31;

    if (close(pipe_fds[0]) != 0 || close(pipe_fds[1]) != 0 ||
        close(sparse_fd) != 0 || close(fd) != 0)
        return 32;

    puts("syscalls=lseek:8,fsync:74,fdatasync:75 off_t=signed64 positions=start1:current3:end5 sparse=data4096:hole0 sync=memfd-position-stable over-i64=SEEK_SET:EINVAL,SEEK_DATA/HOLE:ENXIO errors=EINVAL,ENXIO,ESPIPE,EBADF");
    return 0;
}
