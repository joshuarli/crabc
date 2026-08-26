/* Pinned-musl Linux/x86-64 fadvise64/readahead ABI and behavior reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(SYS_fadvise64 == 221, "x86 fadvise64 syscall number");
_Static_assert(SYS_readahead == 187, "x86 readahead syscall number");
_Static_assert(POSIX_FADV_NORMAL == 0, "x86 POSIX_FADV_NORMAL");
_Static_assert(POSIX_FADV_RANDOM == 1, "x86 POSIX_FADV_RANDOM");
_Static_assert(POSIX_FADV_SEQUENTIAL == 2, "x86 POSIX_FADV_SEQUENTIAL");
_Static_assert(POSIX_FADV_WILLNEED == 3, "x86 POSIX_FADV_WILLNEED");
_Static_assert(POSIX_FADV_DONTNEED == 4, "x86 POSIX_FADV_DONTNEED");
_Static_assert(POSIX_FADV_NOREUSE == 5, "x86 POSIX_FADV_NOREUSE");

static int expect_errno(long result, int error)
{
    return result == -1 && errno == error;
}

int main(void)
{
    char path[128];
    int fd;
    off_t before;
    off_t after;
    const int policies[] = {
        POSIX_FADV_NORMAL,
        POSIX_FADV_RANDOM,
        POSIX_FADV_SEQUENTIAL,
        POSIX_FADV_WILLNEED,
        POSIX_FADV_DONTNEED,
        POSIX_FADV_NOREUSE,
    };
    size_t i;

    if (snprintf(path, sizeof(path), "/tmp/crabc-x86-fs-advice-%ld",
                 (long)getpid()) < 0)
        return 1;
    fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0)
        return 2;
    if (ftruncate(fd, 8192) != 0)
        return 3;
    if (lseek(fd, 19, SEEK_SET) != 19)
        return 4;
    before = lseek(fd, 0, SEEK_CUR);
    if (before != 19)
        return 5;

    for (i = 0; i < sizeof(policies) / sizeof(policies[0]); ++i) {
        errno = 0;
        if (syscall(SYS_fadvise64, fd, (off_t)0,
                    i == 0 ? (off_t)0 : (off_t)8192, policies[i]) != 0)
            return 6;
    }
    after = lseek(fd, 0, SEEK_CUR);
    if (after != before)
        return 7;

    errno = 0;
    if (!expect_errno(syscall(SYS_fadvise64, fd, (off_t)0, (off_t)-1,
                              POSIX_FADV_NORMAL), EINVAL))
        return 8;
    errno = 0;
    if (!expect_errno(syscall(SYS_readahead, fd, (off_t)0, (size_t)-1), EINVAL))
        return 9;

    errno = 0;
    if (syscall(SYS_readahead, fd, (off_t)0, (size_t)8192) != 0)
        return 10;
    after = lseek(fd, 0, SEEK_CUR);
    if (after != before)
        return 11;

    if (close(fd) != 0)
        return 12;
    if (unlink(path) != 0)
        return 13;

    errno = 0;
    if (!expect_errno(syscall(SYS_readahead, -1, (off_t)0, (size_t)0), EBADF))
        return 14;
    errno = 0;
    if (!expect_errno(syscall(SYS_fadvise64, -1, (off_t)0, (off_t)0,
                              POSIX_FADV_NORMAL), EBADF))
        return 15;

    puts("fadvise64=221 policies=0,1,2,3,4,5 readahead=187 position=stable negative-length=EINVAL invalid-fd=EBADF");
    return 0;
}
