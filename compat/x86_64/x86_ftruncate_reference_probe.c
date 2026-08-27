/* Pinned-musl Linux/x86-64 ftruncate ABI and behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(SYS_ftruncate == 77, "x86 ftruncate syscall number");
_Static_assert(sizeof(off_t) == sizeof(int64_t), "x86 signed 64-bit loff_t");
_Static_assert((off_t)-1 < (off_t)0, "x86 loff_t is signed");
_Static_assert((off_t)INT64_MAX == INT64_MAX, "x86 loff_t maximum");

static int expect_error(long result, int error)
{
    return result == -1 && errno == error;
}

static int expect_size(int fd, off_t expected)
{
    struct stat status;

    return fstat(fd, &status) == 0 && status.st_size == expected;
}

int main(void)
{
    static const char name[] = "crabc-x86-ftruncate-reference";
    static const unsigned char payload[] = {'c', 'r', 'a', 'b'};
    unsigned char extended[8];
    unsigned char shrunk[2];
    const uint64_t over_i64 = (uint64_t)INT64_MAX + UINT64_C(1);
    int fd = -1;

    fd = memfd_create(name, MFD_CLOEXEC);
    if (fd < 0)
        return 10;
    if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload))
        return 11;
    if (lseek(fd, 0, SEEK_CUR) != (off_t)sizeof(payload))
        return 12;

    if (ftruncate(fd, (off_t)sizeof(extended)) != 0 ||
        !expect_size(fd, (off_t)sizeof(extended)))
        return 13;
    if (lseek(fd, 0, SEEK_CUR) != (off_t)sizeof(payload))
        return 14;
    if (pread(fd, extended, sizeof(extended), 0) != (ssize_t)sizeof(extended) ||
        memcmp(extended, payload, sizeof(payload)) != 0 ||
        extended[4] != 0 || extended[5] != 0 || extended[6] != 0 ||
        extended[7] != 0)
        return 15;

    /*
     * Linux 5.10 memfd accepts the inclusive positive signed-loff_t maximum.
     * This remains sparse: no bytes are touched between the tested prefix and
     * the new end. Shrinking immediately below restores the small fixture.
     */
    if (ftruncate(fd, INT64_MAX) != 0 || !expect_size(fd, INT64_MAX))
        return 16;
    if (ftruncate(fd, (off_t)sizeof(shrunk)) != 0 ||
        !expect_size(fd, (off_t)sizeof(shrunk)))
        return 17;
    if (pread(fd, shrunk, sizeof(shrunk), 0) != (ssize_t)sizeof(shrunk) ||
        memcmp(shrunk, payload, sizeof(shrunk)) != 0)
        return 18;
    if (lseek(fd, 0, SEEK_CUR) != (off_t)sizeof(payload))
        return 19;

    errno = 0;
    if (!expect_error(ftruncate(fd, (off_t)-1), EINVAL))
        return 20;
    /*
     * The direct syscall sees a full register. The first unsigned value above
     * INT64_MAX is the negative signed-loff_t representation INT64_MIN, so
     * Linux rejects it instead of treating it as a giant positive length.
     */
    errno = 0;
    if (!expect_error(syscall(SYS_ftruncate, fd, (unsigned long)over_i64),
                      EINVAL) ||
        !expect_size(fd, (off_t)sizeof(shrunk)))
        return 21;
    errno = 0;
    if (!expect_error(syscall(SYS_ftruncate, -1, 0UL), EBADF))
        return 22;

    if (close(fd) != 0)
        return 23;

    puts("ftruncate=77 loff_t=signed64 lifecycle=extend8:zero-fill:shrink2:position-stable max=i64-max over-i64=EINVAL direct-errors=EINVAL,EBADF");
    return 0;
}
