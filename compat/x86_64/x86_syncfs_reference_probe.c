/* Pinned-musl/raw Linux/x86-64 syncfs ABI and descriptor reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { PAYLOAD_SIZE = 6, POSITION = 3 };

_Static_assert(SYS_syncfs == 306, "x86 syncfs syscall number");
_Static_assert(sizeof(int) == 4, "x86 int width");
_Static_assert(sizeof(long) == 8, "x86 LP64 long width");

struct syncfs_result {
    long value;
    int error;
};

static struct syncfs_result libc_syncfs(int fd)
{
    struct syncfs_result result;

    errno = 0;
    result.value = syncfs(fd);
    result.error = errno;
    return result;
}

static struct syncfs_result raw_syncfs(int fd)
{
    struct syncfs_result result;

    errno = 0;
    result.value = syscall(SYS_syncfs, (long)fd);
    result.error = errno;
    return result;
}

static int same_success(struct syncfs_result libc_result,
                        struct syncfs_result raw_result)
{
    return libc_result.value == 0 && raw_result.value == 0;
}

static int same_error(struct syncfs_result libc_result,
                      struct syncfs_result raw_result, int error)
{
    return libc_result.value == -1 && raw_result.value == -1 &&
           libc_result.error == error && raw_result.error == error;
}

int main(void)
{
    static const unsigned char payload[PAYLOAD_SIZE] = {
        'c', 'r', 'a', 'b', 'c', '!'};
    char template[] = "/tmp/crabc-x86-syncfs-XXXXXX";
    struct stat status;
    struct syncfs_result libc_result;
    struct syncfs_result raw_result;
    off_t before;
    int fd = -1;
    int closed_fd = -1;
    int pipe_fds[2] = {-1, -1};
    int result = 0;

    fd = mkstemp(template);
    if (fd < 0)
        return 10;
    if (unlink(template) != 0) {
        result = 11;
        goto cleanup;
    }
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)) {
        result = 12;
        goto cleanup;
    }
    if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload)) {
        result = 13;
        goto cleanup;
    }
    if (lseek(fd, POSITION, SEEK_SET) != (off_t)POSITION) {
        result = 14;
        goto cleanup;
    }
    before = lseek(fd, 0, SEEK_CUR);
    if (before != (off_t)POSITION) {
        result = 15;
        goto cleanup;
    }

    /*
     * Success means only that Linux accepted the request for this descriptor's
     * filesystem. This probe does not measure power-loss or storage-cache
     * durability.
     */
    libc_result = libc_syncfs(fd);
    if (!same_success(libc_result, raw_syncfs(fd))) {
        result = 16;
        goto cleanup;
    }
    if (lseek(fd, 0, SEEK_CUR) != before) {
        result = 17;
        goto cleanup;
    }

    closed_fd = dup(fd);
    if (closed_fd < 0) {
        result = 18;
        goto cleanup;
    }
    if (close(closed_fd) != 0) {
        result = 19;
        goto cleanup;
    }
    libc_result = libc_syncfs(closed_fd);
    raw_result = raw_syncfs(closed_fd);
    if (!same_error(libc_result, raw_result, EBADF)) {
        result = 20;
        goto cleanup;
    }

    /* A pipe is backed by pipefs, so Linux accepts its open descriptor too. */
    if (pipe(pipe_fds) != 0) {
        result = 21;
        goto cleanup;
    }
    libc_result = libc_syncfs(pipe_fds[0]);
    raw_result = raw_syncfs(pipe_fds[0]);
    if (!same_success(libc_result, raw_result)) {
        result = 22;
        goto cleanup;
    }

cleanup:
    /* Unlinking here also handles a failure before the initial unlink. */
    (void)unlink(template);
    if (pipe_fds[0] >= 0 && close(pipe_fds[0]) != 0 && result == 0)
        result = 30;
    if (pipe_fds[1] >= 0 && close(pipe_fds[1]) != 0 && result == 0)
        result = 31;
    if (fd >= 0 && close(fd) != 0 && result == 0)
        result = 32;
    if (result != 0)
        return result;

    puts("syscall=306 regular-file=accepted pipe=accepted position=stable "
         "raw=matches-musl closed-fd=EBADF durability=unproved");
    return 0;
}
