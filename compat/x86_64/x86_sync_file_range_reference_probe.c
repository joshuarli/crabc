/* Pinned-musl/raw Linux/x86-64 sync_file_range ABI and behavior reference. */

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

enum { PAYLOAD_SIZE = 8192, POSITION = 37 };

_Static_assert(SYS_sync_file_range == 277,
               "x86 sync_file_range syscall number");
_Static_assert(SYNC_FILE_RANGE_WAIT_BEFORE == 1,
               "x86 SYNC_FILE_RANGE_WAIT_BEFORE");
_Static_assert(SYNC_FILE_RANGE_WRITE == 2,
               "x86 SYNC_FILE_RANGE_WRITE");
_Static_assert(SYNC_FILE_RANGE_WAIT_AFTER == 4,
               "x86 SYNC_FILE_RANGE_WAIT_AFTER");
_Static_assert(sizeof(off_t) == sizeof(long), "x86 off_t register width");
_Static_assert((off_t)-1 < (off_t)0, "x86 off_t is signed");

struct sync_result {
    long value;
    int error;
};

static struct sync_result libc_sync_file_range(int fd, off_t offset,
                                                off_t nbytes, unsigned flags)
{
    struct sync_result result;

    errno = 0;
    result.value = sync_file_range(fd, offset, nbytes, flags);
    result.error = errno;
    return result;
}

static struct sync_result raw_sync_file_range(int fd, off_t offset,
                                               off_t nbytes, unsigned flags)
{
    struct sync_result result;

    errno = 0;
    result.value = syscall(SYS_sync_file_range, fd, offset, nbytes, flags);
    result.error = errno;
    return result;
}

static int same_success(struct sync_result libc_result,
                        struct sync_result raw_result)
{
    return libc_result.value == 0 && raw_result.value == 0;
}

static int same_error(struct sync_result libc_result, struct sync_result raw_result,
                      int error)
{
    return libc_result.value == -1 && raw_result.value == -1 &&
           libc_result.error == error && raw_result.error == error;
}

static int same_regular_file_result(struct sync_result libc_result,
                                    struct sync_result raw_result)
{
    return same_success(libc_result, raw_result) ||
           same_error(libc_result, raw_result, EOPNOTSUPP);
}

int main(void)
{
    static const unsigned flags = SYNC_FILE_RANGE_WAIT_BEFORE |
                                  SYNC_FILE_RANGE_WRITE |
                                  SYNC_FILE_RANGE_WAIT_AFTER;
    char template[] = "/tmp/crabc-x86-sync-file-range-XXXXXX";
    unsigned char payload[PAYLOAD_SIZE];
    struct stat status;
    struct sync_result libc_result;
    struct sync_result raw_result;
    off_t before;
    int fd = -1;
    int pipe_fds[2] = {-1, -1};
    int result = 0;
    size_t i;

    for (i = 0; i < sizeof(payload); ++i)
        payload[i] = (unsigned char)(i & 0xffU);

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
     * nbytes == 0 requests writeback through EOF. This does not establish
     * durable storage; an otherwise valid backing store can report
     * EOPNOTSUPP instead.
     */
    libc_result = libc_sync_file_range(fd, 0, 0, flags);
    if (lseek(fd, 0, SEEK_CUR) != before) {
        result = 16;
        goto cleanup;
    }
    raw_result = raw_sync_file_range(fd, 0, 0, flags);
    if (!same_regular_file_result(libc_result, raw_result)) {
        result = 17;
        goto cleanup;
    }
    if (lseek(fd, 0, SEEK_CUR) != before) {
        result = 18;
        goto cleanup;
    }

    libc_result = libc_sync_file_range(fd, 0, 0, flags | 0x08U);
    raw_result = raw_sync_file_range(fd, 0, 0, flags | 0x08U);
    if (!same_error(libc_result, raw_result, EINVAL)) {
        result = 19;
        goto cleanup;
    }
    if (lseek(fd, 0, SEEK_CUR) != before) {
        result = 20;
        goto cleanup;
    }

    if (pipe(pipe_fds) != 0) {
        result = 21;
        goto cleanup;
    }
    libc_result = libc_sync_file_range(pipe_fds[0], 0, 0, flags);
    raw_result = raw_sync_file_range(pipe_fds[0], 0, 0, flags);
    if (!same_error(libc_result, raw_result, ESPIPE)) {
        result = 22;
        goto cleanup;
    }

    libc_result = libc_sync_file_range(-1, 0, 0, flags);
    raw_result = raw_sync_file_range(-1, 0, 0, flags);
    if (!same_error(libc_result, raw_result, EBADF)) {
        result = 23;
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

    puts("syscall=277 flags=WAIT_BEFORE:1,WRITE:2,WAIT_AFTER:4 "
         "regular-file=zero-length-to-eof-writeback-request:success-or-EOPNOTSUPP "
         "position=stable raw=matches-musl invalid-flags=EINVAL pipe=ESPIPE "
         "invalid-fd=EBADF");
    return 0;
}
