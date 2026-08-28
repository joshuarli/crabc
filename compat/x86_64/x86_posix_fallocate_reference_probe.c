/* Pinned-musl/raw Linux/x86-64 posix_fallocate(3)/fallocate(2) reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    PAYLOAD_SIZE = 8,
    POSITION = 3,
    RANGE_OFFSET = 4096,
    RANGE_LENGTH = 4096,
    RANGE_END = RANGE_OFFSET + RANGE_LENGTH,
};

_Static_assert(SYS_fallocate == 285, "x86 fallocate syscall number");
_Static_assert(sizeof(off_t) == sizeof(long), "x86 off_t register width");
_Static_assert(sizeof(off_t) == sizeof(int64_t), "x86 signed 64-bit off_t");
_Static_assert((off_t)-1 < (off_t)0, "x86 off_t is signed");
_Static_assert((off_t)INT64_MAX == INT64_MAX, "x86 off_t maximum");

static const unsigned char payload[PAYLOAD_SIZE] = {
    'c', 'r', 'a', 'b', 'c', '-', 'x', '8',
};
static const unsigned char zeroes[PAYLOAD_SIZE];

static long raw_fallocate(int fd, unsigned long mode, off_t offset,
                          off_t length)
{
    return syscall(SYS_fallocate, (long)fd, mode, offset, length);
}

static int regular_file_size_is(int fd, off_t expected)
{
    struct stat status;

    return fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
           status.st_size == expected;
}

static int position_is(int fd, off_t expected)
{
    return lseek(fd, 0, SEEK_CUR) == expected;
}

static int content_is_retained_and_new_range_is_zeroed(int fd)
{
    unsigned char retained[PAYLOAD_SIZE];
    unsigned char allocated[PAYLOAD_SIZE];

    return pread(fd, retained, sizeof(retained), 0) ==
               (ssize_t)sizeof(retained) &&
           memcmp(retained, payload, sizeof(payload)) == 0 &&
           pread(fd, allocated, sizeof(allocated), RANGE_OFFSET) ==
               (ssize_t)sizeof(allocated) &&
           memcmp(allocated, zeroes, sizeof(allocated)) == 0;
}

int main(void)
{
    char fixture_template[] = "/tmp/crabc-x86-posix-fallocate-XXXXXX";
    int fd = -1;
    int closed_fd = -1;
    int result = 0;
    int c_error;
    long raw_result;

    fd = mkstemp(fixture_template);
    if (fd < 0)
        return 10;
    if (unlink(fixture_template) != 0) {
        result = 11;
        goto cleanup;
    }
    if (!regular_file_size_is(fd, 0)) {
        result = 12;
        goto cleanup;
    }
    if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload) ||
        lseek(fd, POSITION, SEEK_SET) != (off_t)POSITION) {
        result = 13;
        goto cleanup;
    }

    /* musl's POSIX spelling fixes mode to zero and returns an error number. */
    errno = E2BIG;
    c_error = posix_fallocate(fd, (off_t)RANGE_OFFSET,
                              (off_t)RANGE_LENGTH);
    if (c_error != 0 || errno != E2BIG ||
        !regular_file_size_is(fd, (off_t)RANGE_END) ||
        !content_is_retained_and_new_range_is_zeroed(fd) ||
        !position_is(fd, (off_t)POSITION)) {
        result = 14;
        goto cleanup;
    }

    /* Reset the same unlinked regular-file fixture before the raw comparison. */
    if (ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) != 0 ||
        write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload) ||
        lseek(fd, POSITION, SEEK_SET) != (off_t)POSITION) {
        result = 15;
        goto cleanup;
    }
    errno = 0;
    raw_result = raw_fallocate(fd, 0UL, (off_t)RANGE_OFFSET,
                               (off_t)RANGE_LENGTH);
    if (raw_result != 0 || errno != 0 ||
        !regular_file_size_is(fd, (off_t)RANGE_END) ||
        !content_is_retained_and_new_range_is_zeroed(fd) ||
        !position_is(fd, (off_t)POSITION)) {
        result = 16;
        goto cleanup;
    }

    /* Linux rejects a zero-length request without changing file state. */
    errno = E2BIG;
    c_error = posix_fallocate(fd, 0, 0);
    if (c_error != EINVAL || errno != E2BIG ||
        !regular_file_size_is(fd, (off_t)RANGE_END) ||
        !position_is(fd, (off_t)POSITION)) {
        result = 17;
        goto cleanup;
    }
    errno = 0;
    raw_result = raw_fallocate(fd, 0UL, 0, 0);
    if (raw_result != -1 || errno != EINVAL ||
        !regular_file_size_is(fd, (off_t)RANGE_END) ||
        !position_is(fd, (off_t)POSITION)) {
        result = 18;
        goto cleanup;
    }

    /* musl returns EINVAL directly; the raw ABI reports -1 and sets errno. */
    errno = E2BIG;
    c_error = posix_fallocate(fd, (off_t)-1, 1);
    if (c_error != EINVAL || errno != E2BIG ||
        !regular_file_size_is(fd, (off_t)RANGE_END) ||
        !position_is(fd, (off_t)POSITION)) {
        result = 19;
        goto cleanup;
    }
    errno = 0;
    raw_result = raw_fallocate(fd, 0UL, (off_t)-1, 1);
    if (raw_result != -1 || errno != EINVAL ||
        !regular_file_size_is(fd, (off_t)RANGE_END) ||
        !position_is(fd, (off_t)POSITION)) {
        result = 20;
        goto cleanup;
    }

    closed_fd = fd;
    if (close(fd) != 0) {
        result = 21;
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    errno = E2BIG;
    c_error = posix_fallocate(closed_fd, 0, 1);
    if (c_error != EBADF || errno != E2BIG) {
        result = 22;
        goto cleanup;
    }
    errno = 0;
    raw_result = raw_fallocate(closed_fd, 0UL, 0, 1);
    if (raw_result != -1 || errno != EBADF) {
        result = 23;
        goto cleanup;
    }

cleanup:
    (void)unlink(fixture_template);
    if (fd >= 0 && close(fd) != 0 && result == 0)
        result = 30;
    if (result != 0)
        return result;

    puts("syscall=285 off_t=signed64 mode=zero "
         "fixture=unlinked-regular-file range=offset4096:length4096 "
         "extends8192 bytes=retained-prefix:zero-filled position=stable "
         "zero-length=c:EINVAL,raw:errno=EINVAL "
         "negative-offset=c:EINVAL:errno-unchanged,raw:errno=EINVAL "
         "closed=c:EBADF:errno-unchanged,raw:errno=EBADF "
         "c-api-selection=excluded path-surface=excluded");
    return 0;
}
