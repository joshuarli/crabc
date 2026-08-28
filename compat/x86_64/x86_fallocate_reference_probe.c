/* Pinned-musl/raw Linux/x86-64 fallocate(2) ABI and behavior reference. */

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
    CRABC_FALLOC_FL_KEEP_SIZE = 0x01,
    CRABC_FALLOC_FL_PUNCH_HOLE = 0x02,
    CRABC_FALLOC_FL_COLLAPSE_RANGE = 0x08,
    CRABC_FALLOC_FL_ZERO_RANGE = 0x10,
    CRABC_FALLOC_FL_INSERT_RANGE = 0x20,
    CRABC_FALLOC_FL_UNSHARE_RANGE = 0x40,
    RANGE_OFFSET = 4096,
    RANGE_LENGTH = 4096,
    RANGE_END = RANGE_OFFSET + RANGE_LENGTH,
    INITIAL_SIZE = 12288,
    POSITION = 3,
};

_Static_assert(SYS_fallocate == 285, "x86 fallocate syscall number");
_Static_assert(sizeof(off_t) == sizeof(long), "x86 off_t register width");
_Static_assert(sizeof(off_t) == sizeof(int64_t), "x86 signed 64-bit off_t");
_Static_assert((off_t)-1 < (off_t)0, "x86 off_t is signed");
_Static_assert((off_t)INT64_MAX == INT64_MAX, "x86 off_t maximum");

struct call_result {
    long value;
    int error;
};

static struct call_result libc_fallocate(int fd, int mode, off_t offset,
                                         off_t length)
{
    struct call_result result;

    errno = 0;
    result.value = fallocate(fd, mode, offset, length);
    result.error = errno;
    return result;
}

static struct call_result raw_fallocate(int fd, int mode, off_t offset,
                                        off_t length)
{
    struct call_result result;

    errno = 0;
    result.value = syscall(SYS_fallocate, (long)fd, (long)mode, offset,
                           length);
    result.error = errno;
    return result;
}

static int make_fixture(char *template, size_t size, int *fd_out)
{
    unsigned char block[256];
    size_t written = 0;
    int fd;

    fd = mkstemp(template);
    if (fd < 0)
        return 0;
    if (unlink(template) != 0)
        goto fail;
    while (written < size) {
        size_t count = size - written;
        if (count > sizeof(block))
            count = sizeof(block);
        for (size_t i = 0; i < count; ++i)
            block[i] = (unsigned char)((written + i) % 251U + 1U);
        if (write(fd, block, count) != (ssize_t)count)
            goto fail;
        written += count;
    }
    if (lseek(fd, POSITION, SEEK_SET) != (off_t)POSITION)
        goto fail;
    *fd_out = fd;
    return 1;

fail:
    (void)close(fd);
    return 0;
}

static int size_is(int fd, off_t expected)
{
    struct stat status;

    return fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
           status.st_size == expected;
}

static int position_is(int fd, off_t expected)
{
    return lseek(fd, 0, SEEK_CUR) == expected;
}

static int bytes_are(int fd, off_t offset, size_t length, unsigned char value)
{
    unsigned char bytes[256];
    size_t checked = 0;

    while (checked < length) {
        size_t count = length - checked;
        if (count > sizeof(bytes))
            count = sizeof(bytes);
        if (pread(fd, bytes, count, offset + (off_t)checked) !=
                (ssize_t)count)
            return 0;
        for (size_t i = 0; i < count; ++i) {
            if (bytes[i] != value)
                return 0;
        }
        checked += count;
    }
    return 1;
}

static int bytes_are_pattern(int fd, off_t offset, size_t length)
{
    unsigned char bytes[256];
    size_t checked = 0;

    while (checked < length) {
        size_t count = length - checked;
        if (count > sizeof(bytes))
            count = sizeof(bytes);
        if (pread(fd, bytes, count, offset + (off_t)checked) !=
                (ssize_t)count)
            return 0;
        for (size_t i = 0; i < count; ++i) {
            if (bytes[i] != (unsigned char)((offset + (off_t)checked +
                                             (off_t)i) % 251 + 1))
                return 0;
        }
        checked += count;
    }
    return 1;
}

static int same_success(struct call_result libc_result,
                        struct call_result raw_result)
{
    return libc_result.value == 0 && raw_result.value == 0;
}

static int same_error(struct call_result libc_result,
                      struct call_result raw_result, int expected)
{
    return libc_result.value == -1 && raw_result.value == -1 &&
           libc_result.error == expected && raw_result.error == expected;
}

enum expected_effect {
    EFFECT_EXTEND_WITH_ZEROS,
    EFFECT_KEEP_SIZE,
    EFFECT_ZERO_INTERIOR,
};

enum case_result {
    CASE_FAILED,
    CASE_SUPPORTED,
    CASE_UNSUPPORTED,
};

static enum case_result run_effect_case(int mode, size_t initial_size,
                                        off_t expected_size,
                                        enum expected_effect effect,
                                        int allow_unsupported)
{
    char libc_template[] = "./crabc-x86-fallocate-libc-XXXXXX";
    char raw_template[] = "./crabc-x86-fallocate-raw-XXXXXX";
    struct call_result libc_result;
    struct call_result raw_result;
    int libc_fd = -1;
    int raw_fd = -1;
    enum case_result result = CASE_FAILED;

    if (!make_fixture(libc_template, initial_size, &libc_fd) ||
        !make_fixture(raw_template, initial_size, &raw_fd))
        goto cleanup;
    libc_result = libc_fallocate(libc_fd, mode, (off_t)RANGE_OFFSET,
                                 (off_t)RANGE_LENGTH);
    raw_result = raw_fallocate(raw_fd, mode, (off_t)RANGE_OFFSET,
                               (off_t)RANGE_LENGTH);
    if (allow_unsupported && same_error(libc_result, raw_result, EOPNOTSUPP) &&
        size_is(libc_fd, (off_t)initial_size) &&
        size_is(raw_fd, (off_t)initial_size) &&
        position_is(libc_fd, POSITION) && position_is(raw_fd, POSITION)) {
        result = CASE_UNSUPPORTED;
        goto cleanup;
    }
    if (!same_success(libc_result, raw_result) ||
        !size_is(libc_fd, expected_size) || !size_is(raw_fd, expected_size) ||
        !position_is(libc_fd, POSITION) || !position_is(raw_fd, POSITION))
        goto cleanup;
    switch (effect) {
    case EFFECT_EXTEND_WITH_ZEROS:
        if (!bytes_are_pattern(libc_fd, 0, initial_size) ||
            !bytes_are_pattern(raw_fd, 0, initial_size) ||
            !bytes_are(libc_fd, (off_t)initial_size,
                       (size_t)expected_size - initial_size, 0) ||
            !bytes_are(raw_fd, (off_t)initial_size,
                       (size_t)expected_size - initial_size, 0))
            goto cleanup;
        break;
    case EFFECT_KEEP_SIZE:
        if (!bytes_are_pattern(libc_fd, 0, initial_size) ||
            !bytes_are_pattern(raw_fd, 0, initial_size))
            goto cleanup;
        break;
    case EFFECT_ZERO_INTERIOR:
        if (!bytes_are_pattern(libc_fd, 0, RANGE_OFFSET) ||
            !bytes_are_pattern(raw_fd, 0, RANGE_OFFSET) ||
            !bytes_are(libc_fd, RANGE_OFFSET, RANGE_LENGTH, 0) ||
            !bytes_are(raw_fd, RANGE_OFFSET, RANGE_LENGTH, 0) ||
            !bytes_are_pattern(libc_fd, RANGE_END, initial_size - RANGE_END) ||
            !bytes_are_pattern(raw_fd, RANGE_END, initial_size - RANGE_END))
            goto cleanup;
        break;
    }
    result = CASE_SUPPORTED;

cleanup:
    if (libc_fd >= 0)
        (void)close(libc_fd);
    if (raw_fd >= 0)
        (void)close(raw_fd);
    return result;
}

static int run_invalid_case(int mode, off_t offset, off_t length, int error)
{
    char libc_template[] = "./crabc-x86-fallocate-libc-XXXXXX";
    char raw_template[] = "./crabc-x86-fallocate-raw-XXXXXX";
    struct call_result libc_result;
    struct call_result raw_result;
    int libc_fd = -1;
    int raw_fd = -1;
    int ok = 0;

    if (!make_fixture(libc_template, INITIAL_SIZE, &libc_fd) ||
        !make_fixture(raw_template, INITIAL_SIZE, &raw_fd))
        goto cleanup;
    libc_result = libc_fallocate(libc_fd, mode, offset, length);
    raw_result = raw_fallocate(raw_fd, mode, offset, length);
    if (!same_error(libc_result, raw_result, error) ||
        !size_is(libc_fd, INITIAL_SIZE) || !size_is(raw_fd, INITIAL_SIZE) ||
        !position_is(libc_fd, POSITION) || !position_is(raw_fd, POSITION))
        goto cleanup;
    ok = 1;

cleanup:
    if (libc_fd >= 0)
        (void)close(libc_fd);
    if (raw_fd >= 0)
        (void)close(raw_fd);
    return ok;
}

static int run_closed_case(void)
{
    char template[] = "./crabc-x86-fallocate-closed-XXXXXX";
    struct call_result libc_result;
    struct call_result raw_result;
    int fd = -1;

    if (!make_fixture(template, INITIAL_SIZE, &fd))
        return 0;
    if (close(fd) != 0)
        return 0;
    libc_result = libc_fallocate(fd, 0, 0, 1);
    raw_result = raw_fallocate(fd, 0, 0, 1);
    return same_error(libc_result, raw_result, EBADF);
}

static int run_read_only_case(void)
{
    char template[] = "./crabc-x86-fallocate-read-only-XXXXXX";
    struct call_result libc_result;
    struct call_result raw_result;
    int fd = -1;
    int read_only_fd = -1;

    fd = mkstemp(template);
    if (fd < 0)
        return 0;
    if (close(fd) != 0)
        return 0;
    read_only_fd = open(template, O_RDONLY);
    if (read_only_fd < 0) {
        (void)unlink(template);
        return 0;
    }
    libc_result = libc_fallocate(read_only_fd, 0, 0, 1);
    raw_result = raw_fallocate(read_only_fd, 0, 0, 1);
    (void)close(read_only_fd);
    (void)unlink(template);
    return same_error(libc_result, raw_result, EBADF);
}

static int run_pipe_case(void)
{
    int pipe_fds[2];
    struct call_result libc_result;
    struct call_result raw_result;

    if (pipe(pipe_fds) != 0)
        return 0;
    libc_result = libc_fallocate(pipe_fds[1], 0, 0, 1);
    raw_result = raw_fallocate(pipe_fds[1], 0, 0, 1);
    (void)close(pipe_fds[0]);
    (void)close(pipe_fds[1]);
    return same_error(libc_result, raw_result, ESPIPE);
}

int main(void)
{
    if (run_effect_case(0, 8, RANGE_END, EFFECT_EXTEND_WITH_ZEROS, 0) !=
        CASE_SUPPORTED)
        return 10;
    if (run_effect_case(CRABC_FALLOC_FL_KEEP_SIZE, 8, 8, EFFECT_KEEP_SIZE, 0) !=
        CASE_SUPPORTED)
        return 11;
    if (run_effect_case(CRABC_FALLOC_FL_KEEP_SIZE | CRABC_FALLOC_FL_PUNCH_HOLE,
                        INITIAL_SIZE, INITIAL_SIZE, EFFECT_ZERO_INTERIOR, 1) ==
        CASE_FAILED)
        return 12;
    if (run_effect_case(CRABC_FALLOC_FL_ZERO_RANGE, 8, RANGE_END,
                        EFFECT_EXTEND_WITH_ZEROS, 1) == CASE_FAILED)
        return 13;
    if (run_effect_case(CRABC_FALLOC_FL_KEEP_SIZE | CRABC_FALLOC_FL_ZERO_RANGE,
                        INITIAL_SIZE, INITIAL_SIZE, EFFECT_ZERO_INTERIOR, 1) ==
        CASE_FAILED)
        return 14;

    if (!run_invalid_case(CRABC_FALLOC_FL_PUNCH_HOLE, 0, 1, EOPNOTSUPP) ||
        !run_invalid_case(CRABC_FALLOC_FL_PUNCH_HOLE | CRABC_FALLOC_FL_ZERO_RANGE |
                              CRABC_FALLOC_FL_KEEP_SIZE,
                          0, 1, EOPNOTSUPP) ||
        !run_invalid_case(0x80, 0, 1, EOPNOTSUPP) ||
        !run_invalid_case(0, -1, 1, EINVAL) ||
        !run_invalid_case(0, 0, 0, EINVAL))
        return 15;

    if (!run_closed_case())
        return 16;
    if (!run_read_only_case())
        return 17;
    if (!run_pipe_case())
        return 18;

    puts("syscall=285 off_t=signed64 modes=zero:keep-size:punch-hole|keep-size:zero-range:zero-range|keep-size "
         "fixture=unlinked-regular-file range=offset4096:length4096 "
         "zero=success:retained-edges:zeroed-range:size-extends-or-kept|EOPNOTSUPP "
         "punch=success:size-kept:range-zeroed|EOPNOTSUPP "
         "position=stable invalid=EINVAL:negative-offset|zero-length,EOPNOTSUPP:bad-combinations|unknown-bits "
         "closed=EBADF read-only=EBADF pipe=ESPIPE "
         "future-modes=excluded c-api-selection=excluded path-surface=excluded "
         "durability=excluded");
    return 0;
}
