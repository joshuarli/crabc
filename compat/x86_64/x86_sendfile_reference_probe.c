/* Pinned-musl/raw Linux/x86-64 sendfile(2) ABI and behavior reference. */

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
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    PAYLOAD_SIZE = 10,
    EXPLICIT_OFFSET = 2,
    EXPLICIT_COUNT = 4,
    INPUT_SHARED_POSITION = 8,
    NULL_OFFSET_COUNT = 4,
    SHORT_COUNT = 2,
    OUTPUT_SIZE = EXPLICIT_COUNT + SHORT_COUNT,
};

_Static_assert(SYS_sendfile == 40, "x86 sendfile syscall number");
_Static_assert(sizeof(off_t) == sizeof(int64_t), "x86 signed 64-bit off_t");
_Static_assert((off_t)-1 < (off_t)0, "x86 off_t is signed");

struct sendfile_result {
    long value;
    int error;
};

static struct sendfile_result libc_sendfile(int out_fd, int in_fd,
                                            off_t *offset, size_t count)
{
    struct sendfile_result result;

    errno = 0;
    result.value = sendfile(out_fd, in_fd, offset, count);
    result.error = errno;
    return result;
}

static struct sendfile_result raw_sendfile(int out_fd, int in_fd,
                                           off_t *offset, size_t count)
{
    struct sendfile_result result;

    errno = 0;
    result.value = syscall(SYS_sendfile, (long)out_fd, (long)in_fd, offset,
                           (unsigned long)count);
    result.error = errno;
    return result;
}

static int is_success(struct sendfile_result result, long expected)
{
    return result.value == expected;
}

static int same_error(struct sendfile_result libc_result,
                      struct sendfile_result raw_result, int error)
{
    return libc_result.value == -1 && raw_result.value == -1 &&
           libc_result.error == error && raw_result.error == error;
}

static int current_position_is(int fd, off_t expected)
{
    return lseek(fd, 0, SEEK_CUR) == expected;
}

int main(void)
{
    static const unsigned char payload[PAYLOAD_SIZE] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    static const unsigned char expected_output[OUTPUT_SIZE] = {
        '2', '3', '4', '5', '8', '9'};
    char input_template[] = "/tmp/crabc-x86-sendfile-input-XXXXXX";
    char output_template[] = "/tmp/crabc-x86-sendfile-output-XXXXXX";
    unsigned char observed[OUTPUT_SIZE];
    struct stat input_status;
    struct stat output_status;
    struct sendfile_result libc_result;
    struct sendfile_result raw_result;
    off_t explicit_offset = EXPLICIT_OFFSET;
    off_t raw_explicit_offset = EXPLICIT_OFFSET;
    off_t libc_invalid_offset = -1;
    off_t raw_invalid_offset = -1;
    int input_fd = -1;
    int output_fd = -1;
    int closed_fd = -1;
    int result = 0;

    /* These names only construct unlinked regular-file fixture descriptors. */
    input_fd = mkstemp(input_template);
    if (input_fd < 0)
        return 10;
    output_fd = mkstemp(output_template);
    if (output_fd < 0) {
        result = 11;
        goto cleanup;
    }
    if (unlink(input_template) != 0 || unlink(output_template) != 0) {
        result = 12;
        goto cleanup;
    }
    if (fstat(input_fd, &input_status) != 0 ||
        fstat(output_fd, &output_status) != 0 ||
        !S_ISREG(input_status.st_mode) || !S_ISREG(output_status.st_mode)) {
        result = 13;
        goto cleanup;
    }
    if (write(input_fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload)) {
        result = 14;
        goto cleanup;
    }
    if (lseek(input_fd, INPUT_SHARED_POSITION, SEEK_SET) !=
        (off_t)INPUT_SHARED_POSITION) {
        result = 15;
        goto cleanup;
    }

    /* musl's explicit-offset call leaves the input descriptor position alone. */
    libc_result = libc_sendfile(output_fd, input_fd, &explicit_offset,
                                EXPLICIT_COUNT);
    if (!is_success(libc_result, EXPLICIT_COUNT) ||
        explicit_offset != EXPLICIT_OFFSET + EXPLICIT_COUNT ||
        !current_position_is(input_fd, INPUT_SHARED_POSITION) ||
        !current_position_is(output_fd, EXPLICIT_COUNT)) {
        result = 16;
        goto cleanup;
    }

    /* Reset the same fixture state to compare raw explicit-offset behavior. */
    if (ftruncate(output_fd, 0) != 0 ||
        !current_position_is(input_fd, INPUT_SHARED_POSITION) ||
        lseek(output_fd, 0, SEEK_SET) != 0) {
        result = 24;
        goto cleanup;
    }
    raw_result = raw_sendfile(output_fd, input_fd, &raw_explicit_offset,
                                EXPLICIT_COUNT);
    if (!is_success(raw_result, libc_result.value) ||
        raw_explicit_offset != explicit_offset ||
        !current_position_is(input_fd, INPUT_SHARED_POSITION) ||
        !current_position_is(output_fd, EXPLICIT_COUNT) ||
        pread(output_fd, observed, EXPLICIT_COUNT, 0) != EXPLICIT_COUNT ||
        memcmp(observed, payload + EXPLICIT_OFFSET, EXPLICIT_COUNT) != 0) {
        result = 25;
        goto cleanup;
    }

    /* The raw null-offset call advances the shared input position and is short. */
    raw_result = raw_sendfile(output_fd, input_fd, NULL, NULL_OFFSET_COUNT);
    if (!is_success(raw_result, SHORT_COUNT) ||
        !current_position_is(input_fd, PAYLOAD_SIZE) ||
        !current_position_is(output_fd, OUTPUT_SIZE)) {
        result = 17;
        goto cleanup;
    }

    /* At EOF, the pinned-musl null-offset call reports a zero-length transfer. */
    libc_result = libc_sendfile(output_fd, input_fd, NULL, 1);
    if (!is_success(libc_result, 0) || !current_position_is(input_fd, PAYLOAD_SIZE) ||
        !current_position_is(output_fd, OUTPUT_SIZE)) {
        result = 18;
        goto cleanup;
    }
    if (pread(output_fd, observed, sizeof(observed), 0) !=
            (ssize_t)sizeof(observed) ||
        memcmp(observed, expected_output, sizeof(observed)) != 0) {
        result = 19;
        goto cleanup;
    }

    libc_result = libc_sendfile(output_fd, input_fd, &libc_invalid_offset, 1);
    raw_result = raw_sendfile(output_fd, input_fd, &raw_invalid_offset, 1);
    if (!same_error(libc_result, raw_result, EINVAL) ||
        !current_position_is(input_fd, PAYLOAD_SIZE) ||
        !current_position_is(output_fd, OUTPUT_SIZE)) {
        result = 20;
        goto cleanup;
    }

    closed_fd = dup(input_fd);
    if (closed_fd < 0) {
        result = 21;
        goto cleanup;
    }
    if (close(closed_fd) != 0) {
        result = 22;
        goto cleanup;
    }
    libc_result = libc_sendfile(output_fd, closed_fd, NULL, 1);
    raw_result = raw_sendfile(output_fd, closed_fd, NULL, 1);
    if (!same_error(libc_result, raw_result, EBADF)) {
        result = 23;
        goto cleanup;
    }

cleanup:
    /* These also cover a failure before either fixture was unlinked. */
    (void)unlink(input_template);
    (void)unlink(output_template);
    if (output_fd >= 0 && close(output_fd) != 0 && result == 0)
        result = 30;
    if (input_fd >= 0 && close(input_fd) != 0 && result == 0)
        result = 31;
    if (result != 0)
        return result;

    puts("syscall=40 off_t=signed64 fixtures=regular-files "
        "explicit=offset2:advance6:input-position8:output-position4 "
        "null=short2:input-position10:output-position6 eof=zero "
         "payload=234589 raw=matches-musl-explicit errors=EINVAL,EBADF "
        "c-api-selection=excluded path-surface=excluded socket-network=excluded "
         "splice=excluded durability=unproved");
    return 0;
}
