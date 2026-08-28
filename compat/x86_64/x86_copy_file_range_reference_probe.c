/* Pinned-musl/raw Linux/x86-64 copy_file_range(2) ABI and behavior reference. */

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
    PAYLOAD_SIZE = 10,
    INPUT_POSITION = 7,
    OUTPUT_POSITION = 3,
    EXPLICIT_INPUT_OFFSET = 1,
    EXPLICIT_OUTPUT_OFFSET = 5,
    EXPLICIT_COUNT = 4,
    NULL_OFFSET_COUNT = 8,
    NULL_OFFSET_SHORT_COUNT = 3,
};

_Static_assert(SYS_copy_file_range == 326, "x86 copy_file_range syscall number");
_Static_assert(sizeof(off_t) == sizeof(int64_t), "x86 signed 64-bit off_t");
_Static_assert((off_t)-1 < (off_t)0, "x86 off_t is signed");

struct copy_result {
    long value;
    int error;
};

static struct copy_result libc_copy_file_range(int in_fd, off_t *in_offset,
                                               int out_fd, off_t *out_offset,
                                               size_t count, unsigned flags)
{
    struct copy_result result;

    errno = 0;
    result.value = copy_file_range(in_fd, in_offset, out_fd, out_offset,
                                   count, flags);
    result.error = errno;
    return result;
}

static struct copy_result raw_copy_file_range(int in_fd, off_t *in_offset,
                                              int out_fd, off_t *out_offset,
                                              size_t count, unsigned flags)
{
    struct copy_result result;

    errno = 0;
    result.value = syscall(SYS_copy_file_range, (long)in_fd, in_offset,
                           (long)out_fd, out_offset, (unsigned long)count,
                           (unsigned long)flags);
    result.error = errno;
    return result;
}

static int is_success(struct copy_result result, long expected)
{
    return result.value == expected;
}

static int same_error(struct copy_result libc_result,
                      struct copy_result raw_result, int error)
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
    static const unsigned char explicit_bytes[EXPLICIT_COUNT] = {
        '1', '2', '3', '4'};
    static const unsigned char null_bytes[NULL_OFFSET_SHORT_COUNT] = {
        '7', '8', '9'};
    char input_template[] = "/tmp/crabc-x86-copy-file-range-input-XXXXXX";
    char output_template[] = "/tmp/crabc-x86-copy-file-range-output-XXXXXX";
    unsigned char observed[EXPLICIT_COUNT];
    struct stat input_status;
    struct stat output_status;
    struct copy_result libc_result;
    struct copy_result raw_result;
    off_t libc_explicit_input = EXPLICIT_INPUT_OFFSET;
    off_t libc_explicit_output = EXPLICIT_OUTPUT_OFFSET;
    off_t raw_explicit_input = EXPLICIT_INPUT_OFFSET;
    off_t raw_explicit_output = EXPLICIT_OUTPUT_OFFSET;
    off_t libc_invalid_offset = -1;
    off_t raw_invalid_offset = -1;
    int input_fd = -1;
    int output_fd = -1;
    int closed_fd = -1;
    int result = 0;

    /* Both unlinked fixture descriptors remain on the same /tmp filesystem. */
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
    if (lseek(input_fd, INPUT_POSITION, SEEK_SET) != (off_t)INPUT_POSITION ||
        lseek(output_fd, OUTPUT_POSITION, SEEK_SET) !=
            (off_t)OUTPUT_POSITION) {
        result = 15;
        goto cleanup;
    }

    /* musl explicit pointers leave both descriptor positions unchanged. */
    libc_result = libc_copy_file_range(
        input_fd, &libc_explicit_input, output_fd, &libc_explicit_output,
        EXPLICIT_COUNT, 0
    );
    if (!is_success(libc_result, EXPLICIT_COUNT) ||
        libc_explicit_input != EXPLICIT_INPUT_OFFSET + EXPLICIT_COUNT ||
        libc_explicit_output != EXPLICIT_OUTPUT_OFFSET + EXPLICIT_COUNT ||
        !current_position_is(input_fd, INPUT_POSITION) ||
        !current_position_is(output_fd, OUTPUT_POSITION) ||
        pread(output_fd, observed, sizeof(observed), EXPLICIT_OUTPUT_OFFSET) !=
            (ssize_t)sizeof(observed) ||
        memcmp(observed, explicit_bytes, sizeof(observed)) != 0) {
        result = 16;
        goto cleanup;
    }

    /* Reset the same state to compare raw explicit-pointer behavior. */
    if (ftruncate(output_fd, 0) != 0 ||
        !current_position_is(input_fd, INPUT_POSITION) ||
        lseek(output_fd, OUTPUT_POSITION, SEEK_SET) !=
            (off_t)OUTPUT_POSITION) {
        result = 24;
        goto cleanup;
    }
    raw_result = raw_copy_file_range(
        input_fd, &raw_explicit_input, output_fd, &raw_explicit_output,
        EXPLICIT_COUNT, 0
    );
    if (!is_success(raw_result, libc_result.value) ||
        raw_explicit_input != libc_explicit_input ||
        raw_explicit_output != libc_explicit_output ||
        !current_position_is(input_fd, INPUT_POSITION) ||
        !current_position_is(output_fd, OUTPUT_POSITION) ||
        pread(output_fd, observed, sizeof(observed), EXPLICIT_OUTPUT_OFFSET) !=
            (ssize_t)sizeof(observed) ||
        memcmp(observed, explicit_bytes, sizeof(observed)) != 0) {
        result = 25;
        goto cleanup;
    }

    /* Null pointers use shared positions and may produce a short copy. */
    if (ftruncate(output_fd, 0) != 0 ||
        !current_position_is(input_fd, INPUT_POSITION) ||
        lseek(output_fd, OUTPUT_POSITION, SEEK_SET) !=
            (off_t)OUTPUT_POSITION) {
        result = 26;
        goto cleanup;
    }
    raw_result = raw_copy_file_range(
        input_fd, NULL, output_fd, NULL, NULL_OFFSET_COUNT, 0
    );
    if (!is_success(raw_result, NULL_OFFSET_SHORT_COUNT) ||
        !current_position_is(input_fd, PAYLOAD_SIZE) ||
        !current_position_is(output_fd, OUTPUT_POSITION + NULL_OFFSET_SHORT_COUNT) ||
        pread(output_fd, observed, NULL_OFFSET_SHORT_COUNT, OUTPUT_POSITION) !=
            NULL_OFFSET_SHORT_COUNT ||
        memcmp(observed, null_bytes, NULL_OFFSET_SHORT_COUNT) != 0) {
        result = 17;
        goto cleanup;
    }

    /* At EOF, musl's null-pointer form reports a zero-length transfer. */
    libc_result = libc_copy_file_range(input_fd, NULL, output_fd, NULL, 1, 0);
    if (!is_success(libc_result, 0) ||
        !current_position_is(input_fd, PAYLOAD_SIZE) ||
        !current_position_is(output_fd, OUTPUT_POSITION + NULL_OFFSET_SHORT_COUNT)) {
        result = 18;
        goto cleanup;
    }

    libc_result = libc_copy_file_range(
        input_fd, &libc_invalid_offset, output_fd, NULL, 1, 0
    );
    raw_result = raw_copy_file_range(
        input_fd, &raw_invalid_offset, output_fd, NULL, 1, 0
    );
    if (!same_error(libc_result, raw_result, EOVERFLOW) ||
        !current_position_is(input_fd, PAYLOAD_SIZE) ||
        !current_position_is(output_fd, OUTPUT_POSITION + NULL_OFFSET_SHORT_COUNT)) {
        result = 19;
        goto cleanup;
    }

    libc_result = libc_copy_file_range(input_fd, NULL, output_fd, NULL, 1, 1);
    raw_result = raw_copy_file_range(input_fd, NULL, output_fd, NULL, 1, 1);
    if (!same_error(libc_result, raw_result, EINVAL) ||
        !current_position_is(input_fd, PAYLOAD_SIZE) ||
        !current_position_is(output_fd, OUTPUT_POSITION + NULL_OFFSET_SHORT_COUNT)) {
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
    libc_result = libc_copy_file_range(closed_fd, NULL, output_fd, NULL, 1, 0);
    raw_result = raw_copy_file_range(closed_fd, NULL, output_fd, NULL, 1, 0);
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

    puts("syscall=326 off_t=signed64 fixtures=same-filesystem-regular-files "
         "explicit=in1:out5:advance5,9:positions7,3 "
         "null=short3:positions10,6 eof=zero payload=1234,789 "
         "raw=matches-musl-explicit errors=EOVERFLOW,EINVAL,EBADF flags=zero-only "
         "c-api-selection=excluded path-surface=excluded "
         "sendfile-splice-fallback=excluded copy-policy=excluded");
    return 0;
}
