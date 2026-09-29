/* Static crabc-libc x86-64 freestanding posix_fallocate fixture.
 *
 * This same project-header C body first runs through pinned musl 1.2.6 and
 * then through a `-nostdlib -static` executable linked solely with the
 * selected crabc archive. Raw Linux calls create, inspect, and remove the
 * unlinked temporary regular file; `posix_fallocate` is the only candidate C
 * entry point used for the subject behavior. It records mode-zero allocation
 * across extending, overlapping, and boundary ranges, plus invalid offsets,
 * lengths, and descriptors. Raw calls observe size, bytes, and file position.
 * It is not a general fallocate mode, pathname, CRT, pthread/TLS lifecycle,
 * loader, sysroot, or public x86-64 support test.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    PAYLOAD_SIZE = 8,
    POSITION = 3,
    RANGE_OFFSET = 4096,
    RANGE_LENGTH = 4096,
    RANGE_END = RANGE_OFFSET + RANGE_LENGTH,
    FINAL_END = RANGE_END + 2,
};

_Static_assert(SYS_open == 2 && SYS_close == 3 && SYS_write == 1 &&
    SYS_lseek == 8 && SYS_pread64 == 17 && SYS_fallocate == 285 &&
    SYS_getpid == 39 && SYS_unlink == 87,
    "x86 selected posix_fallocate fixture syscall numbers");
_Static_assert(sizeof(off_t) == sizeof(int64_t) && sizeof(off_t) == sizeof(long) &&
    (off_t)-1 < 0, "x86 signed 64-bit off_t");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_fallocate),
    int (*)(int, off_t, off_t)), "posix_fallocate declaration");

static const unsigned char payload[PAYLOAD_SIZE] = {
    'c', 'r', 'a', 'b', 'c', '-', 'x', '8',
};
static const unsigned char zeroes[PAYLOAD_SIZE];

static long raw0(long number)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw1(long number, long argument_one)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one) : "rcx", "r11", "memory");
    return result;
}

static long raw3(long number, long argument_one, long argument_two,
    long argument_three)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three) : "rcx", "r11", "memory");
    return result;
}

static long raw4(long number, long argument_one, long argument_two,
    long argument_three, long argument_four)
{
    long result;
    register long register_four __asm__("r10") = argument_four;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(register_four)
        : "rcx", "r11", "memory");
    return result;
}

static int make_path(char *output, size_t capacity, long process_id)
{
    static const char prefix[] = "/tmp/crabc-x86-posix-fallocate-";
    char digits[20];
    size_t length = 0;
    size_t prefix_length = 0;
    size_t digit_count = 0;
    unsigned long identifier;

    if (process_id <= 0)
        return -1;
    identifier = (unsigned long)process_id;
    while (prefix[prefix_length] != '\0') {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = prefix[prefix_length++];
    }
    do {
        if (digit_count == sizeof(digits))
            return -1;
        digits[digit_count++] = (char)('0' + identifier % 10);
        identifier /= 10;
    } while (identifier != 0);
    while (digit_count != 0) {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = digits[--digit_count];
    }
    output[length] = '\0';
    return 0;
}

static int close_fd(int descriptor)
{
    return descriptor >= 0 && raw1(SYS_close, descriptor) < 0 ? -1 : 0;
}

static int size_is_and_restore_position(int descriptor, off_t expected,
    off_t restored_position)
{
    return raw3(SYS_lseek, descriptor, 0, SEEK_END) == expected &&
        raw3(SYS_lseek, descriptor, restored_position, SEEK_SET) ==
            restored_position;
}

static long file_size_and_restore_position(int descriptor, off_t position)
{
    long size = raw3(SYS_lseek, descriptor, 0, SEEK_END);

    if (size < 0 || raw3(SYS_lseek, descriptor, position, SEEK_SET) != position)
        return -1;
    return size;
}

static int append_text(char *record, size_t *used, const char *value)
{
    while (*value != '\0') {
        if (*used == 255)
            return -1;
        record[(*used)++] = *value++;
    }
    return 0;
}

static int append_number(char *record, size_t *used, long value)
{
    char digits[20];
    size_t count = 0;
    unsigned long magnitude = value < 0 ? 0UL - (unsigned long)value :
        (unsigned long)value;

    if (value < 0 && append_text(record, used, "-") != 0)
        return -1;
    do {
        digits[count++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude != 0);
    while (count != 0) {
        if (*used == 255)
            return -1;
        record[(*used)++] = digits[--count];
    }
    return 0;
}

static int record_case(const char *name, off_t offset, off_t length,
    int status, int saved_errno, long size, long position)
{
    char record[256];
    size_t used = 0;

    if (append_text(record, &used, "case=") != 0 ||
        append_text(record, &used, name) != 0 ||
        append_text(record, &used, " offset=") != 0 ||
        append_number(record, &used, offset) != 0 ||
        append_text(record, &used, " length=") != 0 ||
        append_number(record, &used, length) != 0 ||
        append_text(record, &used, " status=") != 0 ||
        append_number(record, &used, status) != 0 ||
        append_text(record, &used, " errno=") != 0 ||
        append_number(record, &used, saved_errno) != 0 ||
        append_text(record, &used, " size=") != 0 ||
        append_number(record, &used, size) != 0 ||
        append_text(record, &used, " position=") != 0 ||
        append_number(record, &used, position) != 0 ||
        append_text(record, &used, "\n") != 0)
        return -1;
    return raw3(SYS_write, 1, (long)(void *)record, used) == (long)used ?
        0 : -1;
}

static int bytes_at_are(int descriptor, off_t offset,
    const unsigned char *expected, size_t length);

static int run_case(const char *name, int requested_descriptor,
    int observed_descriptor, off_t offset, off_t length, int sentinel,
    int expected_status, off_t expected_size)
{
    int status;
    int saved_errno;
    long position;
    long size;

    errno = sentinel;
    status = posix_fallocate(requested_descriptor, offset, length);
    saved_errno = errno;
    position = raw3(SYS_lseek, observed_descriptor, 0, SEEK_CUR);
    size = file_size_and_restore_position(observed_descriptor, position);
    if (record_case(name, offset, length, status, saved_errno, size,
            position) != 0 || status != expected_status ||
        saved_errno != sentinel || size != expected_size ||
        position != POSITION ||
        bytes_at_are(observed_descriptor, 0, payload, sizeof(payload)) != 0 ||
        bytes_at_are(observed_descriptor, RANGE_OFFSET, zeroes,
            sizeof(zeroes)) != 0)
        return -1;
    return 0;
}

static int bytes_at_are(int descriptor, off_t offset,
    const unsigned char *expected, size_t length)
{
    unsigned char observed[PAYLOAD_SIZE];
    long result;
    size_t index;

    if (length > sizeof(observed))
        return -1;
    result = raw4(SYS_pread64, descriptor, (long)(void *)observed,
        (long)length, offset);
    if (result != (long)length)
        return -1;
    for (index = 0; index < length; ++index) {
        if (observed[index] != expected[index])
            return -1;
    }
    return 0;
}

int crabc_x86_64_posix_fallocate_probe(void)
{
    char file_path[96] = { 0 };
    int descriptor = -1;
    int closed_descriptor = -1;
    int closed_status;
    int file_owned = 0;
    int result = 0;

    if (make_path(file_path, sizeof(file_path), raw0(SYS_getpid)) != 0)
        return 10;
    descriptor = (int)raw3(SYS_open, (long)(void *)file_path,
        O_CREAT | O_EXCL | O_RDWR, 0600);
    if (descriptor < 0) {
        result = 11;
        goto cleanup;
    }
    file_owned = 1;
    if (raw1(SYS_unlink, (long)(void *)file_path) < 0) {
        result = 12;
        goto cleanup;
    }
    file_owned = 0;
    if (!size_is_and_restore_position(descriptor, 0, 0)) {
        result = 13;
        goto cleanup;
    }
    if (raw3(SYS_write, descriptor, (long)(void *)payload,
            sizeof(payload)) != (long)sizeof(payload) ||
        raw3(SYS_lseek, descriptor, POSITION, SEEK_SET) != POSITION) {
        result = 14;
        goto cleanup;
    }

    if (run_case("extend", descriptor, descriptor, RANGE_OFFSET,
            RANGE_LENGTH, ERANGE, 0, RANGE_END) != 0 ||
        bytes_at_are(descriptor, PAYLOAD_SIZE, zeroes,
            sizeof(zeroes)) != 0) {
        result = 15;
        goto cleanup;
    }
    if (run_case("overlap", descriptor, descriptor, 1, 1,
            EDOM, 0, RANGE_END) != 0) {
        result = 16;
        goto cleanup;
    }
    if (run_case("edge", descriptor, descriptor, RANGE_END - 1, 1,
            E2BIG, 0, RANGE_END) != 0) {
        result = 17;
        goto cleanup;
    }
    if (run_case("adjacent", descriptor, descriptor, RANGE_END, 2,
            ERANGE, 0, FINAL_END) != 0 ||
        bytes_at_are(descriptor, RANGE_END, zeroes, 2) != 0) {
        result = 18;
        goto cleanup;
    }
    if (run_case("zero-length", descriptor, descriptor, 0, 0,
            EDOM, EINVAL, FINAL_END) != 0 ||
        run_case("negative-offset", descriptor, descriptor, -1, 1,
            E2BIG, EINVAL, FINAL_END) != 0 ||
        run_case("negative-length", descriptor, descriptor, 0, -1,
            ERANGE, EINVAL, FINAL_END) != 0 ||
        run_case("past-maximum", descriptor, descriptor, INT64_MAX, 1,
            EDOM, EFBIG, FINAL_END) != 0) {
        result = 19;
        goto cleanup;
    }

    closed_descriptor = descriptor;
    if (close_fd(descriptor) != 0) {
        result = 20;
        descriptor = -1;
        goto cleanup;
    }
    descriptor = -1;
    errno = ERANGE;
    closed_status = posix_fallocate(closed_descriptor, 0, 1);
    if (record_case("closed", 0, 1, closed_status, errno, -1, -1) != 0 ||
        closed_status != EBADF || errno != ERANGE) {
        result = 21;
        goto cleanup;
    }

cleanup:
    if (descriptor >= 0 && close_fd(descriptor) != 0 && result == 0)
        result = 30;
    if (file_owned && raw1(SYS_unlink, (long)(void *)file_path) < 0 &&
        result == 0)
        result = 31;
    return result;
}

#ifndef CRABC_POSIX_FALLOCATE_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_fallocate_probe();
}
#endif
