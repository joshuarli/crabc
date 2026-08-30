/* Static crabc-libc x86-64 freestanding posix_fallocate fixture.
 *
 * This same project-header C body first runs through pinned musl 1.2.6 and
 * then through a `-nostdlib -static` executable linked solely with the
 * selected crabc archive. Raw Linux calls create, inspect, and remove the
 * unlinked temporary regular file; `posix_fallocate` is the only candidate C
 * entry point used for the subject behavior. It proves the fixed mode-zero range
 * over the half-open [4096, 8192) range, retained existing bytes, zero-filled extension,
 * preserved file position, direct POSIX error values, and unchanged errno.
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

static int position_is(int descriptor, off_t expected)
{
    return raw3(SYS_lseek, descriptor, 0, SEEK_CUR) == expected;
}

static int size_is_and_restore_position(int descriptor, off_t expected,
    off_t restored_position)
{
    return raw3(SYS_lseek, descriptor, 0, SEEK_END) == expected &&
        raw3(SYS_lseek, descriptor, restored_position, SEEK_SET) ==
            restored_position;
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

static int allocated_file_is_expected(int descriptor)
{
    return position_is(descriptor, (off_t)POSITION) &&
        size_is_and_restore_position(descriptor, (off_t)RANGE_END,
            (off_t)POSITION) &&
        bytes_at_are(descriptor, 0, payload, sizeof(payload)) == 0 &&
        bytes_at_are(descriptor, (off_t)PAYLOAD_SIZE, zeroes,
            sizeof(zeroes)) == 0 &&
        bytes_at_are(descriptor, 4096, zeroes, sizeof(zeroes)) == 0 &&
        position_is(descriptor, (off_t)POSITION);
}

int crabc_x86_64_posix_fallocate_probe(void)
{
    char file_path[96] = { 0 };
    int descriptor = -1;
    int closed_descriptor = -1;
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

    errno = ERANGE;
    if (posix_fallocate(descriptor, (off_t)RANGE_OFFSET,
            (off_t)RANGE_LENGTH) != 0 || errno != ERANGE ||
        !allocated_file_is_expected(descriptor)) {
        result = 15;
        goto cleanup;
    }

    errno = EDOM;
    if (posix_fallocate(descriptor, 0, 0) != EINVAL || errno != EDOM ||
        !allocated_file_is_expected(descriptor)) {
        result = 16;
        goto cleanup;
    }

    errno = E2BIG;
    if (posix_fallocate(descriptor, (off_t)-1, 1) != EINVAL ||
        errno != E2BIG || !allocated_file_is_expected(descriptor)) {
        result = 17;
        goto cleanup;
    }

    closed_descriptor = descriptor;
    if (close_fd(descriptor) != 0) {
        result = 18;
        descriptor = -1;
        goto cleanup;
    }
    descriptor = -1;
    errno = ERANGE;
    if (posix_fallocate(closed_descriptor, 0, 1) != EBADF ||
        errno != ERANGE) {
        result = 19;
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
