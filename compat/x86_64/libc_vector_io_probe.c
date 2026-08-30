/* Static crabc-libc x86-64 selected vector-I/O fixture.
 *
 * The same project-header C body first executes with pinned musl 1.2.6, then
 * with a `-nostdlib -static` executable linked solely with crabc `libc.a`.
 * Fixture-local raw syscalls make and inspect an anonymous regular file;
 * `readv`, `writev`, `preadv`, and `pwritev` are the only candidate C entry
 * points selected. It proves vector ordering, positioned-offset stability,
 * kernel-owned invalid iovec-count/negative-offset errors, and pwritev's
 * append boundary. It is not scalar descriptor I/O, cancellation, stdio,
 * CRT, loader, sysroot, or public x86 support evidence.
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
#include <sys/uio.h>
#include <unistd.h>

_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8,
    "x86 iovec ABI");
_Static_assert(sizeof(off_t) == 8 && (off_t)-1 < 0,
    "x86 signed LP64 off_t");
_Static_assert(SYS_readv == 19 && SYS_writev == 20 && SYS_preadv == 295 &&
    SYS_pwritev == 296 && SYS_pwritev2 == 328 && SYS_memfd_create == 319,
    "x86 vector-I/O syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readv),
    ssize_t (*)(int, const struct iovec *, int)), "readv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&writev),
    ssize_t (*)(int, const struct iovec *, int)), "writev declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&preadv),
    ssize_t (*)(int, const struct iovec *, int, off_t)), "preadv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pwritev),
    ssize_t (*)(int, const struct iovec *, int, off_t)), "pwritev declaration");

static long raw1(long number, long argument_one)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one) : "rcx", "r11", "memory");
    return result;
}

static long raw2(long number, long argument_one, long argument_two)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two)
        : "rcx", "r11", "memory");
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

static int same_bytes(const char *left, const char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static void raw_close(int descriptor)
{
    if (descriptor >= 0)
        (void)raw1(SYS_close, descriptor);
}

int crabc_x86_64_vector_io_probe(void)
{
    static const char expected[] = "aXYd";
    static const char append_expected[] = "XYYd";
    static const off_t high_offset = ((off_t)1 << 32) + 17;
    char first[] = "ab";
    char second[] = "cd";
    char x[] = "X";
    char y[] = "Y";
    char high_written[] = "H";
    char high_read[] = { 0 };
    char received[4] = { 0, 0, 0, 0 };
    char received_second[4] = { 0, 0, 0, 0 };
    struct iovec write_parts[2] = {
        { first, sizeof(first) - 1 }, { second, sizeof(second) - 1 },
    };
    struct iovec positioned_parts[2] = {
        { x, sizeof(x) - 1 }, { y, sizeof(y) - 1 },
    };
    struct iovec read_parts[2] = {
        { received, 2 }, { received + 2, 2 },
    };
    struct iovec read_second_parts[2] = {
        { received_second, 1 }, { received_second + 1, 3 },
    };
    struct iovec high_write_part[1] = {
        { high_written, sizeof(high_written) - 1 },
    };
    struct iovec high_read_part[1] = {
        { high_read, sizeof(high_read) },
    };
    int descriptor = -1;
    int original_flags;
    int result = 0;

    descriptor = (int)raw2(SYS_memfd_create, (long)(void *)"crabc-vector-io", 0);
    if (descriptor < 0)
        return 10;
    if (writev(descriptor, write_parts, 2) != 4 ||
        raw3(SYS_lseek, descriptor, 0, SEEK_CUR) != 4) {
        result = 11;
        goto finish;
    }
    if (pwritev(descriptor, positioned_parts, 2, 1) != 2 ||
        raw3(SYS_lseek, descriptor, 0, SEEK_CUR) != 4) {
        result = 12;
        goto finish;
    }
    if (preadv(descriptor, read_parts, 2, 0) != 4 ||
        !same_bytes(received, expected, sizeof(received)) ||
        raw3(SYS_lseek, descriptor, 0, SEEK_CUR) != 4) {
        result = 13;
        goto finish;
    }
    if (raw3(SYS_lseek, descriptor, 0, SEEK_SET) != 0 ||
        readv(descriptor, read_second_parts, 2) != 4 ||
        !same_bytes(received_second, expected, sizeof(received_second)) ||
        raw3(SYS_lseek, descriptor, 0, SEEK_CUR) != 4) {
        result = 14;
        goto finish;
    }

    if (pwritev(descriptor, high_write_part, 1, high_offset) != 1 ||
        raw3(SYS_lseek, descriptor, 0, SEEK_END) != high_offset + 1 ||
        raw3(SYS_lseek, descriptor, 4, SEEK_SET) != 4 ||
        preadv(descriptor, high_read_part, 1, high_offset) != 1 ||
        !same_bytes(high_read, high_written, sizeof(high_read)) ||
        raw3(SYS_lseek, descriptor, 0, SEEK_CUR) != 4) {
        result = 15;
        goto finish;
    }

    errno = 0;
    if (readv(descriptor, read_parts, -1) != -1 || errno != EINVAL) {
        result = 16;
        goto finish;
    }
    errno = 0;
    if (preadv(descriptor, read_parts, 2, -1) != -1 || errno != EINVAL) {
        result = 17;
        goto finish;
    }
    errno = 0;
    if (pwritev(descriptor, positioned_parts, 2, -1) != -1 || errno != EINVAL) {
        result = 18;
        goto finish;
    }

    original_flags = (int)raw2(SYS_fcntl, descriptor, F_GETFL);
    if (original_flags < 0 ||
        raw3(SYS_fcntl, descriptor, F_SETFL, original_flags | O_APPEND) != 0) {
        result = 19;
        goto finish;
    }
    errno = 0;
    result = pwritev(descriptor, positioned_parts, 2, 0);
    if ((result == 2 &&
            (preadv(descriptor, read_parts, 2, 0) != 4 ||
                !same_bytes(received, append_expected, sizeof(received)))) ||
        (result == -1 &&
            (errno != EOPNOTSUPP || preadv(descriptor, read_parts, 2, 0) != 4 ||
                !same_bytes(received, expected, sizeof(received)))) ||
        (result != 2 && result != -1)) {
        result = 20;
        goto restore_flags;
    }

    result = 0;

restore_flags:
    if (raw3(SYS_fcntl, descriptor, F_SETFL, original_flags) != 0 && result == 0)
        result = 21;
finish:
    raw_close(descriptor);
    return result;
}

#ifndef CRABC_VECTOR_IO_FREESTANDING
int main(void)
{
    return crabc_x86_64_vector_io_probe();
}
#endif
