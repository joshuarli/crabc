/* Static crabc-libc x86-64 freestanding descriptor-advice fixture.
 *
 * This project-header C body first executes through pinned musl 1.2.6 and
 * then through one `-nostdlib -static` executable linked solely with the
 * selected crabc archive. Raw Linux calls create, size, inspect, and remove
 * the unlinked regular file; `posix_fadvise` and `readahead` are the only
 * candidate C entry points used for the subject behavior. It proves the six
 * fixed POSIX advice values, position preservation, direct POSIX error
 * returns without errno publication, and ordinary `-1`/errno readahead
 * results. It is not a cache-effect, filesystem policy, pathname, CRT,
 * pthread/TLS lifecycle, loader, sysroot, or public x86-64 support test.
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
    FILE_SIZE = 8192,
    POSITION = 19,
};

_Static_assert(SYS_open == 2 && SYS_close == 3 && SYS_lseek == 8 &&
    SYS_ftruncate == 77 && SYS_getpid == 39 && SYS_unlink == 87 &&
    SYS_readahead == 187 && SYS_fadvise64 == 221,
    "x86 selected descriptor-advice fixture syscall numbers");
_Static_assert(sizeof(off_t) == sizeof(int64_t) && sizeof(off_t) == sizeof(long) &&
    (off_t)-1 < 0, "x86 signed 64-bit off_t");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_fadvise),
    int (*)(int, off_t, off_t, int)), "posix_fadvise declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readahead),
    ssize_t (*)(int, off_t, size_t)), "readahead declaration");
_Static_assert(POSIX_FADV_NORMAL == 0 && POSIX_FADV_RANDOM == 1 &&
    POSIX_FADV_SEQUENTIAL == 2 && POSIX_FADV_WILLNEED == 3 &&
    POSIX_FADV_DONTNEED == 4 && POSIX_FADV_NOREUSE == 5,
    "x86 POSIX advice values");

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

static int make_path(char *output, size_t capacity, long process_id)
{
    static const char prefix[] = "/tmp/crabc-x86-descriptor-advice-";
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

static int file_state_is_expected(int descriptor)
{
    return position_is(descriptor, (off_t)POSITION) &&
        raw3(SYS_lseek, descriptor, 0, SEEK_END) == FILE_SIZE &&
        raw3(SYS_lseek, descriptor, POSITION, SEEK_SET) == POSITION &&
        position_is(descriptor, (off_t)POSITION);
}

int crabc_x86_64_descriptor_advice_probe(void)
{
    static const int policies[] = {
        POSIX_FADV_NORMAL,
        POSIX_FADV_RANDOM,
        POSIX_FADV_SEQUENTIAL,
        POSIX_FADV_WILLNEED,
        POSIX_FADV_DONTNEED,
        POSIX_FADV_NOREUSE,
    };
    char file_path[96] = { 0 };
    int descriptor = -1;
    int closed_descriptor = -1;
    int file_owned = 0;
    int result = 0;
    size_t index;

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
    if (raw2(SYS_ftruncate, descriptor, FILE_SIZE) < 0 ||
        raw3(SYS_lseek, descriptor, POSITION, SEEK_SET) != POSITION ||
        !file_state_is_expected(descriptor)) {
        result = 13;
        goto cleanup;
    }

    for (index = 0; index < sizeof(policies) / sizeof(policies[0]); ++index) {
        errno = ERANGE;
        if (posix_fadvise(descriptor, 0,
                index == 0 ? 0 : (off_t)FILE_SIZE, policies[index]) != 0 ||
            errno != ERANGE || !file_state_is_expected(descriptor)) {
            result = 14;
            goto cleanup;
        }
    }

    errno = EDOM;
    if (posix_fadvise(descriptor, 0, 1, 6) != EINVAL || errno != EDOM ||
        !file_state_is_expected(descriptor)) {
        result = 15;
        goto cleanup;
    }
    errno = E2BIG;
    if (posix_fadvise(descriptor, 0, (off_t)-1, POSIX_FADV_NORMAL) != EINVAL ||
        errno != E2BIG || !file_state_is_expected(descriptor)) {
        result = 16;
        goto cleanup;
    }

    errno = ERANGE;
    if (readahead(descriptor, 0, FILE_SIZE) != 0 || errno != ERANGE ||
        !file_state_is_expected(descriptor)) {
        result = 17;
        goto cleanup;
    }
    errno = EDOM;
    if (readahead(descriptor, 0, (size_t)-1) != -1 || errno != EINVAL ||
        !file_state_is_expected(descriptor)) {
        result = 18;
        goto cleanup;
    }

    closed_descriptor = descriptor;
    if (close_fd(descriptor) != 0) {
        result = 19;
        descriptor = -1;
        goto cleanup;
    }
    descriptor = -1;
    errno = ERANGE;
    if (posix_fadvise(closed_descriptor, 0, 0, POSIX_FADV_NORMAL) != EBADF ||
        errno != ERANGE) {
        result = 20;
        goto cleanup;
    }
    errno = EDOM;
    if (readahead(closed_descriptor, 0, 0) != -1 || errno != EBADF) {
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

#ifndef CRABC_DESCRIPTOR_ADVICE_FREESTANDING
int main(void)
{
    return crabc_x86_64_descriptor_advice_probe();
}
#endif
