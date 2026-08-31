/* Static Linux/x86-64 GNU copy_file_range C ABI and pinned-musl behavior fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * through a true static crabc archive. The named boundary forwards one
 * same-filesystem regular-file explicit-offset request: wrapper and raw
 * syscall results, pointed offset updates, stable shared positions, and copied
 * bytes agree; a successful wrapper retains stale errno; invalid flags and a
 * bad input descriptor report EINVAL and EBADF. Fixture-local raw syscalls
 * create, write, seek, inspect, close, and unlink disposable files; they are
 * not selected C descriptor, pathname, copy-policy, or durability APIs.
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
    PATH_CAPACITY = 96,
    INPUT_POSITION = 7,
    OUTPUT_POSITION = 3,
    TRANSFER_INPUT_OFFSET = 1,
    TRANSFER_OUTPUT_OFFSET = 5,
    TRANSFER_LENGTH = 4,
};

typedef ssize_t (*copy_file_range_signature)(int, off_t *, int, off_t *,
    size_t, unsigned);

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(off_t) == sizeof(long), "x86 LP64 off_t ABI");
_Static_assert(SYS_write == 1 && SYS_close == 3 && SYS_lseek == 8 &&
    SYS_pread64 == 17 && SYS_getpid == 39 && SYS_openat == 257 &&
    SYS_unlinkat == 263 && SYS_copy_file_range == 326,
    "x86 selected copy_file_range fixture syscall numbers");
_Static_assert(AT_FDCWD == -100 && O_RDWR == 02 && O_CREAT == 0100 &&
    O_EXCL == 0200 && O_CLOEXEC == 02000000,
    "x86 selected copy_file_range fixture constants");
_Static_assert(SEEK_SET == 0 && SEEK_CUR == 1, "x86 seek constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&copy_file_range),
    copy_file_range_signature), "copy_file_range declaration");

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long argument4_r10 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(argument4_r10)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall6(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5, long argument6)
{
    long result;
    register long argument4_r10 __asm__("r10") = argument4;
    register long argument5_r8 __asm__("r8") = argument5;
    register long argument6_r9 __asm__("r9") = argument6;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(argument4_r10), "r"(argument5_r8), "r"(argument6_r9)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_openat(const char *path, int flags, unsigned mode)
{
    return (int)raw_syscall4(SYS_openat, AT_FDCWD, (long)(uintptr_t)path,
        flags, mode);
}

static int raw_unlinkat(const char *path)
{
    return (int)raw_syscall3(SYS_unlinkat, AT_FDCWD,
        (long)(uintptr_t)path, 0);
}

static void raw_close(int descriptor)
{
    if (descriptor >= 0)
        (void)raw_syscall1(SYS_close, descriptor);
}

static long raw_copy_file_range(int input_descriptor, off_t *input_offset,
    int output_descriptor, off_t *output_offset, size_t length, unsigned flags)
{
    return raw_syscall6(SYS_copy_file_range, input_descriptor,
        (long)(uintptr_t)input_offset, output_descriptor,
        (long)(uintptr_t)output_offset, (long)length, flags);
}

static int make_path(char path[PATH_CAPACITY], char suffix)
{
    static const char prefix[] = "/tmp/crabc-x86-static-copy-file-range-";
    char reverse_digits[20];
    long process_id = raw_syscall0(SYS_getpid);
    size_t digits = 0;
    size_t index;

    if (process_id <= 0)
        return -1;
    do {
        reverse_digits[digits++] = (char)('0' + (process_id % 10));
        process_id /= 10;
    } while (process_id != 0 && digits < sizeof(reverse_digits));
    if (process_id != 0 || sizeof(prefix) + digits + 2 > PATH_CAPACITY)
        return -1;

    for (index = 0; index < sizeof(prefix) - 1; ++index)
        path[index] = prefix[index];
    while (digits != 0)
        path[index++] = reverse_digits[--digits];
    path[index++] = '-';
    path[index++] = suffix;
    path[index] = '\0';
    return 0;
}

static int create_input_file(char suffix)
{
    static const char payload[] = "0123456789abcdef";
    char path[PATH_CAPACITY];
    int descriptor;

    if (make_path(path, suffix) != 0)
        return -1;
    (void)raw_unlinkat(path);
    descriptor = raw_openat(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0)
        return -1;
    if (raw_syscall3(SYS_write, descriptor, (long)(uintptr_t)payload,
            sizeof(payload) - 1) != (long)(sizeof(payload) - 1) ||
        raw_syscall3(SYS_lseek, descriptor, INPUT_POSITION, SEEK_SET) !=
            INPUT_POSITION) {
        raw_close(descriptor);
        (void)raw_unlinkat(path);
        return -1;
    }
    (void)raw_unlinkat(path);
    return descriptor;
}

static int create_output_file(char suffix)
{
    char path[PATH_CAPACITY];
    int descriptor;

    if (make_path(path, suffix) != 0)
        return -1;
    (void)raw_unlinkat(path);
    descriptor = raw_openat(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0)
        return -1;
    if (raw_syscall3(SYS_lseek, descriptor, OUTPUT_POSITION, SEEK_SET) !=
        OUTPUT_POSITION) {
        raw_close(descriptor);
        (void)raw_unlinkat(path);
        return -1;
    }
    (void)raw_unlinkat(path);
    return descriptor;
}

static int check_payload(int descriptor)
{
    static const char expected[] = "1234";
    char observed[TRANSFER_LENGTH];
    size_t index;

    if (raw_syscall4(SYS_pread64, descriptor, (long)(uintptr_t)observed,
            sizeof(observed), TRANSFER_OUTPUT_OFFSET) != (long)sizeof(observed))
        return 1;
    for (index = 0; index < sizeof(observed); ++index) {
        if (observed[index] != expected[index])
            return 2;
    }
    return 0;
}

static int check_fixture(void)
{
    int wrapper_input = -1;
    int wrapper_output = -1;
    int raw_input = -1;
    int raw_output = -1;
    off_t wrapper_input_offset = TRANSFER_INPUT_OFFSET;
    off_t wrapper_output_offset = TRANSFER_OUTPUT_OFFSET;
    off_t raw_input_offset = TRANSFER_INPUT_OFFSET;
    off_t raw_output_offset = TRANSFER_OUTPUT_OFFSET;
    long raw_result;
    ssize_t wrapper_result;
    int wrapper_errno;
    int status = 0;

    wrapper_input = create_input_file('w');
    wrapper_output = create_output_file('x');
    raw_input = create_input_file('r');
    raw_output = create_output_file('s');
    if (wrapper_input < 0 || wrapper_output < 0 || raw_input < 0 || raw_output < 0) {
        status = 1;
        goto cleanup;
    }

    raw_result = raw_copy_file_range(raw_input, &raw_input_offset, raw_output,
        &raw_output_offset, TRANSFER_LENGTH, 0);
    errno = ERANGE;
    wrapper_result = copy_file_range(wrapper_input, &wrapper_input_offset,
        wrapper_output, &wrapper_output_offset, TRANSFER_LENGTH, 0);
    wrapper_errno = errno;
    if (raw_result != TRANSFER_LENGTH || wrapper_result != raw_result ||
        wrapper_errno != ERANGE) {
        status = 2;
        goto cleanup;
    }
    if (raw_input_offset != TRANSFER_INPUT_OFFSET + TRANSFER_LENGTH ||
        raw_output_offset != TRANSFER_OUTPUT_OFFSET + TRANSFER_LENGTH ||
        wrapper_input_offset != raw_input_offset ||
        wrapper_output_offset != raw_output_offset) {
        status = 3;
        goto cleanup;
    }
    if (raw_syscall3(SYS_lseek, raw_input, 0, SEEK_CUR) != INPUT_POSITION ||
        raw_syscall3(SYS_lseek, raw_output, 0, SEEK_CUR) != OUTPUT_POSITION ||
        raw_syscall3(SYS_lseek, wrapper_input, 0, SEEK_CUR) != INPUT_POSITION ||
        raw_syscall3(SYS_lseek, wrapper_output, 0, SEEK_CUR) != OUTPUT_POSITION) {
        status = 4;
        goto cleanup;
    }
    if (check_payload(raw_output) != 0 || check_payload(wrapper_output) != 0) {
        status = 5;
        goto cleanup;
    }

    raw_result = raw_copy_file_range(raw_input, 0, raw_output, 0, 1, 1);
    errno = E2BIG;
    if (copy_file_range(wrapper_input, 0, wrapper_output, 0, 1, 1) != -1 ||
        errno != EINVAL || raw_result != -EINVAL) {
        status = 6;
        goto cleanup;
    }
    if (raw_syscall3(SYS_lseek, raw_input, 0, SEEK_CUR) != INPUT_POSITION ||
        raw_syscall3(SYS_lseek, raw_output, 0, SEEK_CUR) != OUTPUT_POSITION ||
        raw_syscall3(SYS_lseek, wrapper_input, 0, SEEK_CUR) != INPUT_POSITION ||
        raw_syscall3(SYS_lseek, wrapper_output, 0, SEEK_CUR) != OUTPUT_POSITION) {
        status = 7;
        goto cleanup;
    }

    raw_result = raw_copy_file_range(-1, 0, raw_output, 0, 1, 0);
    errno = E2BIG;
    if (copy_file_range(-1, 0, wrapper_output, 0, 1, 0) != -1 ||
        errno != EBADF || raw_result != -EBADF) {
        status = 8;
        goto cleanup;
    }

cleanup:
    raw_close(wrapper_input);
    raw_close(wrapper_output);
    raw_close(raw_input);
    raw_close(raw_output);
    return status;
}

int crabc_x86_64_copy_file_range_probe(void)
{
    return check_fixture();
}

#ifndef CRABC_COPY_FILE_RANGE_FREESTANDING
int main(void)
{
    return crabc_x86_64_copy_file_range_probe();
}
#endif
