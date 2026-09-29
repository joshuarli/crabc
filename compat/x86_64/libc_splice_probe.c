/* Static Linux/x86-64 GNU splice C ABI and pinned-musl behavior fixture.
 *
 * One project-header C body runs through pinned musl and a static crabc
 * archive. Raw kernel calls prepare and inspect file/pipe state; selected
 * splice calls cross the libc boundary. Raw tee and vmsplice calls exercise
 * pipe composition without selecting their C exports. Every named scenario
 * also runs with raw splice, and both static programs emit identical records.
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

enum {
    PATH_CAPACITY = 96,
    INPUT_POSITION = 7,
    TRANSFER_INPUT_OFFSET = 1,
    TRANSFER_LENGTH = 4,
};

#define INVALID_SPLICE_FLAGS 0x80000000U

typedef ssize_t (*splice_signature)(int, off_t *, int, off_t *, size_t,
    unsigned);

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(off_t) == sizeof(long), "x86 LP64 off_t ABI");
_Static_assert(SYS_write == 1 && SYS_close == 3 && SYS_lseek == 8 &&
    SYS_getpid == 39 && SYS_openat == 257 && SYS_unlinkat == 263 &&
    SYS_splice == 275 && SYS_tee == 276 && SYS_vmsplice == 278 &&
    SYS_pipe2 == 293,
    "x86 selected splice fixture syscall numbers");
_Static_assert(AT_FDCWD == -100 && O_RDWR == 02 && O_CREAT == 0100 &&
    O_EXCL == 0200 && O_CLOEXEC == 02000000,
    "x86 selected splice fixture constants");
_Static_assert(SEEK_SET == 0 && SEEK_CUR == 1, "x86 seek constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&splice),
    splice_signature), "splice declaration");

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

static long raw_syscall2(long number, long argument1, long argument2)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2)
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

static int raw_pipe2(int descriptors[2])
{
    return (int)raw_syscall2(SYS_pipe2, (long)(uintptr_t)descriptors, 0);
}

static long raw_splice(int input_descriptor, off_t *input_offset,
    int output_descriptor, off_t *output_offset, size_t length, unsigned flags)
{
    return raw_syscall6(SYS_splice, input_descriptor,
        (long)(uintptr_t)input_offset, output_descriptor,
        (long)(uintptr_t)output_offset, (long)length, (long)flags);
}

static long selected_splice(int selected, int input_descriptor,
    off_t *input_offset, int output_descriptor, off_t *output_offset,
    size_t length, unsigned flags, int *observed_errno)
{
    long result;

    errno = ERANGE;
    if (selected) {
        result = splice(input_descriptor, input_offset, output_descriptor,
            output_offset, length, flags);
        *observed_errno = errno;
        return result;
    }
    result = raw_splice(input_descriptor, input_offset, output_descriptor,
        output_offset, length, flags);
    *observed_errno = result < 0 ? (int)-result : ERANGE;
    return result < 0 ? -1 : result;
}

static long raw_tee(int input_descriptor, int output_descriptor,
    size_t length, unsigned flags)
{
    return raw_syscall4(SYS_tee, input_descriptor, output_descriptor,
        (long)length, flags);
}

static long raw_vmsplice(int descriptor, const struct iovec *iov,
    size_t count, unsigned flags)
{
    return raw_syscall4(SYS_vmsplice, descriptor, (long)(uintptr_t)iov,
        (long)count, flags);
}

static int same_bytes(const char *actual, const char *expected, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (actual[index] != expected[index])
            return 0;
    }
    return 1;
}

static void emit(const char *message)
{
    size_t length = 0;

    while (message[length] != '\0')
        ++length;
    (void)raw_syscall3(SYS_write, 1, (long)(uintptr_t)message, length);
}

static int make_path(char path[PATH_CAPACITY], char suffix)
{
    static const char prefix[] = "/tmp/crabc-x86-static-splice-";
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

static int check_pipe_payload(int descriptor)
{
    static const char expected[] = "1234";
    char observed[TRANSFER_LENGTH];
    size_t index;

    if (raw_syscall3(SYS_read, descriptor, (long)(uintptr_t)observed,
            sizeof(observed)) != (long)sizeof(observed))
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
    int raw_input = -1;
    int wrapper_pipe[2] = { -1, -1 };
    int raw_pipe[2] = { -1, -1 };
    off_t wrapper_input_offset = TRANSFER_INPUT_OFFSET;
    off_t raw_input_offset = TRANSFER_INPUT_OFFSET;
    long raw_result;
    ssize_t wrapper_result;
    int wrapper_errno;
    int status = 0;

    wrapper_input = create_input_file('w');
    raw_input = create_input_file('r');
    if (wrapper_input < 0 || raw_input < 0 || raw_pipe2(wrapper_pipe) != 0 ||
        raw_pipe2(raw_pipe) != 0) {
        status = 1;
        goto cleanup;
    }

    raw_result = raw_splice(raw_input, &raw_input_offset, raw_pipe[1], 0,
        TRANSFER_LENGTH, 0);
    errno = ERANGE;
    wrapper_result = splice(wrapper_input, &wrapper_input_offset,
        wrapper_pipe[1], 0, TRANSFER_LENGTH, 0);
    wrapper_errno = errno;
    if (raw_result != TRANSFER_LENGTH || wrapper_result != raw_result ||
        wrapper_errno != ERANGE) {
        status = 2;
        goto cleanup;
    }
    if (raw_input_offset != TRANSFER_INPUT_OFFSET + TRANSFER_LENGTH ||
        wrapper_input_offset != raw_input_offset) {
        status = 3;
        goto cleanup;
    }
    if (raw_syscall3(SYS_lseek, raw_input, 0, SEEK_CUR) != INPUT_POSITION ||
        raw_syscall3(SYS_lseek, wrapper_input, 0, SEEK_CUR) != INPUT_POSITION) {
        status = 4;
        goto cleanup;
    }
    if (check_pipe_payload(raw_pipe[0]) != 0 ||
        check_pipe_payload(wrapper_pipe[0]) != 0) {
        status = 5;
        goto cleanup;
    }

    raw_result = raw_splice(raw_input, 0, raw_pipe[1], 0, 1,
        INVALID_SPLICE_FLAGS);
    errno = E2BIG;
    if (splice(wrapper_input, 0, wrapper_pipe[1], 0, 1,
            INVALID_SPLICE_FLAGS) != -1 || errno != EINVAL ||
        raw_result != -EINVAL) {
        status = 6;
        goto cleanup;
    }
    if (raw_syscall3(SYS_lseek, raw_input, 0, SEEK_CUR) != INPUT_POSITION ||
        raw_syscall3(SYS_lseek, wrapper_input, 0, SEEK_CUR) != INPUT_POSITION) {
        status = 7;
        goto cleanup;
    }

    raw_result = raw_splice(-1, 0, raw_pipe[1], 0, 1, 0);
    errno = E2BIG;
    if (splice(-1, 0, wrapper_pipe[1], 0, 1, 0) != -1 ||
        errno != EBADF || raw_result != -EBADF) {
        status = 8;
        goto cleanup;
    }

cleanup:
    raw_close(wrapper_input);
    raw_close(raw_input);
    raw_close(wrapper_pipe[0]);
    raw_close(wrapper_pipe[1]);
    raw_close(raw_pipe[0]);
    raw_close(raw_pipe[1]);
    return status;
}

static int check_tee_pipe_transfer(int selected)
{
    static const char payload[] = "abcde";
    char observed[sizeof(payload) - 1];
    int source[2] = { -1, -1 };
    int duplicate[2] = { -1, -1 };
    int destination[2] = { -1, -1 };
    int observed_errno;
    int status = 1;

    if (raw_pipe2(source) != 0 || raw_pipe2(duplicate) != 0 ||
        raw_pipe2(destination) != 0)
        goto cleanup;
    if (raw_syscall3(SYS_write, source[1], (long)(uintptr_t)payload, 5) != 5 ||
        raw_tee(source[0], duplicate[1], 3, SPLICE_F_NONBLOCK) != 3)
        goto cleanup;
    if (selected_splice(selected, source[0], 0, destination[1], 0, 9,
            SPLICE_F_NONBLOCK | SPLICE_F_MORE, &observed_errno) != 5 ||
        observed_errno != ERANGE)
        goto cleanup;
    if (raw_syscall3(SYS_read, duplicate[0], (long)(uintptr_t)observed, 3) != 3 ||
        !same_bytes(observed, "abc", 3))
        goto cleanup;
    if (raw_syscall3(SYS_read, destination[0], (long)(uintptr_t)observed, 5) != 5 ||
        !same_bytes(observed, payload, 5))
        goto cleanup;
    raw_close(source[1]);
    source[1] = -1;
    if (selected_splice(selected, source[0], 0, destination[1], 0, 2, 0,
            &observed_errno) != 0 || observed_errno != ERANGE)
        goto cleanup;
    if (selected_splice(selected, source[0], 0, destination[1], 0, 0, 0,
            &observed_errno) != 0 || observed_errno != ERANGE)
        goto cleanup;
    status = 0;
cleanup:
    raw_close(source[0]);
    raw_close(source[1]);
    raw_close(duplicate[0]);
    raw_close(duplicate[1]);
    raw_close(destination[0]);
    raw_close(destination[1]);
    return status;
}

static int check_vmsplice_pipe_transfer(int selected)
{
    static const char first[] = "ij";
    static const char second[] = "klm";
    struct iovec vector[2] = {
        { (void *)first, sizeof(first) - 1 },
        { (void *)second, sizeof(second) - 1 },
    };
    char observed[5];
    int source[2] = { -1, -1 };
    int destination[2] = { -1, -1 };
    int observed_errno;
    int status = 1;

    if (raw_pipe2(source) != 0 || raw_pipe2(destination) != 0)
        goto cleanup;
    if (raw_vmsplice(source[1], vector, 2, 0) != 5)
        goto cleanup;
    if (selected_splice(selected, source[0], 0, destination[1], 0, 9,
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK, &observed_errno) != 5 ||
        observed_errno != ERANGE)
        goto cleanup;
    if (raw_syscall3(SYS_read, destination[0], (long)(uintptr_t)observed, 5) != 5 ||
        !same_bytes(observed, "ijklm", 5))
        goto cleanup;
    status = 0;
cleanup:
    raw_close(source[0]);
    raw_close(source[1]);
    raw_close(destination[0]);
    raw_close(destination[1]);
    return status;
}

static int check_pipe_to_file_offsets(int selected)
{
    static const char payload[] = "pqrs";
    static const char expected[] = "01pqrs6789abcdef";
    char observed[sizeof(expected) - 1];
    int source[2] = { -1, -1 };
    int output = -1;
    off_t output_offset = 2;
    int observed_errno;
    int status = 1;

    output = create_input_file(selected ? 'o' : 'O');
    if (output < 0 || raw_pipe2(source) != 0)
        goto cleanup;
    if (raw_syscall3(SYS_write, source[1], (long)(uintptr_t)payload, 4) != 4)
        goto cleanup;
    if (selected_splice(selected, source[0], 0, output, &output_offset, 8,
            0, &observed_errno) != 4 || observed_errno != ERANGE ||
        output_offset != 6)
        goto cleanup;
    if (raw_syscall3(SYS_lseek, output, 0, SEEK_CUR) != INPUT_POSITION ||
        raw_syscall4(SYS_pread64, output, (long)(uintptr_t)observed,
            sizeof(observed), 0) != (long)sizeof(observed) ||
        !same_bytes(observed, expected, sizeof(observed)))
        goto cleanup;
    raw_close(source[1]);
    source[1] = -1;
    if (selected_splice(selected, source[0], 0, output, &output_offset, 2,
            0, &observed_errno) != 0 || observed_errno != ERANGE ||
        output_offset != 6)
        goto cleanup;
    status = 0;
cleanup:
    raw_close(source[0]);
    raw_close(source[1]);
    raw_close(output);
    return status;
}

static int check_rejected_offsets_and_state(int selected)
{
    static const char payload[] = "wxyz";
    char observed[4];
    int source[2] = { -1, -1 };
    int destination[2] = { -1, -1 };
    off_t offset = 3;
    int observed_errno;
    int status = 1;

    if (raw_pipe2(source) != 0 || raw_pipe2(destination) != 0)
        goto cleanup;
    if (raw_syscall3(SYS_write, source[1], (long)(uintptr_t)payload, 4) != 4)
        goto cleanup;
    if (selected_splice(selected, source[0], &offset, destination[1], 0, 2,
            0, &observed_errno) != -1 || observed_errno != ESPIPE || offset != 3)
        goto cleanup;
    if (selected_splice(selected, source[0], 0, destination[1], &offset, 2,
            0, &observed_errno) != -1 || observed_errno != ESPIPE || offset != 3)
        goto cleanup;
    if (selected_splice(selected, source[0], 0, destination[1], 0, 2,
            INVALID_SPLICE_FLAGS, &observed_errno) != -1 ||
        observed_errno != EINVAL)
        goto cleanup;
    if (selected_splice(selected, source[1], 0, destination[1], 0, 2,
            0, &observed_errno) != -1 || observed_errno != EBADF)
        goto cleanup;
    if (selected_splice(selected, source[0], 0, destination[1], 0, 4,
            0, &observed_errno) != 4 || observed_errno != ERANGE)
        goto cleanup;
    if (raw_syscall3(SYS_read, destination[0], (long)(uintptr_t)observed, 4) != 4 ||
        !same_bytes(observed, payload, 4))
        goto cleanup;
    status = 0;
cleanup:
    raw_close(source[0]);
    raw_close(source[1]);
    raw_close(destination[0]);
    raw_close(destination[1]);
    return status;
}

int crabc_x86_64_splice_probe(void)
{
    int selected;

    if (check_fixture() != 0)
        return 1;
    emit("selected.splice file-to-pipe-offset-flags-ebadf ok\n");
    for (selected = 0; selected <= 1; ++selected) {
        if (check_tee_pipe_transfer(selected) != 0)
            return selected ? 11 : 10;
        emit(selected ? "selected.splice raw-tee-pipe-short-flags-eof ok\n" :
            "raw-kernel.splice raw-tee-pipe-short-flags-eof ok\n");
        if (check_vmsplice_pipe_transfer(selected) != 0)
            return selected ? 13 : 12;
        emit(selected ? "selected.splice raw-vmsplice-pipe-short-flags ok\n" :
            "raw-kernel.splice raw-vmsplice-pipe-short-flags ok\n");
        if (check_pipe_to_file_offsets(selected) != 0)
            return selected ? 15 : 14;
        emit(selected ? "selected.splice pipe-to-file-offset-short-eof ok\n" :
            "raw-kernel.splice pipe-to-file-offset-short-eof ok\n");
        if (check_rejected_offsets_and_state(selected) != 0)
            return selected ? 17 : 16;
        emit(selected ? "selected.splice rejected-offsets-flags-fds-state ok\n" :
            "raw-kernel.splice rejected-offsets-flags-fds-state ok\n");
    }
    return 0;
}

#ifndef CRABC_SPLICE_FREESTANDING
int main(void)
{
    return crabc_x86_64_splice_probe();
}
#endif
