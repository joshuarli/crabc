/* Native Linux/x86-64 static readlinkat C ABI evidence.
 *
 * One project-header C body runs first through pinned musl 1.2.6 and then
 * through the selected freestanding crabc archive. Raw openat/symlinkat/close
 * and unlinkat calls create and remove only fixture-owned entries; raw
 * readlinkat calls are the direct Linux comparator. The candidate C entry is
 * readlinkat alone. This proves caller-owned non-NUL output, the direct
 * four-word request, musl's zero-size dummy behavior, and direct errno
 * translation; it does not select ordinary readlink, other *at operations,
 * pathname policy, allocation, CWD state, or a Rust filesystem facade.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    FIXTURE_AT_FDCWD = -100,
    FIXTURE_EBADF = 9,
    FIXTURE_EFAULT = 14,
    FIXTURE_EINVAL = 22,
    FIXTURE_EINTR = 4,
    FIXTURE_ENOENT = 2,
    FIXTURE_O_WRONLY = 1,
    FIXTURE_O_CREAT = 0100,
    FIXTURE_O_EXCL = 0200,
};

_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
               "x86 readlinkat int ABI");
_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8 &&
                   sizeof(ssize_t) == 8 && _Alignof(ssize_t) == 8,
               "x86 readlinkat byte-count ABI");
_Static_assert(AT_FDCWD == FIXTURE_AT_FDCWD && O_WRONLY == FIXTURE_O_WRONLY &&
                   O_CREAT == FIXTURE_O_CREAT && O_EXCL == FIXTURE_O_EXCL,
               "x86 readlinkat fixture constants");
_Static_assert(SYS_close == 3 && SYS_openat == 257 &&
                   SYS_unlinkat == 263 && SYS_symlinkat == 266 &&
                   SYS_readlinkat == 267,
               "Linux x86 readlinkat fixture syscall numbers");
_Static_assert(EBADF == FIXTURE_EBADF && EFAULT == FIXTURE_EFAULT &&
                   EINVAL == FIXTURE_EINVAL && EINTR == FIXTURE_EINTR &&
                   ENOENT == FIXTURE_ENOENT,
               "Linux x86 readlinkat errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readlinkat),
    ssize_t (*)(int, const char *, char *, size_t)),
    "readlinkat declaration");

struct guarded_buffer {
    unsigned char value[64];
    unsigned char trailing[16];
};

struct readlink_call {
    ssize_t result;
    int error;
    struct guarded_buffer buffer;
};

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
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static void fill_buffer(struct guarded_buffer *buffer)
{
    size_t index;

    for (index = 0; index < sizeof(buffer->value); ++index)
        buffer->value[index] = 0xa5;
    for (index = 0; index < sizeof(buffer->trailing); ++index)
        buffer->trailing[index] = 0xa5;
}

static int buffer_is_unchanged(const struct guarded_buffer *buffer)
{
    size_t index;

    for (index = 0; index < sizeof(buffer->value); ++index)
        if (buffer->value[index] != 0xa5)
            return 0;
    for (index = 0; index < sizeof(buffer->trailing); ++index)
        if (buffer->trailing[index] != 0xa5)
            return 0;
    return 1;
}

static int buffer_matches(const struct guarded_buffer *left,
    const struct guarded_buffer *right)
{
    size_t index;

    for (index = 0; index < sizeof(left->value); ++index)
        if (left->value[index] != right->value[index])
            return 0;
    for (index = 0; index < sizeof(left->trailing); ++index)
        if (left->trailing[index] != right->trailing[index])
            return 0;
    return 1;
}

static int exact_prefix(const struct guarded_buffer *buffer,
    const char *expected, size_t length)
{
    size_t index;

    if (length > sizeof(buffer->value))
        return 0;
    for (index = 0; index < length; ++index)
        if (buffer->value[index] != (unsigned char)expected[index])
            return 0;
    for (index = length; index < sizeof(buffer->value); ++index)
        if (buffer->value[index] != 0xa5)
            return 0;
    for (index = 0; index < sizeof(buffer->trailing); ++index)
        if (buffer->trailing[index] != 0xa5)
            return 0;
    return 1;
}

static struct readlink_call call_libc_readlinkat(int directory_descriptor,
    const char *path, size_t capacity)
{
    struct readlink_call call;

    fill_buffer(&call.buffer);
    /* A successful call leaves this stale errno sentinel unchanged. */
    errno = EINTR;
    call.result = readlinkat(directory_descriptor, path,
        (char *)call.buffer.value, capacity);
    call.error = errno;
    return call;
}

static struct readlink_call call_raw_readlinkat(int directory_descriptor,
    const char *path, size_t capacity)
{
    struct readlink_call call;
    long result;

    fill_buffer(&call.buffer);
    result = raw_syscall4(SYS_readlinkat, directory_descriptor,
        (long)(uintptr_t)path, (long)(uintptr_t)call.buffer.value,
        (long)capacity);
    if (result < 0 && result >= -4095) {
        call.result = -1;
        call.error = (int)-result;
    } else {
        call.result = (ssize_t)result;
        call.error = EINTR;
    }
    return call;
}

static int calls_match(const struct readlink_call *libc_call,
    const struct readlink_call *raw_call)
{
    return libc_call->result == raw_call->result &&
        libc_call->error == raw_call->error &&
        buffer_matches(&libc_call->buffer, &raw_call->buffer);
}

int crabc_x86_64_readlinkat_probe(void)
{
    static const char symbolic[] = "readlinkat-symbolic";
    static const char regular[] = "readlinkat-regular";
    static const char target[] = "target-value";
    struct readlink_call libc_call;
    struct readlink_call raw_call;
    int regular_fd = -1;
    int symbolic_created = 0;
    int regular_created = 0;
    int status = 0;

    regular_fd = (int)raw_syscall4(SYS_openat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)regular, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (regular_fd < 0)
        return 1;
    regular_created = 1;
    if (raw_syscall1(SYS_close, regular_fd) != 0)
        status = 2;
    regular_fd = -1;
    if (status == 0 && raw_syscall3(SYS_symlinkat,
        (long)(uintptr_t)target, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)symbolic) != 0)
        status = 3;
    else if (status == 0)
        symbolic_created = 1;

    if (status == 0) {
        libc_call = call_libc_readlinkat(FIXTURE_AT_FDCWD, symbolic,
            sizeof(libc_call.buffer.value));
        raw_call = call_raw_readlinkat(FIXTURE_AT_FDCWD, symbolic,
            sizeof(raw_call.buffer.value));
        if (!calls_match(&libc_call, &raw_call) ||
            libc_call.result != (ssize_t)(sizeof(target) - 1) ||
            libc_call.error != EINTR ||
            !exact_prefix(&libc_call.buffer, target, sizeof(target) - 1))
            status = 4;
    }
    if (status == 0) {
        libc_call = call_libc_readlinkat(FIXTURE_AT_FDCWD, symbolic, 3);
        raw_call = call_raw_readlinkat(FIXTURE_AT_FDCWD, symbolic, 3);
        if (!calls_match(&libc_call, &raw_call) || libc_call.result != 3 ||
            libc_call.error != EINTR ||
            !exact_prefix(&libc_call.buffer, target, 3))
            status = 5;
    }
    if (status == 0) {
        libc_call = call_libc_readlinkat(FIXTURE_AT_FDCWD, symbolic, 0);
        if (libc_call.result != 0 || libc_call.error != EINTR ||
            !buffer_is_unchanged(&libc_call.buffer))
            status = 6;
        raw_call = call_raw_readlinkat(FIXTURE_AT_FDCWD, symbolic, 0);
        if (raw_call.result != -1 || raw_call.error != EINVAL ||
            !buffer_is_unchanged(&raw_call.buffer))
            status = 7;
    }
    if (status == 0) {
        libc_call = call_libc_readlinkat(FIXTURE_AT_FDCWD, "missing",
            sizeof(libc_call.buffer.value));
        raw_call = call_raw_readlinkat(FIXTURE_AT_FDCWD, "missing",
            sizeof(raw_call.buffer.value));
        if (!calls_match(&libc_call, &raw_call) || libc_call.result != -1 ||
            libc_call.error != ENOENT || !buffer_is_unchanged(&libc_call.buffer))
            status = 8;
    }
    if (status == 0) {
        libc_call = call_libc_readlinkat(FIXTURE_AT_FDCWD, regular,
            sizeof(libc_call.buffer.value));
        raw_call = call_raw_readlinkat(FIXTURE_AT_FDCWD, regular,
            sizeof(raw_call.buffer.value));
        if (!calls_match(&libc_call, &raw_call) || libc_call.result != -1 ||
            libc_call.error != EINVAL || !buffer_is_unchanged(&libc_call.buffer))
            status = 9;
    }
    if (status == 0) {
        libc_call = call_libc_readlinkat(-1, symbolic,
            sizeof(libc_call.buffer.value));
        raw_call = call_raw_readlinkat(-1, symbolic,
            sizeof(raw_call.buffer.value));
        if (!calls_match(&libc_call, &raw_call) || libc_call.result != -1 ||
            libc_call.error != EBADF || !buffer_is_unchanged(&libc_call.buffer))
            status = 10;
    }
    if (status == 0) {
        libc_call = call_libc_readlinkat(FIXTURE_AT_FDCWD, (const char *)0,
            sizeof(libc_call.buffer.value));
        raw_call = call_raw_readlinkat(FIXTURE_AT_FDCWD, (const char *)0,
            sizeof(raw_call.buffer.value));
        if (!calls_match(&libc_call, &raw_call) || libc_call.result != -1 ||
            libc_call.error != EFAULT || !buffer_is_unchanged(&libc_call.buffer))
            status = 11;
    }

    if (symbolic_created && raw_syscall3(SYS_unlinkat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)symbolic, 0) != 0 && status == 0)
        status = 12;
    if (regular_created && raw_syscall3(SYS_unlinkat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)regular, 0) != 0 && status == 0)
        status = 13;
    return status;
}

#ifndef CRABC_READLINKAT_FREESTANDING
int main(void)
{
    return crabc_x86_64_readlinkat_probe();
}
#endif
