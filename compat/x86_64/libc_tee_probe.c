/* Static x86-64 tee C ABI and pinned-musl behavior fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * through a true static crabc archive. The named boundary duplicates a small
 * caller-written pipe payload from one read endpoint to a second pipe's write
 * endpoint, retaining the source bytes. Fixture-local raw syscalls create,
 * write, read, and close the two ephemeral pipes only; they are not selected
 * descriptor or pipe ownership APIs.
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

enum {
    FIXTURE_EBADF = 9,
};

typedef ssize_t (*tee_signature)(int, int, size_t, unsigned);

_Static_assert(sizeof(ssize_t) == sizeof(long) && sizeof(size_t) == sizeof(long),
    "x86 LP64 ssize_t and size_t ABI");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
    SYS_tee == 276 && SYS_pipe2 == 293,
    "x86 tee fixture syscall numbers");
_Static_assert(EBADF == FIXTURE_EBADF, "x86 EBADF value");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tee), tee_signature),
    "tee declaration");

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

static int raw_close(int descriptor)
{
    return raw_syscall1(SYS_close, descriptor) == 0 ? 0 : -1;
}

static int raw_pipe2(int descriptors[2])
{
    return raw_syscall2(SYS_pipe2, (long)(uintptr_t)descriptors, 0) == 0 ? 0 : -1;
}

static int bytes_equal(const char *actual, const char *expected, size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index)
        if (actual[index] != expected[index])
            return 0;
    return 1;
}

static int check_pipe_duplication(void)
{
    static const char payload[] = "tee-copy";
    char source_bytes[sizeof(payload) - 1];
    char destination_bytes[sizeof(payload) - 1];
    int source[2] = { -1, -1 };
    int destination[2] = { -1, -1 };
    const tee_signature invoke = tee;
    int result = 0;

    if (raw_pipe2(source) != 0 || raw_pipe2(destination) != 0) {
        result = 1;
        goto cleanup;
    }
    if (raw_syscall3(SYS_write, source[1], (long)(uintptr_t)payload,
            sizeof(payload) - 1) != (long)(sizeof(payload) - 1)) {
        result = 2;
        goto cleanup;
    }

    errno = E2BIG;
    if (tee(source[0], destination[1], sizeof(payload) - 1, 0) !=
            (ssize_t)(sizeof(payload) - 1) || errno != E2BIG) {
        result = 3;
        goto cleanup;
    }
    if (raw_syscall3(SYS_read, source[0], (long)(uintptr_t)source_bytes,
            sizeof(source_bytes)) != (long)sizeof(source_bytes) ||
        !bytes_equal(source_bytes, payload, sizeof(source_bytes))) {
        result = 4;
        goto cleanup;
    }
    if (raw_syscall3(SYS_read, destination[0], (long)(uintptr_t)destination_bytes,
            sizeof(destination_bytes)) != (long)sizeof(destination_bytes) ||
        !bytes_equal(destination_bytes, payload, sizeof(destination_bytes))) {
        result = 5;
        goto cleanup;
    }

    errno = ERANGE;
    if (invoke(source[0], destination[1], 0, 0) != 0 || errno != ERANGE) {
        result = 6;
        goto cleanup;
    }
    errno = E2BIG;
    if (invoke(-1, destination[1], 1, 0) != -1 || errno != FIXTURE_EBADF) {
        result = 7;
        goto cleanup;
    }

cleanup:
    if (source[0] >= 0 && raw_close(source[0]) != 0 && result == 0)
        result = 8;
    if (source[1] >= 0 && raw_close(source[1]) != 0 && result == 0)
        result = 9;
    if (destination[0] >= 0 && raw_close(destination[0]) != 0 && result == 0)
        result = 10;
    if (destination[1] >= 0 && raw_close(destination[1]) != 0 && result == 0)
        result = 11;
    return result;
}

int crabc_x86_64_tee_probe(void)
{
    return check_pipe_duplication();
}

#ifndef CRABC_TEE_FREESTANDING
int main(void)
{
    return crabc_x86_64_tee_probe();
}
#endif
