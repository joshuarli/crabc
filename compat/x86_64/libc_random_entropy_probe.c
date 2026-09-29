/* Static x86-64 entropy boundary observed through the same C body in musl
 * and the selected crabc archive. Records contain status, errno, and buffer
 * guards; entropy bytes never enter the comparison or report.
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
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    MAX_ENTROPY_BYTES = 256,
    BUFFER_SENTINEL = 0xa5,
    POINTER_BUFFER = 0,
    POINTER_NULL = 1,
    POINTER_INVALID = 2,
};

struct entropy_case {
    unsigned char id;
    unsigned char use_getentropy;
    unsigned char pointer_kind;
    unsigned char require_unchanged;
    size_t length;
    unsigned flags;
    int expected_status;
    int expected_errno;
};

/* One six-byte row permits a literal comparison without recording random data.
 * A failed request must leave the entire local buffer untouched; successful
 * requests must preserve the bytes immediately before and after the request.
 */
struct entropy_observation {
    unsigned char id;
    signed char status;
    unsigned char error;
    unsigned char leading_guard;
    unsigned char trailing_guard;
    unsigned char unchanged;
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
    "x86 size and ssize widths");
_Static_assert(sizeof(struct entropy_observation) == 6,
    "stable observation record width");
_Static_assert(SYS_getrandom == 318 && SYS_write == 1,
    "x86 syscall numbers");
_Static_assert(GRND_NONBLOCK == 0x0001 && GRND_RANDOM == 0x0002 &&
    GRND_INSECURE == 0x0004, "x86 getrandom flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getrandom),
    ssize_t (*)(void *, size_t, unsigned)), "getrandom declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getentropy),
    int (*)(void *, size_t)), "getentropy declaration");

/* Reporting uses only Linux write so the freestanding candidate selects no
 * unrelated libc symbol. The syscall writes observations, never entropy.
 */
static long report_write(const void *buffer, size_t length)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"((long)SYS_write),
        "D"(1L), "S"(buffer), "d"(length) : "rcx", "r11", "memory");
    return result;
}

static int all_sentinel(const unsigned char *buffer, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index)
        if (buffer[index] != BUFFER_SENTINEL)
            return 0;
    return 1;
}

static int observe(const struct entropy_case *test)
{
    unsigned char buffer[MAX_ENTROPY_BYTES + 3];
    struct entropy_observation row;
    void *target = buffer + 1;
    ssize_t status;
    size_t index;
    size_t written = 0;

    for (index = 0; index < sizeof(buffer); ++index)
        buffer[index] = BUFFER_SENTINEL;
    if (test->pointer_kind == POINTER_NULL)
        target = NULL;
    else if (test->pointer_kind == POINTER_INVALID)
        target = (void *)(uintptr_t)1;

    errno = EINTR;
    if (test->use_getentropy)
        status = getentropy(target, test->length);
    else
        status = getrandom(target, test->length, test->flags);

    row.id = test->id;
    row.status = (signed char)status;
    row.error = (unsigned char)errno;
    row.leading_guard = buffer[0] == BUFFER_SENTINEL;
    row.trailing_guard = buffer[test->length <= MAX_ENTROPY_BYTES ?
        test->length + 1 : MAX_ENTROPY_BYTES + 2] == BUFFER_SENTINEL;
    row.unchanged = test->require_unchanged ?
        all_sentinel(buffer, sizeof(buffer)) : 2;

    while (written < sizeof(row)) {
        long count = report_write((const unsigned char *)&row + written,
            sizeof(row) - written);
        if (count <= 0)
            return 100 + test->id;
        written += (size_t)count;
    }

    if (status != test->expected_status || errno != test->expected_errno ||
        !row.leading_guard || !row.trailing_guard ||
        (test->require_unchanged && !row.unchanged))
        return test->id;
    return 0;
}

int libc_random_entropy_probe(void)
{
    static const struct entropy_case cases[] = {
        { 1, 0, POINTER_BUFFER, 0, 64, 0, 64, EINTR },
        { 2, 0, POINTER_NULL, 1, 0, GRND_NONBLOCK, 0, EINTR },
        { 3, 0, POINTER_INVALID, 1, 0, 0, 0, EINTR },
        { 4, 0, POINTER_BUFFER, 0, 1, GRND_NONBLOCK, 1, EINTR },
        { 5, 0, POINTER_BUFFER, 0, 1, GRND_INSECURE, 1, EINTR },
        { 6, 0, POINTER_BUFFER, 1, 1, 0x0008U, -1, EINVAL },
        { 7, 0, POINTER_INVALID, 1, 1, 0, -1, EFAULT },
        { 8, 0, POINTER_INVALID, 1, 1, 0x0008U, -1, EINVAL },
        { 9, 1, POINTER_NULL, 1, 0, 0, 0, EINTR },
        { 10, 1, POINTER_INVALID, 1, 0, 0, 0, EINTR },
        { 11, 1, POINTER_BUFFER, 0, 32, 0, 0, EINTR },
        { 12, 1, POINTER_BUFFER, 0, 255, 0, 0, EINTR },
        { 13, 1, POINTER_BUFFER, 0, 256, 0, 0, EINTR },
        { 14, 1, POINTER_BUFFER, 1, 257, 0, -1, EIO },
        { 15, 1, POINTER_INVALID, 1, 257, 0, -1, EIO },
        { 16, 1, POINTER_INVALID, 1, 1, 0, -1, EFAULT },
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        int result = observe(&cases[index]);
        if (result != 0)
            return result;
    }
    return 0;
}

#ifndef CRABC_RANDOM_ENTROPY_FREESTANDING
int main(void)
{
    return libc_random_entropy_probe();
}
#endif
