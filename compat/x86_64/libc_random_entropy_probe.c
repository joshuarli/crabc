/* Static crabc-libc x86-64 random-source fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a freestanding executable linked solely with the selected crabc
 * archive.  It selects only getrandom and getentropy.  The random values are
 * intentionally not compared; this fixture proves initialized-length,
 * boundary-error, and getentropy's bounded atomic-request behavior.
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
    RANDOM_BYTES = 64,
    ENTROPY_BYTES = 32,
    MAX_ENTROPY_BYTES = 256,
    BUFFER_SENTINEL = 0xa5,
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
    "x86 size and ssize widths");
_Static_assert(SYS_getrandom == 318, "x86 getrandom syscall number");
_Static_assert(GRND_NONBLOCK == 0x0001 && GRND_RANDOM == 0x0002 &&
    GRND_INSECURE == 0x0004, "x86 getrandom flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getrandom),
    ssize_t (*)(void *, size_t, unsigned)), "getrandom declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getentropy),
    int (*)(void *, size_t)), "getentropy declaration");

static void fill_bytes(unsigned char *buffer, size_t length,
    unsigned char value)
{
    size_t index;

    for (index = 0; index < length; ++index)
        buffer[index] = value;
}

static int all_bytes(const unsigned char *buffer, size_t length,
    unsigned char value)
{
    size_t index;

    for (index = 0; index < length; ++index)
        if (buffer[index] != value)
            return 0;
    return 1;
}

static int check_getrandom(void)
{
    unsigned char buffer[RANDOM_BYTES + 1];
    ssize_t received;

    fill_bytes(buffer, sizeof(buffer), BUFFER_SENTINEL);
    errno = EINTR;
    received = getrandom(buffer, RANDOM_BYTES, 0);
    if (received != RANDOM_BYTES || buffer[RANDOM_BYTES] != BUFFER_SENTINEL ||
        errno != EINTR)
        return 1;

    errno = EINTR;
    if (getrandom(NULL, 0, GRND_NONBLOCK) != 0 || errno != EINTR)
        return 2;

    errno = 0;
    if (getrandom(buffer, 1, GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE |
            0x0008U) != -1 || errno != EINVAL)
        return 3;

    errno = 0;
    if (getrandom((void *)(uintptr_t)1, 1, 0) != -1 || errno != EFAULT)
        return 4;

    return 0;
}

static int check_getentropy(void)
{
    unsigned char normal[ENTROPY_BYTES + 1];
    unsigned char maximum[MAX_ENTROPY_BYTES + 1];
    unsigned char too_large[MAX_ENTROPY_BYTES + 1];

    errno = EINTR;
    if (getentropy(NULL, 0) != 0 || errno != EINTR)
        return 1;

    fill_bytes(normal, sizeof(normal), BUFFER_SENTINEL);
    errno = EINTR;
    if (getentropy(normal, ENTROPY_BYTES) != 0 ||
        normal[ENTROPY_BYTES] != BUFFER_SENTINEL ||
        errno != EINTR)
        return 2;

    fill_bytes(maximum, sizeof(maximum), BUFFER_SENTINEL);
    errno = EINTR;
    if (getentropy(maximum, MAX_ENTROPY_BYTES) != 0 ||
        maximum[MAX_ENTROPY_BYTES] != BUFFER_SENTINEL ||
        errno != EINTR)
        return 3;

    fill_bytes(too_large, sizeof(too_large), BUFFER_SENTINEL);
    errno = 0;
    if (getentropy(too_large, sizeof(too_large)) != -1 || errno != EIO ||
        !all_bytes(too_large, sizeof(too_large), BUFFER_SENTINEL))
        return 4;

    errno = 0;
    if (getentropy((void *)(uintptr_t)1, 1) != -1 || errno != EFAULT)
        return 5;

    return 0;
}

int libc_random_entropy_probe(void)
{
    int result = check_getrandom();

    if (result != 0)
        return result;
    result = check_getentropy();
    return result == 0 ? 0 : 10 + result;
}

#ifndef CRABC_RANDOM_ENTROPY_FREESTANDING
int main(void)
{
    return libc_random_entropy_probe();
}
#endif
