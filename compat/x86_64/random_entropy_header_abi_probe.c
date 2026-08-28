/*
 * Native Linux/x86-64 compile-only random-source header ABI probe.
 *
 * Pinned musl 1.2.6 owns the selected declarations and constants.  The
 * runner compiles this source in strict C11 mode, where getentropy is hidden,
 * and with the GNU/BSD feature selectors, where its declaration is visible.
 * No function is linked or executed by this probe.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(size_t) == 8, "x86 size_t width");
_Static_assert(sizeof(ssize_t) == 8, "x86 ssize_t width");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getrandom),
    ssize_t (*)(void *, size_t, unsigned)), "getrandom declaration");
_Static_assert(GRND_NONBLOCK == 0x0001 && GRND_RANDOM == 0x0002 &&
    GRND_INSECURE == 0x0004, "getrandom flags");

#if defined(CRABC_EXPECT_GETENTROPY)
_Static_assert(__builtin_types_compatible_p(__typeof__(&getentropy),
    int (*)(void *, size_t)), "getentropy declaration");
#endif

/* This branch is intentionally compiled only as an expected-failure check. */
#if defined(CRABC_EXPECT_GETENTROPY_HIDDEN)
int crabc_random_entropy_strict_hidden_probe(void)
{
    return getentropy(NULL, 0);
}
#endif

int crabc_random_entropy_header_abi_probe(void)
{
    return GRND_NONBLOCK + GRND_RANDOM + GRND_INSECURE;
}
