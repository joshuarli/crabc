/* Static crabc-libc x86-64 bounded pthread_getconcurrency fixture.
 *
 * The same project-header body first runs against pinned musl 1.2.6 and then
 * as a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves only musl's direct zero result and that
 * the normal reference route leaves errno unchanged.
 *
 * This fixture deliberately calls no pthread_setconcurrency, thread creation,
 * scheduler API, attribute API, synchronization object, cancellation, TLS,
 * CRT, loader, sysroot, or public-x86 path.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>

_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_getconcurrency),
    int (*)(void)), "pthread_getconcurrency declaration");
_Static_assert(EBUSY == 16, "Linux/musl errno vocabulary");

static int expect_result(void)
{
#if !defined(CRABC_PTHREAD_GETCONCURRENCY_FREESTANDING)
    errno = EBUSY;
#endif
    if (pthread_getconcurrency() != 0)
        return 1;
#if !defined(CRABC_PTHREAD_GETCONCURRENCY_FREESTANDING)
    if (errno != EBUSY)
        return 2;
#endif
    return 0;
}

int crabc_x86_64_pthread_getconcurrency_probe(void)
{
    if (expect_result() != 0)
        return 1;
    if (expect_result() != 0)
        return 2;
    return 0;
}

#if !defined(CRABC_PTHREAD_GETCONCURRENCY_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_getconcurrency_probe();
}
#endif
