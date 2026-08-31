/* Static crabc-libc x86-64 bounded pthread_setconcurrency fixture.
 *
 * The same project-header body first runs against pinned musl 1.2.6 and then
 * as a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves only musl's direct three-way result:
 * negative requests return EINVAL, zero succeeds as a no-op, and positive
 * requests return EAGAIN. The normal reference route additionally proves that
 * every result leaves errno unchanged.
 *
 * This fixture deliberately calls no pthread_getconcurrency, thread creation,
 * scheduler API, attribute API, synchronization object, cancellation, TLS,
 * CRT, loader, sysroot, or public-x86 path.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>

_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_setconcurrency),
    int (*)(int)), "pthread_setconcurrency declaration");
_Static_assert(EAGAIN == 11 && EINVAL == 22, "Linux/musl errno vocabulary");

static int expect_result(int request, int expected)
{
#if !defined(CRABC_PTHREAD_SETCONCURRENCY_FREESTANDING)
    errno = EBUSY;
#endif
    if (pthread_setconcurrency(request) != expected)
        return 1;
#if !defined(CRABC_PTHREAD_SETCONCURRENCY_FREESTANDING)
    if (errno != EBUSY)
        return 2;
#endif
    return 0;
}

int crabc_x86_64_pthread_setconcurrency_probe(void)
{
    if (expect_result(INT_MIN, EINVAL) != 0)
        return 1;
    if (expect_result(-1, EINVAL) != 0)
        return 2;
    if (expect_result(0, 0) != 0)
        return 3;
    if (expect_result(1, EAGAIN) != 0)
        return 4;
    if (expect_result(INT_MAX, EAGAIN) != 0)
        return 5;
    return 0;
}

#if !defined(CRABC_PTHREAD_SETCONCURRENCY_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_setconcurrency_probe();
}
#endif
