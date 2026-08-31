/* Static crabc-libc x86-64 bounded pthread mutex priority-ceiling query fixture.
 *
 * The same project-header body first executes against pinned musl 1.2.6, then
 * as a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves only pthread_mutex_getprioceiling's
 * unconditional direct EINVAL result: musl neither reads the supplied mutex
 * pointer nor writes the optional ceiling slot.
 *
 * This fixture deliberately calls no mutex initializer, lock, unlock,
 * destruction, setter, scheduler API, thread, TLS, synchronization,
 * cancellation, CRT, loader, sysroot, or public-x86 path. Its raw zeroed
 * mutex storage is an opaque argument only, not a mutex state-machine input.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>

_Static_assert(sizeof(pthread_mutex_t) == 40 && _Alignof(pthread_mutex_t) == 8,
    "musl x86-64 pthread_mutex_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutex_getprioceiling),
    int (*)(const pthread_mutex_t *, int *)),
    "pthread_mutex_getprioceiling declaration");

static int expect_direct_einval(const pthread_mutex_t *mutex, int *ceiling)
{
    int preserved = ceiling ? *ceiling : 0;

    if (pthread_mutex_getprioceiling(mutex, ceiling) != EINVAL)
        return 1;
    if (ceiling && *ceiling != preserved)
        return 2;
    return 0;
}

int crabc_x86_64_pthread_mutex_prioceiling_query_probe(void)
{
    pthread_mutex_t opaque_mutex = { 0 };
    int ceiling = 0x5a5a1234;

    if (expect_direct_einval(0, 0) != 0)
        return 1;
    if (expect_direct_einval(&opaque_mutex, 0) != 0)
        return 2;
    if (expect_direct_einval(0, &ceiling) != 0)
        return 3;
    if (expect_direct_einval(&opaque_mutex, &ceiling) != 0)
        return 4;
    return ceiling == 0x5a5a1234 ? 0 : 5;
}

#if !defined(CRABC_PTHREAD_MUTEX_PRIOCEILING_QUERY_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_mutex_prioceiling_query_probe();
}
#endif
