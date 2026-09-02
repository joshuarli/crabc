/* Static crabc-libc x86-64 pthread mutex/condition attribute lifecycle fixture.
 *
 * The same project-header body first executes against pinned musl 1.2.6 and
 * then against a true -nostdlib -static candidate.  It selects the complete
 * stateless lifecycle quartet only: each init zeroes its caller-owned
 * four-byte record, while each destroy returns zero without dereferencing its
 * argument.  It does not select any record setter/getter, mutex/condition
 * initialization or operation, pthread creation, TLS, or a pthread runtime.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>
#include <stdint.h>

_Static_assert(sizeof(unsigned) == 4 && sizeof(int) == 4,
    "x86 pthread attribute lifecycle scalar widths");
_Static_assert(sizeof(pthread_mutexattr_t) == 4 && _Alignof(pthread_mutexattr_t) == 4,
    "musl x86-64 pthread_mutexattr_t ABI");
_Static_assert(sizeof(pthread_condattr_t) == 4 && _Alignof(pthread_condattr_t) == 4,
    "musl x86-64 pthread_condattr_t ABI");
_Static_assert(__builtin_offsetof(pthread_mutexattr_t, __attr) == 0,
    "public pthread_mutexattr_t word offset");
_Static_assert(__builtin_offsetof(pthread_condattr_t, __attr) == 0,
    "public pthread_condattr_t word offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutexattr_init),
    int (*)(pthread_mutexattr_t *)), "pthread_mutexattr_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutexattr_destroy),
    int (*)(pthread_mutexattr_t *)), "pthread_mutexattr_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_condattr_init),
    int (*)(pthread_condattr_t *)), "pthread_condattr_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_condattr_destroy),
    int (*)(pthread_condattr_t *)), "pthread_condattr_destroy declaration");

int crabc_x86_64_pthread_attr_lifecycle_probe(void)
{
    pthread_mutexattr_t mutex_attr = { .__attr = 0xa5a55a5aU };
    pthread_condattr_t cond_attr = { .__attr = 0x5a5aa5a5U };

    if (pthread_mutexattr_init(&mutex_attr) != 0 || mutex_attr.__attr != 0)
        return 1;
    if (pthread_condattr_init(&cond_attr) != 0 || cond_attr.__attr != 0)
        return 2;

    /* Musl's stateless destroy leaves even an invalid address unobserved. */
    if (pthread_mutexattr_destroy((pthread_mutexattr_t *)(uintptr_t)1) != 0)
        return 3;
    if (pthread_condattr_destroy((pthread_condattr_t *)(uintptr_t)1) != 0)
        return 4;
    return 0;
}

#if !defined(CRABC_PTHREAD_ATTR_LIFECYCLE_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_attr_lifecycle_probe();
}
#endif
