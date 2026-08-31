/* Native Linux/x86-64 static pthread_spin_destroy C ABI evidence.
 *
 * The same project-header fixture first executes against pinned musl 1.2.6,
 * then as a true archive-free -nostdlib -static candidate linked from exactly
 * one crabc object. It proves only musl's source-closed successful return and
 * non-observation of one caller-owned pthread_spinlock_t word. It does not
 * establish spin initialization, locking, synchronization, or threads.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

typedef int (*pthread_spin_destroy_signature)(pthread_spinlock_t *);

_Static_assert(sizeof(pthread_spinlock_t) == 4 &&
                   _Alignof(pthread_spinlock_t) == 4,
               "musl x86-64 pthread_spinlock_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_destroy),
                                             pthread_spin_destroy_signature),
               "pthread_spin_destroy declaration");

#define CRABC_SPIN_DESTROY_SENTINEL ((pthread_spinlock_t)0x5a5a5a5aU)

int crabc_x86_64_pthread_spin_destroy_probe(void)
{
    pthread_spinlock_t spinlock = CRABC_SPIN_DESTROY_SENTINEL;
    const pthread_spin_destroy_signature function = pthread_spin_destroy;

    if (pthread_spin_destroy(&spinlock) != 0)
        return 1;
    if (spinlock != CRABC_SPIN_DESTROY_SENTINEL)
        return 2;

    if (function(&spinlock) != 0)
        return 3;
    if (spinlock != CRABC_SPIN_DESTROY_SENTINEL)
        return 4;

    return 0;
}

#if !defined(CRABC_PTHREAD_SPIN_DESTROY_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_spin_destroy_probe();
}
#endif
