/* Native Linux/x86-64 pinned-musl/project pthread spin-operation evidence.
 *
 * The fixture exercises the exact public four-byte record and proves init,
 * trylock success/busy, unlock/reacquire, arbitrary initial-word behavior,
 * and status values. The freestanding mode is linked only with the selected
 * crabc objects and therefore owns no CRT, TLS, errno, allocator, or loader.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

typedef int (*pthread_spin_init_signature)(pthread_spinlock_t *, int);
typedef int (*pthread_spin_lock_signature)(pthread_spinlock_t *);
typedef int (*pthread_spin_trylock_signature)(pthread_spinlock_t *);
typedef int (*pthread_spin_unlock_signature)(pthread_spinlock_t *);

_Static_assert(sizeof(pthread_spinlock_t) == 4 &&
                   _Alignof(pthread_spinlock_t) == 4,
               "musl x86-64 pthread_spinlock_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_init),
                                             pthread_spin_init_signature),
               "pthread_spin_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_lock),
                                             pthread_spin_lock_signature),
               "pthread_spin_lock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_trylock),
                                             pthread_spin_trylock_signature),
               "pthread_spin_trylock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_unlock),
                                             pthread_spin_unlock_signature),
               "pthread_spin_unlock declaration");

#define CRABC_EBUSY 16
#define CRABC_FIRST_WORD ((pthread_spinlock_t)0x13579bdfU)
#define CRABC_SECOND_WORD ((pthread_spinlock_t)0x80000001U)

int crabc_x86_64_pthread_spin_operations_probe(void)
{
    pthread_spinlock_t spinlock = CRABC_FIRST_WORD;
    const pthread_spin_init_signature init = pthread_spin_init;
    const pthread_spin_lock_signature lock = pthread_spin_lock;
    const pthread_spin_trylock_signature trylock = pthread_spin_trylock;
    const pthread_spin_unlock_signature unlock = pthread_spin_unlock;

    /* A nonzero arbitrary word is observed and left untouched by trylock. */
    if (trylock(&spinlock) != CRABC_FIRST_WORD ||
        spinlock != CRABC_FIRST_WORD)
        return 1;

    if (init(&spinlock, PTHREAD_PROCESS_PRIVATE) != 0 || spinlock != 0)
        return 2;
    if (trylock(&spinlock) != 0 || spinlock != CRABC_EBUSY)
        return 3;
    if (trylock(&spinlock) != CRABC_EBUSY || spinlock != CRABC_EBUSY)
        return 4;
    if (unlock(&spinlock) != 0 || spinlock != 0)
        return 5;

    if (lock(&spinlock) != 0 || spinlock != CRABC_EBUSY)
        return 6;
    if (unlock(&spinlock) != 0 || spinlock != 0)
        return 7;

    spinlock = CRABC_SECOND_WORD;
    if (unlock(&spinlock) != 0 || spinlock != 0)
        return 8;
    if (trylock(&spinlock) != 0 || spinlock != CRABC_EBUSY)
        return 9;
    if (unlock(&spinlock) != 0 || spinlock != 0)
        return 10;

    return 0;
}

#if !defined(CRABC_PTHREAD_SPIN_OPERATIONS_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_spin_operations_probe();
}
#endif
