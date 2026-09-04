/* C declaration, linkage, and record-layout proof for the private x86
 * pthread spin-operation aggregate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

typedef int (*pthread_spin_lock_signature)(pthread_spinlock_t *);
typedef int (*pthread_spin_trylock_signature)(pthread_spinlock_t *);
typedef int (*pthread_spin_unlock_signature)(pthread_spinlock_t *);

_Static_assert(sizeof(pthread_spinlock_t) == 4,
               "x86 pthread_spinlock_t width");
_Static_assert(_Alignof(pthread_spinlock_t) == 4,
               "x86 pthread_spinlock_t alignment");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_lock),
                                             pthread_spin_lock_signature),
               "pthread_spin_lock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_trylock),
                                             pthread_spin_trylock_signature),
               "pthread_spin_trylock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_unlock),
                                             pthread_spin_unlock_signature),
               "pthread_spin_unlock declaration");

static pthread_spin_lock_signature pthread_spin_lock_function
    __attribute__((used)) = pthread_spin_lock;
static pthread_spin_trylock_signature pthread_spin_trylock_function
    __attribute__((used)) = pthread_spin_trylock;
static pthread_spin_unlock_signature pthread_spin_unlock_function
    __attribute__((used)) = pthread_spin_unlock;

int crabc_x86_64_pthread_spin_operations_header_abi_probe(void)
{
    return pthread_spin_lock_function == pthread_spin_lock &&
                   pthread_spin_trylock_function == pthread_spin_trylock &&
                   pthread_spin_unlock_function == pthread_spin_unlock
               ? 0
               : 1;
}
