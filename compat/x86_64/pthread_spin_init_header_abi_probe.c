/* Source-only Linux/x86-64 <pthread.h> pthread_spin_init declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

typedef int (*pthread_spin_init_signature)(pthread_spinlock_t *, int);

_Static_assert(sizeof(pthread_spinlock_t) == 4 && _Alignof(pthread_spinlock_t) == 4,
    "musl x86-64 pthread_spinlock_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_init),
    pthread_spin_init_signature), "pthread_spin_init declaration");

static pthread_spin_init_signature volatile direct_pthread_spin_init = pthread_spin_init;

int crabc_x86_64_pthread_spin_init_header_abi_probe(void)
{
    return direct_pthread_spin_init == 0;
}
