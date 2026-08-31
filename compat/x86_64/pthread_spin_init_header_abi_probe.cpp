/* C++17 companion for the native x86-64 pthread_spin_init header probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

using pthread_spin_init_signature = int (*)(pthread_spinlock_t *, int);

static_assert(sizeof(pthread_spinlock_t) == 4 && alignof(pthread_spinlock_t) == 4,
    "musl x86-64 pthread_spinlock_t ABI");
static_assert(__is_same(decltype(&pthread_spin_init), pthread_spin_init_signature),
    "pthread_spin_init declaration");

static pthread_spin_init_signature volatile direct_pthread_spin_init = pthread_spin_init;

extern "C" int crabc_x86_64_pthread_spin_init_header_abi_probe_cpp(void)
{
    return direct_pthread_spin_init == nullptr;
}
