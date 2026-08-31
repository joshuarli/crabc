/* C++17 companion for the pinned-musl/project spin-destruction header gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

using pthread_spin_destroy_signature = int (*)(pthread_spinlock_t *);

static_assert(sizeof(pthread_spinlock_t) == 4,
              "x86 pthread_spinlock_t width");
static_assert(alignof(pthread_spinlock_t) == 4,
              "x86 pthread_spinlock_t alignment");
static_assert(__is_same(decltype(&pthread_spin_destroy),
                        pthread_spin_destroy_signature),
              "C++ pthread_spin_destroy declaration");

static pthread_spin_destroy_signature pthread_spin_destroy_function
    __attribute__((used)) = pthread_spin_destroy;

int crabc_x86_64_pthread_spin_destroy_header_abi_probe_cpp()
{
    return pthread_spin_destroy_function == pthread_spin_destroy ? 0 : 1;
}
