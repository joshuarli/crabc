/* C++17 declaration, linkage, and record-layout proof for private x86
 * pthread spin operations. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <pthread.h>

using pthread_spin_lock_signature = int (*)(pthread_spinlock_t *);
using pthread_spin_trylock_signature = int (*)(pthread_spinlock_t *);
using pthread_spin_unlock_signature = int (*)(pthread_spinlock_t *);

static_assert(sizeof(pthread_spinlock_t) == 4,
              "x86 pthread_spinlock_t width");
static_assert(alignof(pthread_spinlock_t) == 4,
              "x86 pthread_spinlock_t alignment");
static_assert(__is_same(decltype(&pthread_spin_lock),
                        pthread_spin_lock_signature),
              "pthread_spin_lock declaration");
static_assert(__is_same(decltype(&pthread_spin_trylock),
                        pthread_spin_trylock_signature),
              "pthread_spin_trylock declaration");
static_assert(__is_same(decltype(&pthread_spin_unlock),
                        pthread_spin_unlock_signature),
              "pthread_spin_unlock declaration");

static pthread_spin_lock_signature pthread_spin_lock_function
    __attribute__((used)) = pthread_spin_lock;
static pthread_spin_trylock_signature pthread_spin_trylock_function
    __attribute__((used)) = pthread_spin_trylock;
static pthread_spin_unlock_signature pthread_spin_unlock_function
    __attribute__((used)) = pthread_spin_unlock;

extern "C" int crabc_x86_64_pthread_spin_operations_header_abi_probe_cpp()
{
    return pthread_spin_lock_function == pthread_spin_lock &&
                   pthread_spin_trylock_function == pthread_spin_trylock &&
                   pthread_spin_unlock_function == pthread_spin_unlock
               ? 0
               : 1;
}
