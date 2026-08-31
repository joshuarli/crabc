/* Static crabc-libc x86-64 bounded pthread_spin_init fixture.
 *
 * The same project-header body first executes against pinned musl 1.2.6, then
 * as a dependency-free -nostdlib -static candidate. It proves only that musl
 * stores a zero into valid caller-owned pthread_spinlock_t storage and returns
 * that zero while ignoring every pshared value. It does not select lock,
 * trylock, unlock, destroy, process sharing, synchronization, thread/TLS
 * lifecycle, or general pthread behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <limits.h>
#include <pthread.h>

typedef int (*pthread_spin_init_signature)(pthread_spinlock_t *, int);

_Static_assert(sizeof(int) == 4 && sizeof(pthread_spinlock_t) == 4,
    "musl x86-64 pthread_spinlock_t scalar ABI");
_Static_assert(_Alignof(pthread_spinlock_t) == _Alignof(int),
    "musl x86-64 pthread_spinlock_t alignment");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_spin_init),
    pthread_spin_init_signature), "pthread_spin_init declaration");

static pthread_spin_init_signature direct_pthread_spin_init = pthread_spin_init;

static int check_case(int initial, int shared, int failure_base)
{
    pthread_spinlock_t spinlock = initial;

    if (direct_pthread_spin_init(&spinlock, shared) != 0)
        return failure_base;
    if (spinlock != 0)
        return failure_base + 1;
    return 0;
}

int crabc_x86_64_pthread_spin_init_probe(void)
{
    static const int initial_values[] = { 0, 1, -1, INT_MIN, INT_MAX };
    static const int shared_values[] = { 0, 1, -1, INT_MIN, INT_MAX };
    unsigned initial_index;
    unsigned shared_index;

    for (initial_index = 0;
         initial_index < sizeof(initial_values) / sizeof(initial_values[0]);
         initial_index++) {
        for (shared_index = 0;
             shared_index < sizeof(shared_values) / sizeof(shared_values[0]);
             shared_index++) {
            int result = check_case(initial_values[initial_index],
                shared_values[shared_index],
                1 + (int)(initial_index * 10 + shared_index * 2));
            if (result != 0)
                return result;
        }
    }
    return 0;
}

#if !defined(CRABC_PTHREAD_SPIN_INIT_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_spin_init_probe();
}
#endif
