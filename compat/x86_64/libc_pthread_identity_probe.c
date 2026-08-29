/* Static crabc-libc x86-64 pthread identity fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * against a `-nostdlib -static` executable linked only through the selected
 * crabc archive. It specifies the selected public pthread identity surface:
 * stable main-thread identity, macro and function equality, C11 aliases, and
 * creator/worker handle identity for normal and explicit-exit workers. This
 * is not a general pthread lifecycle, synchronization, or C runtime claim.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <threads.h>

_Static_assert(__builtin_types_compatible_p(pthread_t, struct __pthread *),
    "x86 C pthread_t is an opaque thread pointer");
_Static_assert(__builtin_types_compatible_p(thrd_t, pthread_t),
    "C11 thrd_t aliases pthread_t");
/* Capture the project-header C macro route before selecting the public
 * function symbols below. The un-macroed calls verify that those symbols are
 * usable C ABI boundaries rather than merely header expressions. */
static int pthread_equal_macro(pthread_t left, pthread_t right)
{
    return pthread_equal(left, right);
}

static int thrd_equal_macro(thrd_t left, thrd_t right)
{
    return thrd_equal(left, right);
}

#undef pthread_equal
#undef thrd_equal

struct worker_observation {
    volatile int *entered;
    volatile int *release;
    pthread_t pthread_identity;
    thrd_t thrd_identity;
    int use_pthread_exit;
};

static void *observe_identity(void *opaque)
{
    struct worker_observation *observation = opaque;

    observation->pthread_identity = pthread_self();
    observation->thrd_identity = thrd_current();
    __atomic_fetch_add(observation->entered, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(observation->release, __ATOMIC_ACQUIRE) == 0)
        ;
    if (observation->use_pthread_exit)
        pthread_exit(observation->pthread_identity);
    return observation->pthread_identity;
}

static int check_worker_identity(pthread_t handle,
    const struct worker_observation *observation, pthread_t main_identity)
{
    if (handle == 0 || observation->pthread_identity == 0 ||
        observation->thrd_identity == 0)
        return 1;
    if (observation->pthread_identity != handle ||
        observation->thrd_identity != handle)
        return 2;
    if (observation->pthread_identity == main_identity ||
        observation->thrd_identity == main_identity)
        return 3;
    if (pthread_equal_macro(handle, observation->pthread_identity) != 1 ||
        pthread_equal(handle, observation->pthread_identity) != 1 ||
        thrd_equal_macro((thrd_t)handle, observation->thrd_identity) != 1 ||
        thrd_equal((thrd_t)handle, observation->thrd_identity) != 1)
        return 4;
    if (pthread_equal_macro(handle, main_identity) != 0 ||
        pthread_equal(handle, main_identity) != 0 ||
        thrd_equal_macro((thrd_t)handle, (thrd_t)main_identity) != 0 ||
        thrd_equal((thrd_t)handle, (thrd_t)main_identity) != 0)
        return 5;
    return 0;
}

static int run_two_live_workers(pthread_t main_identity, int expected_errno)
{
    volatile int entered = 0;
    volatile int release = 0;
    struct worker_observation first = {
        .entered = &entered,
        .release = &release,
        .pthread_identity = 0,
        .thrd_identity = 0,
        .use_pthread_exit = 0,
    };
    struct worker_observation second = {
        .entered = &entered,
        .release = &release,
        .pthread_identity = 0,
        .thrd_identity = 0,
        .use_pthread_exit = 0,
    };
    pthread_t first_handle;
    pthread_t second_handle;
    void *first_result = 0;
    void *second_result = 0;
    int identity_status = 0;

    if (pthread_create(&first_handle, 0, observe_identity, &first) != 0)
        return 1;
    if (pthread_create(&second_handle, 0, observe_identity, &second) != 0) {
        __atomic_store_n(&release, 1, __ATOMIC_RELEASE);
        (void)pthread_join(first_handle, 0);
        return 2;
    }
    while (__atomic_load_n(&entered, __ATOMIC_ACQUIRE) != 2)
        ;
    if (check_worker_identity(first_handle, &first, main_identity) != 0 ||
        check_worker_identity(second_handle, &second, main_identity) != 0)
        identity_status = 3;
    if (first_handle == second_handle ||
        first.pthread_identity == second.pthread_identity ||
        first.thrd_identity == second.thrd_identity)
        identity_status = 4;
    if (errno != expected_errno)
        identity_status = 5;

    __atomic_store_n(&release, 1, __ATOMIC_RELEASE);
    if (pthread_join(first_handle, &first_result) != 0 ||
        pthread_join(second_handle, &second_result) != 0)
        return 6;
    if (identity_status != 0)
        return identity_status;
    if (first_result != first_handle || second_result != second_handle)
        return 7;
    if (errno != expected_errno)
        return 8;
    return 0;
}

static int run_explicit_exit_worker(pthread_t main_identity, int expected_errno)
{
    volatile int entered = 0;
    volatile int release = 0;
    struct worker_observation observation = {
        .entered = &entered,
        .release = &release,
        .pthread_identity = 0,
        .thrd_identity = 0,
        .use_pthread_exit = 1,
    };
    pthread_t handle;
    void *result = 0;

    if (pthread_create(&handle, 0, observe_identity, &observation) != 0)
        return 1;
    while (__atomic_load_n(&entered, __ATOMIC_ACQUIRE) != 1)
        ;
    if (check_worker_identity(handle, &observation, main_identity) != 0) {
        __atomic_store_n(&release, 1, __ATOMIC_RELEASE);
        (void)pthread_join(handle, 0);
        return 2;
    }
    if (errno != expected_errno) {
        __atomic_store_n(&release, 1, __ATOMIC_RELEASE);
        (void)pthread_join(handle, 0);
        return 3;
    }
    __atomic_store_n(&release, 1, __ATOMIC_RELEASE);
    if (pthread_join(handle, &result) != 0)
        return 4;
    if (result != handle)
        return 5;
    if (errno != expected_errno)
        return 6;
    return 0;
}

int crabc_x86_64_pthread_identity_probe(void)
{
    pthread_t main_identity = pthread_self();
    thrd_t main_c11_identity = thrd_current();

    if (main_identity == 0 || main_c11_identity == 0 ||
        main_identity != main_c11_identity)
        return 10;
    if (pthread_self() != main_identity || thrd_current() != main_c11_identity)
        return 11;
    if (pthread_equal_macro(main_identity, main_identity) != 1 ||
        pthread_equal(main_identity, main_identity) != 1 ||
        thrd_equal_macro(main_c11_identity, main_c11_identity) != 1 ||
        thrd_equal(main_c11_identity, main_c11_identity) != 1)
        return 12;
    if ((void (*)(void))pthread_self != (void (*)(void))thrd_current ||
        (void (*)(void))pthread_equal != (void (*)(void))thrd_equal)
        return 13;

    errno = E2BIG;
    if (run_two_live_workers(main_identity, E2BIG) != 0)
        return 20;
    if (run_explicit_exit_worker(main_identity, E2BIG) != 0)
        return 30;
    if (errno != E2BIG || pthread_self() != main_identity ||
        thrd_current() != main_c11_identity)
        return 40;
    return 0;
}

#ifndef CRABC_PTHREAD_IDENTITY_FREESTANDING
int main(void)
{
    return crabc_x86_64_pthread_identity_probe();
}
#endif
