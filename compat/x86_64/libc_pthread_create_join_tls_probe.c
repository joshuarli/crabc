/* Static crabc-libc x86-64 pthread create/join initial-TLS fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * against a `-nostdlib -static` candidate linked solely through the selected
 * crabc archive. It specifies one deliberately bounded worker contract:
 * a default-attribute joinable worker receives a distinct zeroed initial-TLS
 * errno slot, returns one pointer through pthread_join, and leaves its
 * creator's errno untouched. It does not exercise attributes, detachment,
 * cancellation, TSD, synchronization objects, or a general pthread runtime.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>

_Static_assert(__builtin_types_compatible_p(pthread_t, struct __pthread *),
    "x86 C pthread_t is an opaque thread pointer");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_create),
    int (*)(pthread_t *__restrict, const pthread_attr_t *__restrict,
        void *(*)(void *), void *__restrict)),
    "pthread_create declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_join),
    int (*)(pthread_t, void **)), "pthread_join declaration");

struct worker_observation {
    int *errno_location;
    int initial_errno;
    int final_errno;
    uintptr_t marker;
};

struct held_worker_observation {
    int *errno_location;
    int initial_errno;
    int final_errno;
    volatile int *entered;
    volatile int *release;
    uintptr_t marker;
};

static void *observe_worker(void *opaque)
{
    struct worker_observation *observation = opaque;

    observation->errno_location = __errno_location();
    observation->initial_errno = errno;
    errno = E2BIG;
    observation->final_errno = errno;
    return (void *)observation->marker;
}

static void *observe_held_worker(void *opaque)
{
    struct held_worker_observation *observation = opaque;

    observation->errno_location = __errno_location();
    observation->initial_errno = errno;
    errno = E2BIG;
    observation->final_errno = errno;
    __atomic_fetch_add(observation->entered, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(observation->release, __ATOMIC_ACQUIRE) == 0)
        ;
    return (void *)observation->marker;
}

static int run_worker_round(uintptr_t marker, int *main_errno_location)
{
    pthread_t thread;
    struct worker_observation observation = {
        .errno_location = 0,
        .initial_errno = -1,
        .final_errno = -1,
        .marker = marker,
    };
    void *thread_result = 0;

    if (pthread_create(&thread, 0, observe_worker, &observation) != 0)
        return 1;
    if (pthread_join(thread, &thread_result) != 0)
        return 2;
    if (thread_result != (void *)marker)
        return 3;
    if (observation.errno_location == 0 ||
        observation.errno_location == main_errno_location)
        return 4;
    if (observation.initial_errno != 0 || observation.final_errno != E2BIG)
        return 5;
    if (errno != EACCES || __errno_location() != main_errno_location)
        return 6;
    return 0;
}

static int run_null_result_join(int *main_errno_location)
{
    pthread_t thread;
    struct worker_observation observation = {
        .errno_location = 0,
        .initial_errno = -1,
        .final_errno = -1,
        .marker = (uintptr_t)0x1020304050607080ULL,
    };

    if (pthread_create(&thread, 0, observe_worker, &observation) != 0)
        return 1;
    if (pthread_join(thread, 0) != 0)
        return 2;
    if (observation.errno_location == 0 ||
        observation.errno_location == main_errno_location)
        return 3;
    if (observation.initial_errno != 0 || observation.final_errno != E2BIG)
        return 4;
    if (errno != EACCES || __errno_location() != main_errno_location)
        return 5;
    return 0;
}

static int run_concurrent_worker_round(int *main_errno_location)
{
    pthread_t first_thread;
    pthread_t second_thread;
    volatile int entered = 0;
    volatile int release = 0;
    struct held_worker_observation first = {
        .errno_location = 0,
        .initial_errno = -1,
        .final_errno = -1,
        .entered = &entered,
        .release = &release,
        .marker = (uintptr_t)0x0102030405060708ULL,
    };
    struct held_worker_observation second = {
        .errno_location = 0,
        .initial_errno = -1,
        .final_errno = -1,
        .entered = &entered,
        .release = &release,
        .marker = (uintptr_t)0x0807060504030201ULL,
    };
    void *first_result = 0;
    void *second_result = 0;

    if (pthread_create(&first_thread, 0, observe_held_worker, &first) != 0)
        return 1;
    if (pthread_create(&second_thread, 0, observe_held_worker, &second) != 0) {
        __atomic_store_n(&release, 1, __ATOMIC_RELEASE);
        (void)pthread_join(first_thread, 0);
        return 2;
    }
    while (__atomic_load_n(&entered, __ATOMIC_ACQUIRE) != 2)
        ;
    if (first.errno_location == 0 || second.errno_location == 0 ||
        first.errno_location == main_errno_location ||
        second.errno_location == main_errno_location ||
        first.errno_location == second.errno_location)
        return 3;
    if (first.initial_errno != 0 || second.initial_errno != 0 ||
        first.final_errno != E2BIG || second.final_errno != E2BIG)
        return 4;
    if (errno != EACCES || __errno_location() != main_errno_location)
        return 5;

    __atomic_store_n(&release, 1, __ATOMIC_RELEASE);
    if (pthread_join(first_thread, &first_result) != 0)
        return 6;
    if (pthread_join(second_thread, &second_result) != 0)
        return 7;
    if (first_result != (void *)first.marker ||
        second_result != (void *)second.marker)
        return 8;
    if (errno != EACCES || __errno_location() != main_errno_location)
        return 9;
    return 0;
}

int crabc_x86_64_pthread_create_join_tls_probe(void)
{
    int *main_errno_location = __errno_location();

    if (main_errno_location == 0 || errno != 0)
        return 10;
    errno = EACCES;
    if (errno != EACCES || __errno_location() != main_errno_location)
        return 11;

    int first = run_worker_round((uintptr_t)0x1122334455667788ULL,
        main_errno_location);
    if (first != 0)
        return 20 + first;
    int second = run_worker_round((uintptr_t)0x8877665544332211ULL,
        main_errno_location);
    if (second != 0)
        return 40 + second;

    int null_result = run_null_result_join(main_errno_location);
    if (null_result != 0)
        return 60 + null_result;

    int concurrent = run_concurrent_worker_round(main_errno_location);
    if (concurrent != 0)
        return 80 + concurrent;

    return 0;
}

#ifndef CRABC_PTHREAD_CREATE_JOIN_TLS_FREESTANDING
int main(void)
{
    return crabc_x86_64_pthread_create_join_tls_probe();
}
#endif
