/* Static crabc-libc x86-64 normal pthread-mutex fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * against a `-nostdlib -static` executable linked only through the selected
 * crabc archive. It specifies one deliberately bounded process-private
 * normal-mutex slice: NULL-attribute initialization, lock, contended
 * trylock, unlock, and destroy. Two default-attribute joinable workers first
 * observe contention while the creator holds the mutex, then acquire and
 * release it after the creator releases that hold. This is not a claim for
 * mutex attributes, C11 wrappers, condition variables, process-shared,
 * robust, recursive, error-checking, timed, or cancellation behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>

_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutex_init),
    int (*)(pthread_mutex_t *__restrict, const pthread_mutexattr_t *__restrict)),
    "pthread_mutex_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutex_destroy),
    int (*)(pthread_mutex_t *)), "pthread_mutex_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutex_lock),
    int (*)(pthread_mutex_t *)), "pthread_mutex_lock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutex_trylock),
    int (*)(pthread_mutex_t *)), "pthread_mutex_trylock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_mutex_unlock),
    int (*)(pthread_mutex_t *)), "pthread_mutex_unlock declaration");

enum {
    WORKER_COUNT = 2,
    CONTENTION_ROUNDS = 6,
};

struct normal_mutex_round;

struct normal_mutex_worker {
    struct normal_mutex_round *round;
    int pre_release_trylock;
    int pre_release_unlock;
    int lock_result;
    int unlock_result;
    uintptr_t marker;
};

struct normal_mutex_round {
    pthread_mutex_t mutex;
    volatile int pre_release_count;
    volatile int release_workers;
    volatile int lock_attempt_count;
    volatile int critical_active;
    volatile int critical_entries;
    volatile int critical_overlap;
    volatile int release_critical;
};

/* This is intentionally distinct from the per-round `pthread_mutex_init`
 * route below: it proves the project header's all-zero static initializer
 * enters the same selected normal/private state machine before any init call.
 */
static pthread_mutex_t static_normal_mutex = PTHREAD_MUTEX_INITIALIZER;

static int run_static_initializer_probe(void)
{
    if (pthread_mutex_lock(&static_normal_mutex) != 0)
        return 1;
    if (pthread_mutex_trylock(&static_normal_mutex) != EBUSY) {
        (void)pthread_mutex_unlock(&static_normal_mutex);
        return 2;
    }
    if (pthread_mutex_unlock(&static_normal_mutex) != 0)
        return 3;
    if (pthread_mutex_destroy(&static_normal_mutex) != 0)
        return 4;
    return 0;
}

/* Each worker first proves that the creator's held normal mutex rejects a
 * trylock with EBUSY.  The external atomic gate makes that observation
 * deterministic without adding a condition-variable or another pthread
 * synchronization primitive to this selected slice. */
static void *normal_mutex_worker(void *opaque)
{
    struct normal_mutex_worker *worker = opaque;
    struct normal_mutex_round *round = worker->round;

    worker->pre_release_trylock = pthread_mutex_trylock(&round->mutex);
    worker->pre_release_unlock = 0;
    if (worker->pre_release_trylock == 0)
        worker->pre_release_unlock = pthread_mutex_unlock(&round->mutex);
    __atomic_fetch_add(&round->pre_release_count, 1, __ATOMIC_RELEASE);

    while (__atomic_load_n(&round->release_workers, __ATOMIC_ACQUIRE) == 0)
        ;

    worker->lock_result = pthread_mutex_lock(&round->mutex);
    __atomic_fetch_add(&round->lock_attempt_count, 1, __ATOMIC_RELEASE);
    worker->unlock_result = 0;
    if (worker->lock_result == 0) {
        if (__atomic_exchange_n(&round->critical_active, 1,
                __ATOMIC_ACQ_REL) != 0)
            __atomic_store_n(&round->critical_overlap, 1, __ATOMIC_RELEASE);
        __atomic_fetch_add(&round->critical_entries, 1, __ATOMIC_RELEASE);

        /* Hold the first acquired critical section until the creator has
         * observed it. If an invalid implementation admits both workers,
         * they remain simultaneously observable here rather than racing past
         * a short critical region. */
        while (__atomic_load_n(&round->release_critical, __ATOMIC_ACQUIRE) == 0)
            ;

        __atomic_store_n(&round->critical_active, 0, __ATOMIC_RELEASE);
        worker->unlock_result = pthread_mutex_unlock(&round->mutex);
    }

    return (void *)worker->marker;
}

static int run_normal_private_mutex_round(void)
{
    struct normal_mutex_round round = {0};
    struct normal_mutex_worker workers[WORKER_COUNT] = {
        {
            .round = &round,
            .pre_release_trylock = -1,
            .pre_release_unlock = -1,
            .lock_result = -1,
            .unlock_result = -1,
            .marker = (uintptr_t)0x0102030405060708ULL,
        },
        {
            .round = &round,
            .pre_release_trylock = -1,
            .pre_release_unlock = -1,
            .lock_result = -1,
            .unlock_result = -1,
            .marker = (uintptr_t)0x0807060504030201ULL,
        },
    };
    pthread_t threads[WORKER_COUNT];
    void *results[WORKER_COUNT] = {0, 0};
    int first_created = 0;
    int second_created = 0;
    int status = 0;

    errno = E2BIG;
    if (pthread_mutex_init(&round.mutex, 0) != 0)
        return 1;
    if (pthread_mutex_lock(&round.mutex) != 0) {
        (void)pthread_mutex_destroy(&round.mutex);
        return 2;
    }
    if (pthread_mutex_trylock(&round.mutex) != EBUSY) {
        (void)pthread_mutex_unlock(&round.mutex);
        (void)pthread_mutex_destroy(&round.mutex);
        return 3;
    }

    if (pthread_create(&threads[0], 0, normal_mutex_worker, &workers[0]) != 0) {
        (void)pthread_mutex_unlock(&round.mutex);
        (void)pthread_mutex_destroy(&round.mutex);
        return 4;
    }
    first_created = 1;
    if (pthread_create(&threads[1], 0, normal_mutex_worker, &workers[1]) != 0) {
        __atomic_store_n(&round.release_workers, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&round.release_critical, 1, __ATOMIC_RELEASE);
        (void)pthread_mutex_unlock(&round.mutex);
        (void)pthread_join(threads[0], 0);
        (void)pthread_mutex_destroy(&round.mutex);
        return 5;
    }
    second_created = 1;

    while (__atomic_load_n(&round.pre_release_count, __ATOMIC_ACQUIRE) !=
        WORKER_COUNT)
        ;

    if (pthread_mutex_unlock(&round.mutex) != 0 && status == 0)
        status = 6;
    __atomic_store_n(&round.release_workers, 1, __ATOMIC_RELEASE);

    /* A successful lock remains inside the externally held critical section
     * until this owner lets it proceed.  If both lock calls fail, release the
     * cleanup gate once both have reported that bounded attempt instead of
     * leaving an error path stuck in the fixture. */
    while (__atomic_load_n(&round.critical_entries, __ATOMIC_ACQUIRE) == 0 &&
        __atomic_load_n(&round.lock_attempt_count, __ATOMIC_ACQUIRE) !=
            WORKER_COUNT)
        ;
    __atomic_store_n(&round.release_critical, 1, __ATOMIC_RELEASE);

    if (first_created && pthread_join(threads[0], &results[0]) != 0 && status == 0)
        status = 7;
    if (second_created && pthread_join(threads[1], &results[1]) != 0 && status == 0)
        status = 8;
    if (workers[0].pre_release_trylock != EBUSY ||
        workers[1].pre_release_trylock != EBUSY ||
        workers[0].pre_release_unlock != 0 || workers[1].pre_release_unlock != 0) {
        if (status == 0)
            status = 9;
    }
    if (results[0] != (void *)workers[0].marker ||
        results[1] != (void *)workers[1].marker) {
        if (status == 0)
            status = 10;
    }
    if (workers[0].lock_result != 0 || workers[1].lock_result != 0 ||
        workers[0].unlock_result != 0 || workers[1].unlock_result != 0) {
        if (status == 0)
            status = 11;
    }
    if (__atomic_load_n(&round.lock_attempt_count, __ATOMIC_ACQUIRE) !=
            WORKER_COUNT ||
        __atomic_load_n(&round.critical_entries, __ATOMIC_ACQUIRE) != WORKER_COUNT ||
        __atomic_load_n(&round.critical_overlap, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&round.critical_active, __ATOMIC_ACQUIRE) != 0) {
        if (status == 0)
            status = 12;
    }

    if (pthread_mutex_trylock(&round.mutex) != 0) {
        if (status == 0)
            status = 13;
    } else if (pthread_mutex_unlock(&round.mutex) != 0 && status == 0) {
        status = 14;
    }
    if (pthread_mutex_destroy(&round.mutex) != 0 && status == 0)
        status = 15;
    if (errno != E2BIG && status == 0)
        status = 16;
    return status;
}

int crabc_x86_64_pthread_mutex_normal_probe(void)
{
    int round_index;
    int initializer_status;

    /* Six exact two-worker rounds are enough to require repeated waiter
     * mark/wake handoffs without turning this artifact into a stress suite or
     * a general pthread admission test. The exit-code encoding stays below
     * 255 so the freestanding entry shim preserves a failing round. */
    errno = E2BIG;
    initializer_status = run_static_initializer_probe();
    if (initializer_status != 0)
        return initializer_status;
    if (errno != E2BIG)
        return 8;
    for (round_index = 0; round_index != CONTENTION_ROUNDS; ++round_index) {
        int round_status = run_normal_private_mutex_round();

        if (round_status != 0)
            return 40 + (round_index * 20) + round_status;
    }
    return 0;
}

#ifndef CRABC_PTHREAD_MUTEX_NORMAL_FREESTANDING
int main(void)
{
    return crabc_x86_64_pthread_mutex_normal_probe();
}
#endif
