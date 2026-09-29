/* Static crabc-libc x86-64 private pthread-condition fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * against a `-nostdlib -static` executable linked only through the selected
 * crabc archive. It specifies one deliberately bounded process-private
 * condition-variable block paired with the selected normal mutex: all-zero
 * static or NULL-attribute initialization, wait, signal, broadcast, reused
 * two-waiter handoff, cancellation removal amid live waiters, and quiescent
 * destruction. It is not a claim for condition attributes, process-shared or timed waits, C11
 * conditions, allocator integration, dynamic TLS, a general pthread runtime,
 * CRT, loader, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>

_Static_assert(sizeof(pthread_mutex_t) == 40 && _Alignof(pthread_mutex_t) == 8,
    "musl x86-64 pthread_mutex_t ABI");
_Static_assert(sizeof(pthread_cond_t) == 48 && _Alignof(pthread_cond_t) == 8,
    "musl x86-64 pthread_cond_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_cond_init),
    int (*)(pthread_cond_t *__restrict, const pthread_condattr_t *__restrict)),
    "pthread_cond_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_cond_destroy),
    int (*)(pthread_cond_t *)), "pthread_cond_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_cond_wait),
    int (*)(pthread_cond_t *__restrict, pthread_mutex_t *__restrict)),
    "pthread_cond_wait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_cond_signal),
    int (*)(pthread_cond_t *)), "pthread_cond_signal declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_cond_broadcast),
    int (*)(pthread_cond_t *)), "pthread_cond_broadcast declaration");
_Static_assert(EACCES == 13 && E2BIG == 7 && ENOTSUP == 95,
    "Linux x86 condition fixture errno values");

/* The reference and freestanding candidate use the same direct Linux write
 * for a deterministic phase stream, without requiring a stdio runtime. */
static int report_phase(const char *message, unsigned long length)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(1L), "D"(1L), "S"(message), "d"(length)
        : "rcx", "r11", "memory");
    return result == (long)length ? 0 : 1;
}

#define REPORT_PHASE(message) report_phase(message, sizeof(message) - 1)

enum {
    BROADCAST_WAITER_COUNT = 2,
    PING_PONG_HANDOFFS = 64,
    PING_PONG_ROUNDS = 4,
    REUSE_ROUNDS = 8,
};

/* The predicate remains protected by `mutex`. The three atomic counters are
 * only fixture-visible admission/observation gates: after a worker increments
 * `entered` while holding the mutex, the parent locks that mutex before it
 * signals. That establishes that pthread_cond_wait has atomically enrolled
 * the worker and released the selected normal mutex before a wake can occur.
 */
struct private_condition_round {
    pthread_cond_t condition;
    pthread_mutex_t mutex;
    volatile int entered;
    volatile int release;
    volatile int awakened;
};

struct condition_waiter {
    struct private_condition_round *round;
    int lock_result;
    int wait_result;
    int unlock_result;
    int observed_release;
    int final_errno;
    uintptr_t marker;
};

/* This static pair is intentionally distinct from every init(NULL) round. It
 * proves the all-zero public PTHREAD_COND_INITIALIZER and
 * PTHREAD_MUTEX_INITIALIZER records enter the same selected private state
 * machine before either initializer function has been called. */
static struct private_condition_round static_condition_round = {
    .condition = PTHREAD_COND_INITIALIZER,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
};

static void *condition_waiter_main(void *opaque)
{
    struct condition_waiter *waiter = opaque;
    struct private_condition_round *round = waiter->round;

    errno = EACCES;
    waiter->lock_result = pthread_mutex_lock(&round->mutex);
    waiter->wait_result = 0;
    waiter->unlock_result = 0;
    waiter->observed_release = 0;
    if (waiter->lock_result == 0) {
        __atomic_fetch_add(&round->entered, 1, __ATOMIC_RELEASE);
        while (__atomic_load_n(&round->release, __ATOMIC_ACQUIRE) == 0) {
            waiter->wait_result = pthread_cond_wait(&round->condition,
                &round->mutex);
            if (waiter->wait_result != 0)
                break;
        }
        if (waiter->wait_result == 0 &&
            __atomic_load_n(&round->release, __ATOMIC_ACQUIRE) != 0) {
            waiter->observed_release = 1;
            __atomic_fetch_add(&round->awakened, 1, __ATOMIC_RELEASE);
        }
        waiter->unlock_result = pthread_mutex_unlock(&round->mutex);
    }
    waiter->final_errno = errno;
    return (void *)waiter->marker;
}

/* Wake one or two enrolled workers. The parent locks the same normal mutex
 * after `entered` reaches `waiter_count`; pthread_cond_wait's atomic
 * unlock-and-enroll operation means that lock acquisition closes the lost-wake
 * window before it publishes `release` and notifies. */
static int run_waiter_round(struct private_condition_round *round,
    int waiter_count, int use_broadcast)
{
    struct condition_waiter waiters[BROADCAST_WAITER_COUNT] = {
        {
            .round = round,
            .lock_result = -1,
            .wait_result = -1,
            .unlock_result = -1,
            .observed_release = -1,
            .final_errno = -1,
            .marker = (uintptr_t)0x0102030405060708ULL,
        },
        {
            .round = round,
            .lock_result = -1,
            .wait_result = -1,
            .unlock_result = -1,
            .observed_release = -1,
            .final_errno = -1,
            .marker = (uintptr_t)0x0807060504030201ULL,
        },
    };
    pthread_t threads[BROADCAST_WAITER_COUNT];
    void *results[BROADCAST_WAITER_COUNT] = { 0, 0 };
    int created = 0;
    int index;
    int status = 0;

    for (index = 0; index != waiter_count; ++index) {
        if (pthread_create(&threads[index], 0, condition_waiter_main,
                &waiters[index]) != 0) {
            status = 1 + index;
            break;
        }
        ++created;
    }

    if (status == 0) {
        while (__atomic_load_n(&round->entered, __ATOMIC_ACQUIRE) !=
            waiter_count)
            ;

        if (pthread_mutex_lock(&round->mutex) != 0) {
            status = 3;
        } else {
            int notify_result;

            __atomic_store_n(&round->release, 1, __ATOMIC_RELEASE);
            notify_result = use_broadcast
                ? pthread_cond_broadcast(&round->condition)
                : pthread_cond_signal(&round->condition);
            if (notify_result != 0)
                status = 4;
            /* If the selected notify boundary reports an error, give every
             * waiter one bounded cleanup wake before collecting its result.
             * A correct single-signal round never takes this path. */
            if (status != 0)
                (void)pthread_cond_broadcast(&round->condition);
            if (pthread_mutex_unlock(&round->mutex) != 0 && status == 0)
                status = 5;
        }
    }

    if (status != 0 && created != 0 &&
        __atomic_load_n(&round->release, __ATOMIC_ACQUIRE) == 0) {
        /* Creation failures are not a behavior claim. Make already-created
         * waiters leave before the caller records the failure. */
        if (pthread_mutex_lock(&round->mutex) == 0) {
            __atomic_store_n(&round->release, 1, __ATOMIC_RELEASE);
            (void)pthread_cond_broadcast(&round->condition);
            (void)pthread_mutex_unlock(&round->mutex);
        }
    }

    for (index = 0; index != created; ++index) {
        if (pthread_join(threads[index], &results[index]) != 0 && status == 0)
            status = 6 + index;
    }
    if (status != 0)
        return status;

    for (index = 0; index != waiter_count; ++index) {
        if (results[index] != (void *)waiters[index].marker)
            return 8 + index;
        if (waiters[index].lock_result != 0 ||
            waiters[index].wait_result != 0 ||
            waiters[index].unlock_result != 0 ||
            waiters[index].observed_release != 1)
            return 10 + index;
        if (waiters[index].final_errno != EACCES)
            return 12 + index;
    }
    if (__atomic_load_n(&round->entered, __ATOMIC_ACQUIRE) != waiter_count ||
        __atomic_load_n(&round->awakened, __ATOMIC_ACQUIRE) != waiter_count)
        return 14;
    return 0;
}

static int run_static_initializer_round(void)
{
    int status;

    errno = E2BIG;
    status = run_waiter_round(&static_condition_round, 1, 0);
    if (status != 0)
        return status;
    if (pthread_cond_destroy(&static_condition_round.condition) != 0)
        return 16;
    if (pthread_mutex_destroy(&static_condition_round.mutex) != 0)
        return 17;
    if (errno != E2BIG)
        return 18;
    return 0;
}

static int run_initialized_waiter_round(int waiter_count, int use_broadcast)
{
    struct private_condition_round round = { 0 };
    int status;

    errno = E2BIG;
    if (pthread_mutex_init(&round.mutex, 0) != 0)
        return 1;
    if (pthread_cond_init(&round.condition, 0) != 0) {
        (void)pthread_mutex_destroy(&round.mutex);
        return 2;
    }
    status = run_waiter_round(&round, waiter_count, use_broadcast);
    if (pthread_cond_destroy(&round.condition) != 0 && status == 0)
        status = 20;
    if (pthread_mutex_destroy(&round.mutex) != 0 && status == 0)
        status = 21;
    if (errno != E2BIG && status == 0)
        status = 22;
    return status;
}

/* Signal with no enrolled waiter still returns through the selected private
 * condition boundary and retains the caller's stale errno. It uses the same
 * normal mutex/predicate discipline as the wake rounds without making any
 * claim about signaling unpaired application state. */
static int run_no_waiter_signal_round(void)
{
    struct private_condition_round round = { 0 };
    int status = 0;

    errno = E2BIG;
    if (pthread_mutex_init(&round.mutex, 0) != 0)
        return 1;
    if (pthread_cond_init(&round.condition, 0) != 0) {
        (void)pthread_mutex_destroy(&round.mutex);
        return 2;
    }
    if (pthread_mutex_lock(&round.mutex) != 0)
        status = 3;
    else {
        if (pthread_cond_signal(&round.condition) != 0)
            status = 4;
        if (pthread_mutex_unlock(&round.mutex) != 0 && status == 0)
            status = 5;
    }
    if (pthread_cond_destroy(&round.condition) != 0 && status == 0)
        status = 6;
    if (pthread_mutex_destroy(&round.mutex) != 0 && status == 0)
        status = 7;
    if (errno != E2BIG && status == 0)
        status = 8;
    return status;
}

struct reuse_round {
    pthread_cond_t condition;
    pthread_mutex_t mutex;
    volatile int entered;
    volatile int completed;
    int permits;
};

struct reuse_waiter {
    struct reuse_round *round;
    int status;
    int final_errno;
    uintptr_t marker;
};

/* Each permit is consumed with the mutex held. A spurious wake can only retry
 * the predicate; it cannot finish a worker or consume the next permit. */
static void *reuse_waiter_main(void *opaque)
{
    struct reuse_waiter *waiter = opaque;
    struct reuse_round *round = waiter->round;
    int result;

    errno = EACCES;
    waiter->status = 0;
    result = pthread_mutex_lock(&round->mutex);
    if (result != 0) {
        waiter->status = 1;
    } else {
        __atomic_fetch_add(&round->entered, 1, __ATOMIC_RELEASE);
        while (round->permits == 0) {
            result = pthread_cond_wait(&round->condition, &round->mutex);
            if (result != 0) {
                waiter->status = 2;
                break;
            }
        }
        if (waiter->status == 0) {
            --round->permits;
            __atomic_fetch_add(&round->completed, 1, __ATOMIC_RELEASE);
        }
        if (pthread_mutex_unlock(&round->mutex) != 0 && waiter->status == 0)
            waiter->status = 3;
    }
    waiter->final_errno = errno;
    return (void *)waiter->marker;
}

/* One signal admits exactly one permit, then a broadcast admits the other.
 * Reuse the same initialized condition after both workers have joined, with
 * every object quiescent before its final destruction. */
static int run_reuse_round(void)
{
    struct reuse_round round = { 0 };
    int epoch;
    int status = 0;

    errno = E2BIG;
    if (pthread_mutex_init(&round.mutex, 0) != 0)
        return 1;
    if (pthread_cond_init(&round.condition, 0) != 0) {
        (void)pthread_mutex_destroy(&round.mutex);
        return 2;
    }
    for (epoch = 0; epoch != REUSE_ROUNDS && status == 0; ++epoch) {
        struct reuse_waiter waiters[BROADCAST_WAITER_COUNT] = {
            { .round = &round, .status = -1, .final_errno = -1,
              .marker = (uintptr_t)0x1020304050607080ULL },
            { .round = &round, .status = -1, .final_errno = -1,
              .marker = (uintptr_t)0x8070605040302010ULL },
        };
        pthread_t threads[BROADCAST_WAITER_COUNT];
        void *results[BROADCAST_WAITER_COUNT] = { 0, 0 };
        int created = 0;
        int index;

        __atomic_store_n(&round.entered, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&round.completed, 0, __ATOMIC_RELEASE);
        round.permits = 0;
        for (index = 0; index != BROADCAST_WAITER_COUNT; ++index) {
            if (pthread_create(&threads[index], 0, reuse_waiter_main,
                    &waiters[index]) != 0) {
                status = 3;
                break;
            }
            ++created;
        }
        if (status == 0) {
            while (__atomic_load_n(&round.entered, __ATOMIC_ACQUIRE) !=
                BROADCAST_WAITER_COUNT)
                ;
            /* Both workers entered while holding the mutex. Acquiring it
             * now observes their atomic wait enrollment and unlock. */
            if (pthread_mutex_lock(&round.mutex) != 0) {
                status = 4;
            } else {
                round.permits = 1;
                if (pthread_cond_signal(&round.condition) != 0)
                    status = 5;
                if (pthread_mutex_unlock(&round.mutex) != 0 && status == 0)
                    status = 6;
            }
        }
        if (status == 0) {
            while (__atomic_load_n(&round.completed, __ATOMIC_ACQUIRE) < 1)
                ;
            if (pthread_mutex_lock(&round.mutex) != 0) {
                status = 7;
            } else {
                if (__atomic_load_n(&round.completed, __ATOMIC_ACQUIRE) != 1 ||
                    round.permits != 0)
                    status = 8;
                round.permits = 1;
                if (pthread_cond_broadcast(&round.condition) != 0 && status == 0)
                    status = 9;
                if (pthread_mutex_unlock(&round.mutex) != 0 && status == 0)
                    status = 10;
            }
        }
        if (status != 0 && created != 0) {
            if (pthread_mutex_lock(&round.mutex) == 0) {
                round.permits = created;
                (void)pthread_cond_broadcast(&round.condition);
                (void)pthread_mutex_unlock(&round.mutex);
            }
        }
        for (index = 0; index != created; ++index) {
            if (pthread_join(threads[index], &results[index]) != 0 &&
                status == 0)
                status = 11;
        }
        if (status == 0) {
            for (index = 0; index != BROADCAST_WAITER_COUNT; ++index) {
                if (results[index] != (void *)waiters[index].marker ||
                    waiters[index].status != 0 ||
                    waiters[index].final_errno != EACCES)
                    status = 12;
            }
            if (__atomic_load_n(&round.entered, __ATOMIC_ACQUIRE) != 2 ||
                __atomic_load_n(&round.completed, __ATOMIC_ACQUIRE) != 2 ||
                round.permits != 0)
                status = 13;
        }
    }
    if (pthread_cond_destroy(&round.condition) != 0 && status == 0)
        status = 14;
    if (pthread_mutex_destroy(&round.mutex) != 0 && status == 0)
        status = 15;
    if (errno != E2BIG && status == 0)
        status = 16;
    return status;
}

struct canceled_middle_round {
    pthread_cond_t condition;
    pthread_mutex_t mutex;
    volatile int entered;
    volatile int completed;
    volatile int cleanup_count;
    volatile int cleanup_mutex_held;
    int permits;
};

struct canceled_middle_waiter {
    struct canceled_middle_round *round;
    int status;
    int final_errno;
    uintptr_t marker;
};

/* A canceled condition waiter runs cleanup after its condition wait has
 * reacquired the mutex. Leave the mutex unlocked so surviving waiters can
 * consume their later permits on this same condition object. */
static void canceled_middle_cleanup(void *opaque)
{
    struct canceled_middle_round *round = opaque;
    int held = pthread_mutex_trylock(&round->mutex) == EBUSY;

    __atomic_store_n(&round->cleanup_mutex_held, held, __ATOMIC_RELEASE);
    __atomic_fetch_add(&round->cleanup_count, 1, __ATOMIC_RELEASE);
    (void)pthread_mutex_unlock(&round->mutex);
}

static void *canceled_middle_waiter_main(void *opaque)
{
    struct canceled_middle_waiter *waiter = opaque;
    struct canceled_middle_round *round = waiter->round;

    errno = EACCES;
    waiter->status = pthread_mutex_lock(&round->mutex);
    if (waiter->status != 0)
        return 0;
    pthread_cleanup_push(canceled_middle_cleanup, round);
    __atomic_fetch_add(&round->entered, 1, __ATOMIC_RELEASE);
    while (round->permits == 0) {
        waiter->status = pthread_cond_wait(&round->condition, &round->mutex);
        if (waiter->status != 0)
            break;
    }
    if (waiter->status == 0) {
        --round->permits;
        __atomic_fetch_add(&round->completed, 1, __ATOMIC_RELEASE);
    }
    pthread_cleanup_pop(0);
    if (pthread_mutex_unlock(&round->mutex) != 0 && waiter->status == 0)
        waiter->status = 1;
    waiter->final_errno = errno;
    return (void *)waiter->marker;
}

/* Cancel the middle of three enrolled waiters. Signal and broadcast must
 * hand two subsequent permits only to the survivors. A fourth worker then
 * reuses the same condition and mutex after the canceled node has retired. */
static int run_canceled_middle_round(void)
{
    struct canceled_middle_round round = { 0 };
    struct canceled_middle_waiter waiters[4] = {
        { .round = &round, .marker = (uintptr_t)0x1020304050607080ULL },
        { .round = &round, .marker = (uintptr_t)0x2030405060708090ULL },
        { .round = &round, .marker = (uintptr_t)0x30405060708090a0ULL },
        { .round = &round, .marker = (uintptr_t)0x405060708090a0b0ULL },
    };
    pthread_t threads[4];
    void *results[4] = { 0, 0, 0, 0 };
    int index;
    int status = 0;

    errno = E2BIG;
    if (pthread_mutex_init(&round.mutex, 0) != 0)
        return 1;
    if (pthread_cond_init(&round.condition, 0) != 0)
        return 2;
    for (index = 0; index != 3; ++index) {
        if (pthread_create(&threads[index], 0, canceled_middle_waiter_main,
                &waiters[index]) != 0)
            return 3;
        while (__atomic_load_n(&round.entered, __ATOMIC_ACQUIRE) != index + 1)
            ;
        /* The worker released the mutex only after enrolling its waiter. */
        if (pthread_mutex_lock(&round.mutex) != 0 ||
            pthread_mutex_unlock(&round.mutex) != 0)
            return 4;
    }
    if (pthread_cancel(threads[1]) != 0 ||
        pthread_join(threads[1], &results[1]) != 0)
        return 5;
    if (results[1] != PTHREAD_CANCELED ||
        __atomic_load_n(&round.cleanup_count, __ATOMIC_ACQUIRE) != 1 ||
        __atomic_load_n(&round.cleanup_mutex_held, __ATOMIC_ACQUIRE) != 1)
        return 6;

    if (pthread_mutex_lock(&round.mutex) != 0)
        return 7;
    round.permits = 1;
    if (pthread_cond_signal(&round.condition) != 0 ||
        pthread_mutex_unlock(&round.mutex) != 0)
        return 8;
    while (__atomic_load_n(&round.completed, __ATOMIC_ACQUIRE) != 1)
        ;
    if (pthread_mutex_lock(&round.mutex) != 0)
        return 9;
    if (round.permits != 0)
        return 10;
    round.permits = 1;
    if (pthread_cond_broadcast(&round.condition) != 0 ||
        pthread_mutex_unlock(&round.mutex) != 0)
        return 11;
    for (index = 0; index < 3; index += 2) {
        if (pthread_join(threads[index], &results[index]) != 0)
            return 12;
        if (results[index] != (void *)waiters[index].marker ||
            waiters[index].status != 0 || waiters[index].final_errno != EACCES)
            status = 13;
    }
    if (status != 0 || __atomic_load_n(&round.completed, __ATOMIC_ACQUIRE) != 2 ||
        round.permits != 0)
        return 14;

    if (pthread_create(&threads[3], 0, canceled_middle_waiter_main,
            &waiters[3]) != 0)
        return 15;
    while (__atomic_load_n(&round.entered, __ATOMIC_ACQUIRE) != 4)
        ;
    if (pthread_mutex_lock(&round.mutex) != 0)
        return 16;
    if (round.permits != 0 ||
        __atomic_load_n(&round.completed, __ATOMIC_ACQUIRE) != 2)
        return 17;
    round.permits = 1;
    if (pthread_cond_signal(&round.condition) != 0 ||
        pthread_mutex_unlock(&round.mutex) != 0)
        return 18;
    if (pthread_join(threads[3], &results[3]) != 0 ||
        results[3] != (void *)waiters[3].marker ||
        waiters[3].status != 0 || waiters[3].final_errno != EACCES ||
        __atomic_load_n(&round.completed, __ATOMIC_ACQUIRE) != 3 ||
        __atomic_load_n(&round.cleanup_count, __ATOMIC_ACQUIRE) != 1)
        return 19;
    if (pthread_cond_destroy(&round.condition) != 0 ||
        pthread_mutex_destroy(&round.mutex) != 0 || errno != E2BIG)
        return 20;
    return 0;
}

/* This is deliberately candidate-only boundary evidence, not a pinned-musl
 * comparison: musl accepts a valid condition attribute while this selected
 * static x86 slice rejects every non-NULL attribute without reading it. */
#if defined(CRABC_PTHREAD_COND_PRIVATE_FREESTANDING)
static int run_candidate_only_attribute_rejection(void)
{
    pthread_cond_t condition = { 0 };
    pthread_condattr_t attribute = { 0 };

    errno = E2BIG;
    if (pthread_cond_init(&condition, &attribute) != ENOTSUP)
        return 1;
    if (errno != E2BIG)
        return 2;
    return 0;
}
#endif

struct ping_pong_round {
    pthread_cond_t condition;
    pthread_mutex_t mutex;
    int turn;
    int remaining;
    int stopped;
    int actions[BROADCAST_WAITER_COUNT];
    volatile int wait_entries[BROADCAST_WAITER_COUNT];
};

struct ping_pong_worker {
    struct ping_pong_round *round;
    int index;
    int status;
    int final_errno;
    uintptr_t marker;
};

/* A 64-step predicate handoff is repeated four times below. Worker one is
 * enrolled before worker zero is created, so each round must use a real
 * condition wait before the first signal. The protected turn predicate makes
 * subsequent notifications safe even if the scheduler lets a signal arrive
 * before its peer has blocked. */
static void *ping_pong_worker_main(void *opaque)
{
    struct ping_pong_worker *worker = opaque;
    struct ping_pong_round *round = worker->round;

    errno = EACCES;
    worker->status = 0;
    for (;;) {
        int result = pthread_mutex_lock(&round->mutex);

        if (result != 0) {
            worker->status = 1;
            break;
        }
        while (round->stopped == 0 && round->remaining != 0 &&
            round->turn != worker->index) {
            __atomic_fetch_add(&round->wait_entries[worker->index], 1,
                __ATOMIC_RELEASE);
            result = pthread_cond_wait(&round->condition, &round->mutex);
            if (result != 0) {
                worker->status = 2;
                round->stopped = 1;
                (void)pthread_cond_broadcast(&round->condition);
                break;
            }
        }
        if (worker->status != 0 || round->stopped != 0 ||
            round->remaining == 0) {
            if (round->remaining == 0 && round->stopped == 0 &&
                pthread_cond_signal(&round->condition) != 0)
                worker->status = 3;
            if (pthread_mutex_unlock(&round->mutex) != 0 &&
                worker->status == 0)
                worker->status = 4;
            break;
        }

        --round->remaining;
        ++round->actions[worker->index];
        round->turn = worker->index ^ 1;
        if (pthread_cond_signal(&round->condition) != 0) {
            worker->status = 5;
            round->stopped = 1;
            (void)pthread_cond_broadcast(&round->condition);
        }
        if (pthread_mutex_unlock(&round->mutex) != 0 && worker->status == 0)
            worker->status = 6;
        if (worker->status != 0)
            break;
    }
    worker->final_errno = errno;
    return (void *)worker->marker;
}

static int run_ping_pong_round(void)
{
    struct ping_pong_round round = {
        .turn = 0,
        .remaining = PING_PONG_HANDOFFS,
    };
    struct ping_pong_worker workers[BROADCAST_WAITER_COUNT] = {
        {
            .round = &round,
            .index = 0,
            .status = -1,
            .final_errno = -1,
            .marker = (uintptr_t)0x1122334455667788ULL,
        },
        {
            .round = &round,
            .index = 1,
            .status = -1,
            .final_errno = -1,
            .marker = (uintptr_t)0x8877665544332211ULL,
        },
    };
    pthread_t threads[BROADCAST_WAITER_COUNT];
    void *results[BROADCAST_WAITER_COUNT] = { 0, 0 };
    int status = 0;

    errno = E2BIG;
    if (pthread_mutex_init(&round.mutex, 0) != 0)
        return 1;
    if (pthread_cond_init(&round.condition, 0) != 0) {
        (void)pthread_mutex_destroy(&round.mutex);
        return 2;
    }

    /* Start the non-turn worker first and wait until it has made the initial
     * condition-wait attempt. Locking and unlocking the mutex then confirms
     * its atomic release/enrollment before the turn-zero worker can signal. */
    if (pthread_create(&threads[1], 0, ping_pong_worker_main, &workers[1]) != 0)
        status = 3;
    if (status == 0) {
        while (__atomic_load_n(&round.wait_entries[1], __ATOMIC_ACQUIRE) == 0)
            ;
        if (pthread_mutex_lock(&round.mutex) != 0)
            status = 4;
        else if (pthread_mutex_unlock(&round.mutex) != 0)
            status = 5;
    }
    if (status == 0 &&
        pthread_create(&threads[0], 0, ping_pong_worker_main, &workers[0]) != 0)
        status = 6;

    if (status != 0) {
        if (pthread_mutex_lock(&round.mutex) == 0) {
            round.stopped = 1;
            (void)pthread_cond_broadcast(&round.condition);
            (void)pthread_mutex_unlock(&round.mutex);
        }
        if (status == 6)
            (void)pthread_join(threads[1], 0);
        if (pthread_cond_destroy(&round.condition) != 0 && status == 0)
            status = 7;
        if (pthread_mutex_destroy(&round.mutex) != 0 && status == 0)
            status = 8;
        return status;
    }

    if (pthread_join(threads[0], &results[0]) != 0)
        status = 9;
    if (pthread_join(threads[1], &results[1]) != 0 && status == 0)
        status = 10;
    if (status == 0 &&
        (results[0] != (void *)workers[0].marker ||
         results[1] != (void *)workers[1].marker))
        status = 11;
    if (status == 0 &&
        (workers[0].status != 0 || workers[1].status != 0 ||
         workers[0].final_errno != EACCES ||
         workers[1].final_errno != EACCES))
        status = 12;
    if (status == 0 &&
        (round.stopped != 0 || round.remaining != 0 || round.turn != 0 ||
         round.actions[0] != PING_PONG_HANDOFFS / 2 ||
         round.actions[1] != PING_PONG_HANDOFFS / 2 ||
         __atomic_load_n(&round.wait_entries[1], __ATOMIC_ACQUIRE) == 0))
        status = 13;
    if (pthread_cond_destroy(&round.condition) != 0 && status == 0)
        status = 14;
    if (pthread_mutex_destroy(&round.mutex) != 0 && status == 0)
        status = 15;
    if (errno != E2BIG && status == 0)
        status = 16;
    return status;
}

int crabc_x86_64_pthread_cond_private_probe(void)
{
    int round_index;
    int status;

    status = run_static_initializer_round();
    if (status != 0)
        return status;
    if (REPORT_PHASE("cond-static-initializer: pass\n") != 0)
        return 230;
    status = run_initialized_waiter_round(1, 0);
    if (status != 0)
        return 32 + status;
    if (REPORT_PHASE("cond-one-waiter-signal: pass\n") != 0)
        return 231;
    status = run_initialized_waiter_round(BROADCAST_WAITER_COUNT, 1);
    if (status != 0)
        return 64 + status;
    if (REPORT_PHASE("cond-two-waiter-broadcast: pass\n") != 0)
        return 232;
    status = run_no_waiter_signal_round();
    if (status != 0)
        return 96 + status;
    if (REPORT_PHASE("cond-no-waiter-signal: pass\n") != 0)
        return 233;
    status = run_reuse_round();
    if (status != 0)
        return 208 + status;
    if (REPORT_PHASE("cond-reused-signal-broadcast-8: pass\n") != 0)
        return 234;
    status = run_canceled_middle_round();
    if (status != 0)
        return 160 + status;
    if (REPORT_PHASE("cond-canceled-middle-survivors-and-reuse: pass\n") != 0)
        return 236;
#if defined(CRABC_PTHREAD_COND_PRIVATE_FREESTANDING)
    status = run_candidate_only_attribute_rejection();
    if (status != 0)
        return 112 + status;
#endif
    for (round_index = 0; round_index != PING_PONG_ROUNDS; ++round_index) {
        status = run_ping_pong_round();
        if (status != 0)
            return 128 + (round_index * 20) + status;
    }
    if (REPORT_PHASE("cond-ping-pong-4x64: pass\n") != 0)
        return 235;
    return 0;
}

#ifndef CRABC_PTHREAD_COND_PRIVATE_FREESTANDING
int main(void)
{
    return crabc_x86_64_pthread_cond_private_probe();
}
#endif
