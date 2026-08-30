/* Static crabc-libc x86-64 C11 plain synchronization fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * against a `-nostdlib -static` executable linked only through the selected
 * crabc archive. It specifies a deliberately narrow C11 synchronization
 * bridge: `mtx_plain` init/destroy/lock/trylock/unlock and private
 * cnd init/destroy/wait/signal/broadcast over the already selected static
 * worker, normal mutex, and private condition seams. It is not a claim for
 * recursive/timed mutexes, timed conditions, static C11 initialization,
 * cancellation, TSS, once, dynamic TLS, a general C11 runtime, CRT, loader,
 * sysroot, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <threads.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

_Static_assert(sizeof(mtx_t) == 40 && _Alignof(mtx_t) == 8,
    "musl x86-64 mtx_t ABI");
_Static_assert(sizeof(cnd_t) == 48 && _Alignof(cnd_t) == 8,
    "musl x86-64 cnd_t ABI");
_Static_assert(!CRABC_TYPE_IS(mtx_t, pthread_mutex_t),
    "C11 mtx_t remains distinct from pthread_mutex_t");
_Static_assert(!CRABC_TYPE_IS(cnd_t, pthread_cond_t),
    "C11 cnd_t remains distinct from pthread_cond_t");
_Static_assert(mtx_plain == 0 && mtx_recursive == 1 && mtx_timed == 2,
    "musl C11 mutex-kind vocabulary");
_Static_assert(thrd_success == 0 && thrd_busy == 1 && thrd_error == 2 &&
    thrd_nomem == 3 && thrd_timedout == 4,
    "musl C11 thread status vocabulary");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_init), int (*)(mtx_t *, int)),
    "mtx_init declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_destroy), void (*)(mtx_t *)),
    "mtx_destroy declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_lock), int (*)(mtx_t *)),
    "mtx_lock declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_trylock), int (*)(mtx_t *)),
    "mtx_trylock declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mtx_unlock), int (*)(mtx_t *)),
    "mtx_unlock declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_init), int (*)(cnd_t *)),
    "cnd_init declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_destroy), void (*)(cnd_t *)),
    "cnd_destroy declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_wait), int (*)(cnd_t *, mtx_t *)),
    "cnd_wait declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_signal), int (*)(cnd_t *)),
    "cnd_signal declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&cnd_broadcast), int (*)(cnd_t *)),
    "cnd_broadcast declaration");

enum {
    BROADCAST_WAITER_COUNT = 2,
    PING_PONG_HANDOFFS = 64,
    PING_PONG_ROUNDS = 4,
};

/* `entered` is only a fixture admission gate. Each worker increments it while
 * holding the same mutex that the parent takes before publishing `release`.
 * That closes the lost-wake window: a successful parent lock proves every
 * counted worker has either entered cnd_wait and released the mutex, or will
 * see the predicate before it waits. */
struct c11_wait_round {
    cnd_t condition;
    mtx_t mutex;
    volatile int entered;
    volatile int release;
    volatile int awakened;
};

struct c11_waiter {
    struct c11_wait_round *round;
    int lock_result;
    int wait_result;
    int unlock_result;
    int observed_release;
    int final_errno;
    int marker;
};

static int c11_waiter_main(void *opaque)
{
    struct c11_waiter *waiter = opaque;
    struct c11_wait_round *round = waiter->round;

    errno = EACCES;
    waiter->lock_result = mtx_lock(&round->mutex);
    waiter->wait_result = thrd_success;
    waiter->unlock_result = thrd_success;
    waiter->observed_release = 0;
    if (waiter->lock_result == thrd_success) {
        __atomic_fetch_add(&round->entered, 1, __ATOMIC_RELEASE);
        while (__atomic_load_n(&round->release, __ATOMIC_ACQUIRE) == 0) {
            waiter->wait_result = cnd_wait(&round->condition, &round->mutex);
            if (waiter->wait_result != thrd_success)
                break;
        }
        if (waiter->wait_result == thrd_success &&
            __atomic_load_n(&round->release, __ATOMIC_ACQUIRE) != 0) {
            waiter->observed_release = 1;
            __atomic_fetch_add(&round->awakened, 1, __ATOMIC_RELEASE);
        }
        waiter->unlock_result = mtx_unlock(&round->mutex);
    }
    waiter->final_errno = errno;
    return waiter->marker;
}

static int run_trylock_round(void)
{
    mtx_t mutex = { 0 };

    errno = E2BIG;
    if (mtx_init(&mutex, mtx_plain) != thrd_success)
        return 1;
    if (mtx_lock(&mutex) != thrd_success)
        return 2;
    if (mtx_trylock(&mutex) != thrd_busy)
        return 3;
    if (mtx_unlock(&mutex) != thrd_success)
        return 4;
    mtx_destroy(&mutex);
    if (errno != E2BIG)
        return 5;
    return 0;
}

static int run_waiter_round(int waiter_count, int use_broadcast)
{
    struct c11_wait_round round = { 0 };
    struct c11_waiter waiters[BROADCAST_WAITER_COUNT] = {
        {
            .round = &round,
            .lock_result = -1,
            .wait_result = -1,
            .unlock_result = -1,
            .observed_release = -1,
            .final_errno = -1,
            .marker = 0x10203040,
        },
        {
            .round = &round,
            .lock_result = -1,
            .wait_result = -1,
            .unlock_result = -1,
            .observed_release = -1,
            .final_errno = -1,
            .marker = -0x1020304,
        },
    };
    thrd_t threads[BROADCAST_WAITER_COUNT];
    int results[BROADCAST_WAITER_COUNT] = { 0, 0 };
    int created = 0;
    int status = 0;
    int index;

    errno = E2BIG;
    if (mtx_init(&round.mutex, mtx_plain) != thrd_success)
        return 1;
    if (cnd_init(&round.condition) != thrd_success) {
        mtx_destroy(&round.mutex);
        return 2;
    }

    for (index = 0; index != waiter_count; ++index) {
        if (thrd_create(&threads[index], c11_waiter_main, &waiters[index]) !=
            thrd_success) {
            status = 3 + index;
            break;
        }
        ++created;
    }

    if (status == 0) {
        while (__atomic_load_n(&round.entered, __ATOMIC_ACQUIRE) != waiter_count)
            ;

        if (mtx_lock(&round.mutex) != thrd_success) {
            status = 5;
        } else {
            int notify_result;

            __atomic_store_n(&round.release, 1, __ATOMIC_RELEASE);
            notify_result = use_broadcast
                ? cnd_broadcast(&round.condition)
                : cnd_signal(&round.condition);
            if (notify_result != thrd_success)
                status = 6;
            if (status != 0)
                (void)cnd_broadcast(&round.condition);
            if (mtx_unlock(&round.mutex) != thrd_success && status == 0)
                status = 7;
        }
    }

    if (status != 0 && created != 0 &&
        __atomic_load_n(&round.release, __ATOMIC_ACQUIRE) == 0 &&
        mtx_lock(&round.mutex) == thrd_success) {
        __atomic_store_n(&round.release, 1, __ATOMIC_RELEASE);
        (void)cnd_broadcast(&round.condition);
        (void)mtx_unlock(&round.mutex);
    }

    for (index = 0; index != created; ++index) {
        if (thrd_join(threads[index], &results[index]) != thrd_success &&
            status == 0)
            status = 8 + index;
    }
    if (status != 0) {
        cnd_destroy(&round.condition);
        mtx_destroy(&round.mutex);
        return status;
    }

    for (index = 0; index != waiter_count; ++index) {
        if (results[index] != waiters[index].marker)
            status = 10 + index;
        if (status == 0 &&
            (waiters[index].lock_result != thrd_success ||
             waiters[index].wait_result != thrd_success ||
             waiters[index].unlock_result != thrd_success ||
             waiters[index].observed_release != 1))
            status = 12 + index;
        if (status == 0 && waiters[index].final_errno != EACCES)
            status = 14 + index;
    }
    if (status == 0 &&
        (__atomic_load_n(&round.entered, __ATOMIC_ACQUIRE) != waiter_count ||
         __atomic_load_n(&round.awakened, __ATOMIC_ACQUIRE) != waiter_count))
        status = 16;
    cnd_destroy(&round.condition);
    mtx_destroy(&round.mutex);
    if (status == 0 && errno != E2BIG)
        status = 17;
    return status;
}

struct c11_ping_pong_round {
    cnd_t condition;
    mtx_t mutex;
    int turn;
    int remaining;
    int stopped;
    int actions[BROADCAST_WAITER_COUNT];
    volatile int wait_entries[BROADCAST_WAITER_COUNT];
};

struct c11_ping_pong_worker {
    struct c11_ping_pong_round *round;
    int index;
    int status;
    int final_errno;
    int marker;
};

static int c11_ping_pong_main(void *opaque)
{
    struct c11_ping_pong_worker *worker = opaque;
    struct c11_ping_pong_round *round = worker->round;

    errno = EACCES;
    worker->status = mtx_lock(&round->mutex);
    while (worker->status == thrd_success && round->remaining != 0) {
        while (round->remaining != 0 && round->turn != worker->index) {
            __atomic_fetch_add(&round->wait_entries[worker->index], 1,
                __ATOMIC_RELEASE);
            worker->status = cnd_wait(&round->condition, &round->mutex);
            if (worker->status != thrd_success)
                break;
        }
        if (worker->status != thrd_success || round->remaining == 0)
            break;
        ++round->actions[worker->index];
        --round->remaining;
        if (round->remaining == 0) {
            round->stopped = 1;
            worker->status = cnd_broadcast(&round->condition);
        } else {
            round->turn = 1 - worker->index;
            worker->status = cnd_signal(&round->condition);
        }
    }
    if (worker->status == thrd_success)
        worker->status = mtx_unlock(&round->mutex);
    worker->final_errno = errno;
    return worker->marker;
}

static int run_ping_pong_round(void)
{
    struct c11_ping_pong_round round = {
        .turn = 0,
        .remaining = PING_PONG_HANDOFFS,
    };
    struct c11_ping_pong_worker workers[BROADCAST_WAITER_COUNT] = {
        { .round = &round, .index = 0, .status = -1, .final_errno = -1,
          .marker = 0x1234 },
        { .round = &round, .index = 1, .status = -1, .final_errno = -1,
          .marker = -0x2345 },
    };
    thrd_t threads[BROADCAST_WAITER_COUNT];
    int results[BROADCAST_WAITER_COUNT] = { 0, 0 };
    int created = 0;
    int status = 0;
    int index;

    errno = E2BIG;
    if (mtx_init(&round.mutex, mtx_plain) != thrd_success)
        return 1;
    if (cnd_init(&round.condition) != thrd_success) {
        mtx_destroy(&round.mutex);
        return 2;
    }
    for (index = 0; index != BROADCAST_WAITER_COUNT; ++index) {
        if (thrd_create(&threads[index], c11_ping_pong_main, &workers[index]) !=
            thrd_success) {
            status = 3 + index;
            break;
        }
        ++created;
    }
    if (status != 0 && mtx_lock(&round.mutex) == thrd_success) {
        round.remaining = 0;
        round.stopped = 1;
        (void)cnd_broadcast(&round.condition);
        (void)mtx_unlock(&round.mutex);
    }
    for (index = 0; index != created; ++index) {
        if (thrd_join(threads[index], &results[index]) != thrd_success &&
            status == 0)
            status = 5 + index;
    }
    if (status == 0 &&
        (results[0] != workers[0].marker || results[1] != workers[1].marker ||
         workers[0].status != thrd_success || workers[1].status != thrd_success ||
         workers[0].final_errno != EACCES || workers[1].final_errno != EACCES))
        status = 7;
    if (status == 0 &&
        (round.stopped != 1 || round.remaining != 0 || round.turn != 1 ||
         round.actions[0] != PING_PONG_HANDOFFS / 2 ||
         round.actions[1] != PING_PONG_HANDOFFS / 2 ||
         __atomic_load_n(&round.wait_entries[1], __ATOMIC_ACQUIRE) == 0))
        status = 8;
    cnd_destroy(&round.condition);
    mtx_destroy(&round.mutex);
    if (status == 0 && errno != E2BIG)
        status = 9;
    return status;
}

/* This is deliberately candidate-only boundary evidence. Pinned musl admits
 * recursive/timed C11 kinds, while the selected x86 bridge refuses any kind
 * other than mtx_plain without initializing or interpreting that object. */
#if defined(CRABC_C11_PLAIN_SYNC_FREESTANDING)
static int run_candidate_only_kind_rejection(void)
{
    mtx_t recursive = { 0 };
    mtx_t timed = { 0 };

    errno = E2BIG;
    if (mtx_init(&recursive, mtx_recursive) != thrd_error)
        return 1;
    if (mtx_init(&timed, mtx_timed) != thrd_error)
        return 2;
    if (errno != E2BIG)
        return 3;
    return 0;
}
#endif

static int run_c11_plain_sync(void)
{
    int status;
    int round;

    if ((status = run_trylock_round()) != 0)
        return status;
    if ((status = run_waiter_round(1, 0)) != 0)
        return 32 + status;
    if ((status = run_waiter_round(BROADCAST_WAITER_COUNT, 1)) != 0)
        return 64 + status;
#if defined(CRABC_C11_PLAIN_SYNC_FREESTANDING)
    if ((status = run_candidate_only_kind_rejection()) != 0)
        return 96 + status;
#endif
    for (round = 0; round != PING_PONG_ROUNDS; ++round) {
        if ((status = run_ping_pong_round()) != 0)
            return 128 + (round * 16) + status;
    }
    return 0;
}

#if defined(CRABC_C11_PLAIN_SYNC_FREESTANDING)
int crabc_x86_64_c11_plain_sync_probe(void)
{
    return run_c11_plain_sync();
}
#else
int main(void)
{
    return run_c11_plain_sync();
}
#endif
