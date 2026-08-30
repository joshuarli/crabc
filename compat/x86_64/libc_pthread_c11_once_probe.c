/* Static crabc-libc x86-64 pthread/C11 once fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * against a `-nostdlib -static` executable linked only through the selected
 * crabc archive. It specifies the normal non-cancellation pthread_once and
 * C11 call_once paths: zero/static initialization, exactly one initializer,
 * contended wait/wake, completed acquire visibility of a relaxed application
 * payload, and errno preservation.
 * It is not a claim for cancellation reset, initializer pthread_exit/thrd_exit,
 * same-control recursion, fork/atfork, TSS, dynamic TLS, general pthread/C11
 * synchronization, CRT, loader, sysroot, family completion, or public x86
 * support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <threads.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

_Static_assert(sizeof(pthread_once_t) == 4 && _Alignof(pthread_once_t) == 4,
    "musl x86-64 pthread_once_t ABI");
_Static_assert(sizeof(once_flag) == 4 && _Alignof(once_flag) == 4,
    "musl x86-64 once_flag ABI");
_Static_assert(CRABC_TYPE_IS(pthread_once_t, once_flag),
    "musl C once_flag has pthread_once_t identity");
_Static_assert(PTHREAD_ONCE_INIT == 0 && ONCE_FLAG_INIT == 0,
    "musl pthread/C11 once initializers are zero");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_once),
    int (*)(pthread_once_t *, void (*)(void))), "pthread_once declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&call_once),
    void (*)(once_flag *, void (*)(void))), "call_once declaration");

enum {
    CONTENDING_WORKER_COUNT = 2,
    ONCE_INITIAL = 0,
    ONCE_COMPLETE = 2,
    ONCE_WAITERS = 3,
    PTHREAD_EFFECT = 0x10203040,
    C11_EFFECT = -0x1020304,
};

/* The gate does not implement once. It simply keeps the first initializer
 * inside its callback while the parent starts two contenders. `entered`,
 * `release_initializer`, `callers`, and `initializer_status` use explicit
 * atomics only as fixture observation/admission gates. The callback payload
 * and count use only relaxed atomics: each worker reads them only after its
 * once call returns, so they cannot supply a release/acquire edge that masks
 * the selected once publication.
 */
struct once_round {
    pthread_mutex_t gate_mutex;
    pthread_cond_t gate_condition;
    volatile int initializer_entered;
    volatile int release_initializer;
    volatile int callers;
    volatile int initializer_status;
    volatile int initializer_calls;
    volatile int initializer_effect;
};

struct pthread_once_worker {
    struct once_round *round;
    pthread_once_t *control;
    int counts_as_contender;
    int result;
    int observed_effect;
    int final_errno;
};

struct c11_once_worker {
    struct once_round *round;
    once_flag *control;
    int counts_as_contender;
    int observed_effect;
    int final_errno;
    int marker;
};

static struct once_round *active_round;
static pthread_once_t static_pthread_once = PTHREAD_ONCE_INIT;
static once_flag static_c11_once = ONCE_FLAG_INIT;
static volatile int static_pthread_calls;
static volatile int static_c11_calls;
static volatile int static_pthread_effect;
static volatile int static_c11_effect;

static void static_pthread_initializer(void)
{
    __atomic_fetch_add(&static_pthread_calls, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&static_pthread_effect, PTHREAD_EFFECT, __ATOMIC_RELAXED);
}

static void static_c11_initializer(void)
{
    __atomic_fetch_add(&static_c11_calls, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&static_c11_effect, C11_EFFECT, __ATOMIC_RELAXED);
}

static void block_active_initializer(int effect)
{
    struct once_round *round = active_round;

    if (round == 0)
        return;
    if (pthread_mutex_lock(&round->gate_mutex) != 0) {
        __atomic_store_n(&round->initializer_status, 1, __ATOMIC_RELEASE);
        return;
    }
    __atomic_store_n(&round->initializer_entered, 1, __ATOMIC_RELEASE);
    if (pthread_cond_signal(&round->gate_condition) != 0)
        __atomic_store_n(&round->initializer_status, 2, __ATOMIC_RELEASE);
    while (__atomic_load_n(&round->release_initializer, __ATOMIC_ACQUIRE) == 0) {
        if (pthread_cond_wait(&round->gate_condition, &round->gate_mutex) != 0) {
            __atomic_store_n(&round->initializer_status, 3, __ATOMIC_RELEASE);
            break;
        }
    }
    if (__atomic_load_n(&round->initializer_status, __ATOMIC_ACQUIRE) == 0) {
        __atomic_fetch_add(&round->initializer_calls, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&round->initializer_effect, effect, __ATOMIC_RELAXED);
    }
    if (pthread_mutex_unlock(&round->gate_mutex) != 0)
        __atomic_store_n(&round->initializer_status, 4, __ATOMIC_RELEASE);
}

static void blocking_pthread_initializer(void)
{
    block_active_initializer(PTHREAD_EFFECT);
}

static void blocking_c11_initializer(void)
{
    block_active_initializer(C11_EFFECT);
}

static void *pthread_once_worker_main_selected(void *opaque)
{
    struct pthread_once_worker *worker = opaque;

    errno = EACCES;
    if (worker->counts_as_contender)
        __atomic_fetch_add(&worker->round->callers, 1, __ATOMIC_RELEASE);
    worker->result = pthread_once(worker->control,
        blocking_pthread_initializer);
    worker->observed_effect = __atomic_load_n(&worker->round->initializer_effect,
        __ATOMIC_RELAXED);
    worker->final_errno = errno;
    return worker;
}

static int c11_once_worker_main(void *opaque)
{
    struct c11_once_worker *worker = opaque;

    errno = EACCES;
    if (worker->counts_as_contender)
        __atomic_fetch_add(&worker->round->callers, 1, __ATOMIC_RELEASE);
    call_once(worker->control, blocking_c11_initializer);
    worker->observed_effect = __atomic_load_n(&worker->round->initializer_effect,
        __ATOMIC_RELAXED);
    worker->final_errno = errno;
    return worker->marker;
}

static int initialize_round(struct once_round *round)
{
    if (pthread_mutex_init(&round->gate_mutex, 0) != 0)
        return 1;
    if (pthread_cond_init(&round->gate_condition, 0) != 0) {
        (void)pthread_mutex_destroy(&round->gate_mutex);
        return 2;
    }
    return 0;
}

static void release_round(struct once_round *round)
{
    if (pthread_mutex_lock(&round->gate_mutex) == 0) {
        __atomic_store_n(&round->release_initializer, 1, __ATOMIC_RELEASE);
        (void)pthread_cond_broadcast(&round->gate_condition);
        (void)pthread_mutex_unlock(&round->gate_mutex);
    }
}

static int destroy_round(struct once_round *round)
{
    int status = 0;

    if (pthread_cond_destroy(&round->gate_condition) != 0)
        status = 1;
    if (pthread_mutex_destroy(&round->gate_mutex) != 0 && status == 0)
        status = 2;
    return status;
}

static int run_static_initializer_round(void)
{
    errno = E2BIG;
    if (pthread_once(&static_pthread_once, static_pthread_initializer) != 0)
        return 1;
    if (pthread_once(&static_pthread_once, static_pthread_initializer) != 0)
        return 2;
    if (__atomic_load_n(&static_pthread_calls, __ATOMIC_RELAXED) != 1 ||
        __atomic_load_n(&static_pthread_effect, __ATOMIC_RELAXED) !=
            PTHREAD_EFFECT)
        return 3;
    call_once(&static_c11_once, static_c11_initializer);
    call_once(&static_c11_once, static_c11_initializer);
    if (__atomic_load_n(&static_c11_calls, __ATOMIC_RELAXED) != 1 ||
        __atomic_load_n(&static_c11_effect, __ATOMIC_RELAXED) != C11_EFFECT)
        return 4;
    if (errno != E2BIG)
        return 5;
    return 0;
}

static int wait_for_contended_state(volatile int *callers, const int *control)
{
    while (__atomic_load_n(callers, __ATOMIC_ACQUIRE) != CONTENDING_WORKER_COUNT)
        ;
    while (__atomic_load_n(control, __ATOMIC_ACQUIRE) != ONCE_WAITERS)
        ;
    return 0;
}

static int run_pthread_contention_round(void)
{
    struct once_round round = { 0 };
    pthread_once_t control = PTHREAD_ONCE_INIT;
    struct pthread_once_worker workers[CONTENDING_WORKER_COUNT + 1] = { 0 };
    pthread_t threads[CONTENDING_WORKER_COUNT + 1];
    void *results[CONTENDING_WORKER_COUNT + 1] = { 0 };
    int created = 0;
    int joins_complete = 1;
    int index;
    int status;

    errno = E2BIG;
    if ((status = initialize_round(&round)) != 0)
        return status;
    active_round = &round;
    workers[0].round = &round;
    workers[0].control = &control;
    if (pthread_create(&threads[created], 0, pthread_once_worker_main_selected,
            &workers[0]) != 0) {
        status = 3;
        goto done;
    }
    ++created;
    while (__atomic_load_n(&round.initializer_entered, __ATOMIC_ACQUIRE) == 0)
        ;
    for (index = 1; index <= CONTENDING_WORKER_COUNT; ++index) {
        workers[index].round = &round;
        workers[index].control = &control;
        workers[index].counts_as_contender = 1;
        if (pthread_create(&threads[created], 0, pthread_once_worker_main_selected,
                &workers[index]) != 0) {
            status = 4 + index;
            goto done;
        }
        ++created;
    }
    if (wait_for_contended_state(&round.callers, &control) != 0) {
        status = 7;
        goto done;
    }
    release_round(&round);
done:
    release_round(&round);
    for (index = 0; index != created; ++index) {
        if (pthread_join(threads[index], &results[index]) != 0) {
            if (status == 0)
                status = 8 + index;
            joins_complete = 0;
            break;
        }
    }
    /* A failed join leaves the worker's lifetime unknown. Do not destroy its
     * gate or clear the callback route before the process exits through the
     * freestanding shim. */
    if (!joins_complete)
        return status;
    active_round = 0;
    if (status == 0 &&
        (__atomic_load_n(&round.initializer_status, __ATOMIC_ACQUIRE) != 0 ||
         __atomic_load_n(&round.initializer_calls, __ATOMIC_RELAXED) != 1 ||
         __atomic_load_n(&round.initializer_effect, __ATOMIC_RELAXED) !=
            PTHREAD_EFFECT ||
         __atomic_load_n(&control, __ATOMIC_ACQUIRE) != ONCE_COMPLETE))
        status = 12;
    for (index = 0; index != created && status == 0; ++index) {
        if (results[index] != &workers[index] || workers[index].result != 0 ||
            workers[index].observed_effect != PTHREAD_EFFECT ||
            workers[index].final_errno != EACCES)
            status = 16 + index;
    }
    if (destroy_round(&round) != 0 && status == 0)
        status = 20;
    if (errno != E2BIG && status == 0)
        status = 21;
    return status;
}

static int run_c11_contention_round(void)
{
    struct once_round round = { 0 };
    once_flag control = ONCE_FLAG_INIT;
    struct c11_once_worker workers[CONTENDING_WORKER_COUNT + 1] = {
        { .marker = 0x1234 },
        { .counts_as_contender = 1, .marker = -0x2345 },
        { .counts_as_contender = 1, .marker = 0x3456 },
    };
    thrd_t threads[CONTENDING_WORKER_COUNT + 1];
    int results[CONTENDING_WORKER_COUNT + 1] = { 0 };
    int created = 0;
    int joins_complete = 1;
    int index;
    int status;

    errno = E2BIG;
    if ((status = initialize_round(&round)) != 0)
        return status;
    active_round = &round;
    workers[0].round = &round;
    workers[0].control = &control;
    if (thrd_create(&threads[created], c11_once_worker_main, &workers[0]) !=
        thrd_success) {
        status = 3;
        goto done;
    }
    ++created;
    while (__atomic_load_n(&round.initializer_entered, __ATOMIC_ACQUIRE) == 0)
        ;
    for (index = 1; index <= CONTENDING_WORKER_COUNT; ++index) {
        workers[index].round = &round;
        workers[index].control = &control;
        if (thrd_create(&threads[created], c11_once_worker_main, &workers[index]) !=
            thrd_success) {
            status = 4 + index;
            goto done;
        }
        ++created;
    }
    if (wait_for_contended_state(&round.callers, (const int *)&control) != 0) {
        status = 7;
        goto done;
    }
    release_round(&round);
done:
    release_round(&round);
    for (index = 0; index != created; ++index) {
        if (thrd_join(threads[index], &results[index]) != thrd_success) {
            if (status == 0)
                status = 8 + index;
            joins_complete = 0;
            break;
        }
    }
    /* See the pthread route: a failed join leaves the worker live/unknown,
     * so terminate through the fixture shim without tearing down its gate. */
    if (!joins_complete)
        return status;
    active_round = 0;
    if (status == 0 &&
        (__atomic_load_n(&round.initializer_status, __ATOMIC_ACQUIRE) != 0 ||
         __atomic_load_n(&round.initializer_calls, __ATOMIC_RELAXED) != 1 ||
         __atomic_load_n(&round.initializer_effect, __ATOMIC_RELAXED) !=
            C11_EFFECT ||
         __atomic_load_n((const int *)&control, __ATOMIC_ACQUIRE) !=
            ONCE_COMPLETE))
        status = 12;
    for (index = 0; index != created && status == 0; ++index) {
        if (results[index] != workers[index].marker ||
            workers[index].observed_effect != C11_EFFECT ||
            workers[index].final_errno != EACCES)
            status = 16 + index;
    }
    if (destroy_round(&round) != 0 && status == 0)
        status = 20;
    if (errno != E2BIG && status == 0)
        status = 21;
    return status;
}

static int run_pthread_c11_once(void)
{
    int status;

    if ((status = run_static_initializer_round()) != 0)
        return status;
    if ((status = run_pthread_contention_round()) != 0)
        return 32 + status;
    if ((status = run_c11_contention_round()) != 0)
        return 64 + status;
    return 0;
}

#if defined(CRABC_PTHREAD_C11_ONCE_FREESTANDING)
int crabc_x86_64_pthread_c11_once_probe(void)
{
    return run_pthread_c11_once();
}
#else
int main(void)
{
    return run_pthread_c11_once();
}
#endif
