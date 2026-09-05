/* Ordinary installed Linux/x86-64 pthread/C11 lifecycle consumer.
 *
 * This project-header body is intentionally one composition witness rather
 * than another per-entry archive fixture. It first executes with pinned musl
 * 1.2.6, then with the installed owned static ET_EXEC and static-PIE products.
 * It covers the selected worker seam's real pthread_attr_t consumption
 * (private guarded stack, caller stack, and detached-at-create), typed C11
 * result handoff, deferred cancellation cleanup/TSD teardown, and the
 * single-threaded atfork/fork order after every selected worker is gone.
 *
 * It does not claim a general pthread runtime: scheduler attributes,
 * asynchronous or syscall-point cancellation, foreign threads, loader TLS,
 * process-wide fork repair, and dynamic-product behavior remain outside this
 * installed static consumer. The eventual dynamic product reuses this source
 * boundary only after its own TLS/TCB composition is materialized.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this consumer requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <threads.h>
#include <unistd.h>

enum {
    CRABC_WAIT_LIMIT = 100000000u,
    CRABC_PRIVATE_STACK_SIZE = 64 * 1024,
    CRABC_DETACHED_ROUNDS = 65,
    CRABC_CONCURRENT_WORKERS = 96,
    CRABC_PARALLEL_DETACHED_CREATORS = 8,
    CRABC_PARALLEL_DETACHED_ROUNDS = 48,
    CRABC_CANCELED_SENTINEL = 0x56a71c2d,
};

_Static_assert(sizeof(pthread_attr_t) == 56 && _Alignof(pthread_attr_t) == 8,
    "musl x86-64 pthread_attr_t ABI");
_Static_assert(PTHREAD_CREATE_JOINABLE == 0 && PTHREAD_CREATE_DETACHED == 1,
    "pthread detach-state values");
_Static_assert(PTHREAD_CANCEL_ENABLE == 0 && PTHREAD_CANCEL_DISABLE == 1 &&
    PTHREAD_CANCEL_MASKED == 2, "pthread cancellation-state values");
_Static_assert(PTHREAD_CANCELED == (void *)-1,
    "pthread cancellation join result");
_Static_assert(thrd_success == 0 && thrd_error == 2 && thrd_nomem == 3,
    "C11 thread status values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_create),
    int (*)(pthread_t *__restrict, const pthread_attr_t *__restrict,
        void *(*)(void *), void *__restrict)), "pthread_create declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&thrd_create),
    int (*)(thrd_t *, thrd_start_t, void *)), "thrd_create declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_atfork),
    int (*)(void (*)(void), void (*)(void), void (*)(void))),
    "pthread_atfork declaration");

static _Alignas(4096) unsigned char crabc_caller_stack[CRABC_PRIVATE_STACK_SIZE];
static pthread_key_t crabc_teardown_key;
static volatile int crabc_atfork_count;
static volatile int crabc_atfork_order[2];
static int crabc_main_exit_pipe = -1;

static void spin_pause(void)
{
    __asm__ volatile("pause" ::: "memory");
}

static int wait_for_nonzero(const volatile int *value)
{
    unsigned int spin;

    for (spin = 0; spin != CRABC_WAIT_LIMIT; ++spin) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) != 0)
            return 0;
        spin_pause();
    }
    return -1;
}

static int wait_for_at_least(const volatile int *value, int expected)
{
    unsigned int spin;

    for (spin = 0; spin != CRABC_WAIT_LIMIT; ++spin) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) >= expected)
            return 0;
        spin_pause();
    }
    return -1;
}

struct custom_stack_round {
    volatile int failure;
};

static void *custom_stack_worker(void *opaque)
{
    struct custom_stack_round *round = opaque;
    volatile unsigned char local;
    const uintptr_t address = (uintptr_t)&local;
    const uintptr_t lower = (uintptr_t)crabc_caller_stack;
    const uintptr_t upper = lower + sizeof(crabc_caller_stack);

    if (address <= lower || address > upper)
        __atomic_store_n(&round->failure, 1, __ATOMIC_RELEASE);
    return opaque;
}

struct cancellation_round {
    volatile int ready;
    volatile int cleanup_seen;
    volatile int destructor_seen;
    volatile int failure;
};

static void cancellation_cleanup(void *opaque)
{
    struct cancellation_round *round = opaque;

    if (errno != EACCES)
        __atomic_store_n(&round->failure, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&round->cleanup_seen, 1, __ATOMIC_RELEASE);
}

static void cancellation_destructor(void *opaque)
{
    struct cancellation_round *round = opaque;

    /* Musl clears the selected value before it calls its destructor. */
    if (pthread_getspecific(crabc_teardown_key) != 0 || errno != EACCES)
        __atomic_store_n(&round->failure, 2, __ATOMIC_RELEASE);
    __atomic_store_n(&round->destructor_seen, 1, __ATOMIC_RELEASE);
}

static void *cancellation_worker(void *opaque)
{
    struct cancellation_round *round = opaque;

    errno = EACCES;
    if (pthread_setspecific(crabc_teardown_key, round) != 0) {
        __atomic_store_n(&round->failure, 3, __ATOMIC_RELEASE);
        return 0;
    }
    pthread_cleanup_push(cancellation_cleanup, round);
    __atomic_store_n(&round->ready, 1, __ATOMIC_RELEASE);
    for (;;) {
        pthread_testcancel();
        spin_pause();
    }
    pthread_cleanup_pop(0);
    return 0;
}

struct detached_round {
    volatile int done;
};

static void *detached_worker(void *opaque)
{
    struct detached_round *round = opaque;

    __atomic_store_n(&round->done, 1, __ATOMIC_RELEASE);
    return 0;
}

struct concurrent_round {
    volatile int ready;
    volatile int release;
};

static void *concurrent_worker(void *opaque)
{
    struct concurrent_round *round = opaque;

    __atomic_store_n(&round->ready, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&round->release, __ATOMIC_ACQUIRE) == 0)
        spin_pause();
    return opaque;
}

static int run_concurrent_lifecycle_capacity(void)
{
    pthread_attr_t attributes;
    pthread_t threads[CRABC_CONCURRENT_WORKERS];
    struct concurrent_round rounds[CRABC_CONCURRENT_WORKERS];
    unsigned int index;

    if (pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setstacksize(&attributes, 8 * PTHREAD_STACK_MIN) != 0)
        return 1;
    for (index = 0; index != CRABC_CONCURRENT_WORKERS; ++index) {
        rounds[index].ready = 0;
        rounds[index].release = 0;
        if (pthread_create(&threads[index], &attributes, concurrent_worker,
                &rounds[index]) != 0) {
            while (index != 0) {
                --index;
                __atomic_store_n(&rounds[index].release, 1, __ATOMIC_RELEASE);
                (void)pthread_join(threads[index], 0);
            }
            (void)pthread_attr_destroy(&attributes);
            return 2;
        }
    }
    for (index = 0; index != CRABC_CONCURRENT_WORKERS; ++index) {
        if (wait_for_nonzero(&rounds[index].ready) != 0) {
            unsigned int release_index;

            for (release_index = 0;
                    release_index != CRABC_CONCURRENT_WORKERS;
                    ++release_index)
                __atomic_store_n(&rounds[release_index].release, 1,
                    __ATOMIC_RELEASE);
            for (index = 0; index != CRABC_CONCURRENT_WORKERS; ++index)
                (void)pthread_join(threads[index], 0);
            (void)pthread_attr_destroy(&attributes);
            return 3;
        }
    }
    for (index = 0; index != CRABC_CONCURRENT_WORKERS; ++index)
        __atomic_store_n(&rounds[index].release, 1, __ATOMIC_RELEASE);
    for (index = 0; index != CRABC_CONCURRENT_WORKERS; ++index) {
        void *result = 0;

        if (pthread_join(threads[index], &result) != 0 || result != &rounds[index]) {
            (void)pthread_attr_destroy(&attributes);
            return 4;
        }
    }
    return pthread_attr_destroy(&attributes) == 0 ? 0 : 5;
}

struct parallel_detached_creators {
    const pthread_attr_t *detached_attributes;
    volatile int ready;
    volatile int release;
    volatile int failure;
};

static void *fast_detached_worker(void *opaque)
{
    (void)opaque;
    return 0;
}

static void *parallel_detached_creator(void *opaque)
{
    struct parallel_detached_creators *round = opaque;
    unsigned int index;

    __atomic_fetch_add(&round->ready, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&round->release, __ATOMIC_ACQUIRE) == 0)
        spin_pause();
    for (index = 0; index != CRABC_PARALLEL_DETACHED_ROUNDS; ++index) {
        pthread_t child;

        if (pthread_create(&child, round->detached_attributes,
                fast_detached_worker, 0) != 0) {
            __atomic_store_n(&round->failure, 1, __ATOMIC_RELEASE);
            return 0;
        }
    }
    return 0;
}

/*
 * Drive a detached reaper concurrently with creators. In particular, a fast
 * detached child may reach clear-child-tid before its creating parent has
 * returned from pthread_create, while a different creator begins the next
 * reaper pass. The ownership boundary must not treat a merely linked
 * pre-clone/incomplete-handoff control (whose child-TID is still zero) as an
 * exited child and unmap it.
 */
static int run_parallel_detached_creator_handoff(void)
{
    pthread_attr_t detached_attributes;
    pthread_attr_t creator_attributes;
    pthread_t creators[CRABC_PARALLEL_DETACHED_CREATORS];
    struct parallel_detached_creators round = {
        .detached_attributes = &detached_attributes,
        .ready = 0,
        .release = 0,
        .failure = 0,
    };
    pthread_t final_reaper;
    unsigned int index;

    if (pthread_attr_init(&detached_attributes) != 0 ||
        pthread_attr_setdetachstate(&detached_attributes,
            PTHREAD_CREATE_DETACHED) != 0 ||
        pthread_attr_setstacksize(&detached_attributes,
            8 * PTHREAD_STACK_MIN) != 0 ||
        pthread_attr_init(&creator_attributes) != 0 ||
        pthread_attr_setstacksize(&creator_attributes,
            8 * PTHREAD_STACK_MIN) != 0)
        return 1;
    for (index = 0; index != CRABC_PARALLEL_DETACHED_CREATORS; ++index) {
        if (pthread_create(&creators[index], &creator_attributes,
                parallel_detached_creator, &round) != 0) {
            while (index != 0) {
                --index;
                __atomic_store_n(&round.release, 1, __ATOMIC_RELEASE);
                (void)pthread_join(creators[index], 0);
            }
            (void)pthread_attr_destroy(&creator_attributes);
            (void)pthread_attr_destroy(&detached_attributes);
            return 2;
        }
    }
    if (wait_for_at_least(&round.ready, CRABC_PARALLEL_DETACHED_CREATORS) != 0) {
        __atomic_store_n(&round.release, 1, __ATOMIC_RELEASE);
        for (index = 0; index != CRABC_PARALLEL_DETACHED_CREATORS; ++index)
            (void)pthread_join(creators[index], 0);
        (void)pthread_attr_destroy(&creator_attributes);
        (void)pthread_attr_destroy(&detached_attributes);
        return 3;
    }
    __atomic_store_n(&round.release, 1, __ATOMIC_RELEASE);
    for (index = 0; index != CRABC_PARALLEL_DETACHED_CREATORS; ++index) {
        if (pthread_join(creators[index], 0) != 0)
            return 4;
    }
    if (__atomic_load_n(&round.failure, __ATOMIC_ACQUIRE) != 0 ||
        pthread_create(&final_reaper, 0, fast_detached_worker, 0) != 0 ||
        pthread_join(final_reaper, 0) != 0)
        return 5;
    if (pthread_attr_destroy(&creator_attributes) != 0 ||
        pthread_attr_destroy(&detached_attributes) != 0)
        return 6;
    return 0;
}

static int c11_worker(void *opaque)
{
    const int value = *(const int *)opaque;

    return value;
}

static void atfork_prepare(void)
{
    crabc_atfork_order[crabc_atfork_count++] = 1;
}

static void atfork_parent(void)
{
    crabc_atfork_order[crabc_atfork_count++] = 2;
}

static void atfork_child(void)
{
    crabc_atfork_order[crabc_atfork_count++] = 3;
}

static int run_attr_and_cancellation(void)
{
    pthread_attr_t attributes;
    pthread_t thread;
    void *result = 0;
    const struct sched_param inherited_scheduler = { .sched_priority = 17 };
    struct custom_stack_round custom = { .failure = 0 };
    struct cancellation_round cancellation = {
        .ready = 0,
        .cleanup_seen = 0,
        .destructor_seen = 0,
        .failure = 0,
    };

    if (pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setstack(&attributes, crabc_caller_stack,
            sizeof(crabc_caller_stack)) != 0 ||
        pthread_attr_setguardsize(&attributes, 4096) != 0 ||
        /* Pinned musl preserves policy/priority record metadata but applies
         * scheduling only when PTHREAD_EXPLICIT_SCHED is requested. */
        pthread_attr_setschedpolicy(&attributes, SCHED_FIFO) != 0 ||
        pthread_attr_setschedparam(&attributes, &inherited_scheduler) != 0 ||
        pthread_create(&thread, &attributes, custom_stack_worker, &custom) != 0 ||
        pthread_join(thread, &result) != 0 || result != &custom ||
        __atomic_load_n(&custom.failure, __ATOMIC_ACQUIRE) != 0 ||
        pthread_attr_destroy(&attributes) != 0)
        return 1;

    if (pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setstacksize(&attributes, 8 * PTHREAD_STACK_MIN) != 0 ||
        pthread_attr_setguardsize(&attributes, 4096) != 0 ||
        pthread_key_create(&crabc_teardown_key, cancellation_destructor) != 0 ||
        pthread_create(&thread, &attributes, cancellation_worker, &cancellation) != 0 ||
        wait_for_nonzero(&cancellation.ready) != 0 ||
        pthread_cancel(thread) != 0 ||
        pthread_join(thread, &result) != 0 || result != PTHREAD_CANCELED ||
        __atomic_load_n(&cancellation.cleanup_seen, __ATOMIC_ACQUIRE) != 1 ||
        __atomic_load_n(&cancellation.destructor_seen, __ATOMIC_ACQUIRE) != 1 ||
        __atomic_load_n(&cancellation.failure, __ATOMIC_ACQUIRE) != 0 ||
        pthread_key_delete(crabc_teardown_key) != 0 ||
        pthread_attr_destroy(&attributes) != 0)
        return 2;
    return 0;
}

static int run_detached_attr_and_c11_reaper(void)
{
    pthread_attr_t attributes;
    struct detached_round rounds[CRABC_DETACHED_ROUNDS];
    pthread_t thread;
    thrd_t c11_thread;
    int c11_input = -217;
    int c11_result = 0;
    unsigned int index;

    if (pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) != 0 ||
        pthread_attr_setstacksize(&attributes, 8 * PTHREAD_STACK_MIN) != 0)
        return 1;
    for (index = 0; index != CRABC_DETACHED_ROUNDS; ++index) {
        __atomic_store_n(&rounds[index].done, 0, __ATOMIC_RELAXED);
        if (pthread_create(&thread, &attributes, detached_worker, &rounds[index]) != 0 ||
            wait_for_nonzero(&rounds[index].done) != 0)
            return 2;
        /* The next selected creation reaps this exited detached worker. */
    }
    if (pthread_attr_destroy(&attributes) != 0 ||
        thrd_create(&c11_thread, c11_worker, &c11_input) != thrd_success ||
        thrd_join(c11_thread, &c11_result) != thrd_success ||
        c11_result != c11_input)
        return 3;
    return 0;
}

static void main_pthread_exit_atexit(void)
{
    static const unsigned char marker = 'E';

    if (crabc_main_exit_pipe < 0 ||
        write(crabc_main_exit_pipe, &marker, sizeof(marker)) != sizeof(marker))
        _Exit(97);
}

/*
 * pthread_exit on the bootstrapped thread must use ordinary exit when it is
 * already the last task: its registered atexit callback runs before
 * exit_group. A raw SYS_exit would close this pipe without the marker.
 */
static int run_main_thread_pthread_exit(void)
{
    int pipefd[2];
    pid_t child;
    int status;
    unsigned char marker = 0;

    if (pipe(pipefd) != 0)
        return 1;
    child = fork();
    if (child == 0) {
        (void)close(pipefd[0]);
        crabc_main_exit_pipe = pipefd[1];
        if (atexit(main_pthread_exit_atexit) != 0)
            _Exit(96);
        pthread_exit(0);
        _Exit(95);
    }
    (void)close(pipefd[1]);
    if (child < 0 || read(pipefd[0], &marker, sizeof(marker)) != sizeof(marker) ||
        marker != 'E' || close(pipefd[0]) != 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 2;
    return 0;
}

struct live_fork_round {
    volatile int ready;
    volatile int release;
};

static void *live_fork_worker(void *opaque)
{
    struct live_fork_round *round = opaque;

    __atomic_store_n(&round->ready, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&round->release, __ATOMIC_ACQUIRE) == 0)
        spin_pause();
    return 0;
}

/*
 * A selected worker remains live across this main-thread fork. The child must
 * drop inherited worker handles, refresh the copied static TLS main identity,
 * and still admit selected main TSD key operations under its new Linux TID.
 */
static int run_fork_with_live_selected_worker(void)
{
    pthread_attr_t attributes;
    struct live_fork_round round = { .ready = 0, .release = 0 };
    pthread_t worker;
    pid_t child;
    int status;

    if (pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setstacksize(&attributes, 8 * PTHREAD_STACK_MIN) != 0 ||
        pthread_create(&worker, &attributes, live_fork_worker, &round) != 0 ||
        wait_for_nonzero(&round.ready) != 0)
        return 1;
    child = fork();
    if (child == 0) {
        pthread_key_t key;

        if (pthread_key_create(&key, 0) != 0 ||
            pthread_setspecific(key, &round) != 0 ||
            pthread_getspecific(key) != &round || pthread_key_delete(key) != 0)
            _Exit(94);
        _Exit(0);
    }
    __atomic_store_n(&round.release, 1, __ATOMIC_RELEASE);
    if (child < 0 || pthread_join(worker, 0) != 0 ||
        pthread_attr_destroy(&attributes) != 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 2;
    return 0;
}

static int run_atfork_after_worker_teardown(void)
{
    pid_t child;
    int status;

    crabc_atfork_count = 0;
    crabc_atfork_order[0] = 0;
    crabc_atfork_order[1] = 0;
    if (pthread_atfork(atfork_prepare, atfork_parent, atfork_child) != 0)
        return 1;
    child = fork();
    if (child == 0) {
        if (crabc_atfork_count != 2 || crabc_atfork_order[0] != 1 ||
            crabc_atfork_order[1] != 3)
            _Exit(91);
        _Exit(0);
    }
    if (child < 0 || crabc_atfork_count != 2 || crabc_atfork_order[0] != 1 ||
        crabc_atfork_order[1] != 2 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 2;
    return 0;
}

int main(void)
{
    const int capacity = run_concurrent_lifecycle_capacity();
    const int detached_handoff = run_parallel_detached_creator_handoff();
    const int attrs = run_attr_and_cancellation();
    const int detached = run_detached_attr_and_c11_reaper();
    const int main_exit = run_main_thread_pthread_exit();
    const int live_fork = run_fork_with_live_selected_worker();
    const int atfork = run_atfork_after_worker_teardown();

    if (capacity != 0)
        return 5 + capacity;
    if (detached_handoff != 0)
        return 10 + detached_handoff;
    if (attrs != 0)
        return 20 + attrs;
    if (detached != 0)
        return 30 + detached;
    if (main_exit != 0)
        return 40 + main_exit;
    if (live_fork != 0)
        return 50 + live_fork;
    if (atfork != 0)
        return 60 + atfork;
    return 0;
}
