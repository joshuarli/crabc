/*
 * Linux/x86-64 bounded static pthread/C11 detach fixture.
 *
 * The runner compiles this exact project-header body first against pinned musl
 * and then as a `-nostdlib -static` crabc archive candidate.  The comparable
 * routes are deliberately small: detach a held pthread or C11 worker before
 * or after it is released, for normal return and the selected explicit-exit
 * forms, and preserve the parent's errno.  A successful detach transfers
 * lifecycle ownership; comparable routes never reuse an opaque handle after
 * terminal join or detached completion. Candidate-only error-path diagnostics
 * make their one intentionally documented pre-completion handle query while
 * the detached worker remains held live.
 *
 * The candidate additionally selects prompt state-only detach followed by
 * lazy reaping at a later selected lifecycle entry, after the kernel has
 * applied CLONE_CHILD_CLEARTID.  The fixed 64-worker route makes that boundary
 * observable without promoting a general pthread/C11 implementation.
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
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_detach),
    int (*)(pthread_t)), "pthread_detach declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&thrd_detach),
    int (*)(thrd_t)), "thrd_detach declaration");

enum { parent_errno_sentinel = E2BIG };

struct held_worker {
    volatile int entered;
    volatile int release;
    volatile int completed;
    int initial_errno;
    int self_detach_result;
};

static int wait_until_set(volatile int *value)
{
    unsigned long spins;

    for (spins = 0; spins != 100000000UL; ++spins) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) != 0)
            return 0;
        __asm__ volatile("pause" ::: "memory");
    }
    return 1;
}

static void wait_for_release(struct held_worker *worker)
{
    __atomic_store_n(&worker->entered, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&worker->release, __ATOMIC_ACQUIRE) == 0)
        __asm__ volatile("pause" ::: "memory");
    __atomic_store_n(&worker->completed, 1, __ATOMIC_RELEASE);
}

static void *pthread_normal_worker(void *opaque)
{
    struct held_worker *worker = opaque;

    worker->initial_errno = errno;
    wait_for_release(worker);
    return opaque;
}

static void *pthread_explicit_exit_worker(void *opaque)
{
    struct held_worker *worker = opaque;

    worker->initial_errno = errno;
    wait_for_release(worker);
    pthread_exit(opaque);
}

static int thrd_normal_worker(void *opaque)
{
    struct held_worker *worker = opaque;

    worker->initial_errno = errno;
    wait_for_release(worker);
    return 17;
}

static int thrd_explicit_exit_worker(void *opaque)
{
    struct held_worker *worker = opaque;

    worker->initial_errno = errno;
    wait_for_release(worker);
    thrd_exit(-17);
}

static int run_pthread_round(void *(*start)(void *), int release_before_detach)
{
    struct held_worker worker = {0, 0, 0, -1};
    pthread_t thread = 0;
    int detach_result;

    errno = parent_errno_sentinel;
    if (pthread_create(&thread, 0, start, &worker) != 0)
        return 1;
    if (wait_until_set(&worker.entered))
        return 2;
    if (release_before_detach) {
        __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
        if (wait_until_set(&worker.completed))
            return 3;
    }
    detach_result = pthread_detach(thread);
    if (detach_result != 0)
        return 4;
    if (errno != parent_errno_sentinel || worker.initial_errno != 0)
        return 5;
    if (!release_before_detach) {
        __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
        if (wait_until_set(&worker.completed))
            return 6;
    }
    return 0;
}

static int run_thrd_round(int (*start)(void *), int release_before_detach)
{
    struct held_worker worker = {0, 0, 0, -1};
    thrd_t thread = 0;
    int detach_result;

    errno = parent_errno_sentinel;
    if (thrd_create(&thread, start, &worker) != thrd_success)
        return 20;
    if (wait_until_set(&worker.entered))
        return 21;
    if (release_before_detach) {
        __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
        if (wait_until_set(&worker.completed))
            return 22;
    }
    detach_result = thrd_detach(thread);
    if (detach_result != thrd_success)
        return 23;
    if (errno != parent_errno_sentinel || worker.initial_errno != 0)
        return 24;
    if (!release_before_detach) {
        __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
        if (wait_until_set(&worker.completed))
            return 25;
    }
    return 0;
}

static int run_double_detach_round(void)
{
    struct held_worker worker = {0, 0, 0, -1};
    pthread_t thread = 0;

    errno = parent_errno_sentinel;
    if (pthread_create(&thread, 0, pthread_normal_worker, &worker) != 0)
        return 40;
    if (wait_until_set(&worker.entered))
        return 41;
    if (pthread_detach(thread) != 0)
        return 42;
    if (pthread_detach(thread) == 0)
        return 43;
    if (errno != parent_errno_sentinel)
        return 44;
    __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
    if (wait_until_set(&worker.completed))
        return 45;
    return 0;
}

static int run_thrd_double_detach_round(void)
{
    struct held_worker worker = {0, 0, 0, -1};
    thrd_t thread = 0;

    errno = parent_errno_sentinel;
    if (thrd_create(&thread, thrd_normal_worker, &worker) != thrd_success)
        return 46;
    if (wait_until_set(&worker.entered))
        return 47;
    if (thrd_detach(thread) != thrd_success)
        return 48;
    if (thrd_detach(thread) != thrd_error)
        return 49;
    if (errno != parent_errno_sentinel)
        return 50;
    __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
    if (wait_until_set(&worker.completed))
        return 51;
    return 0;
}

#if defined(CRABC_PTHREAD_DETACH_FREESTANDING)
/* Self-detach is candidate-only because the selected crabc completion/reap
 * boundary, rather than a general POSIX self-detach contract, is the point
 * under test.  The parent releases and observes completion without joining or
 * otherwise reusing the returned opaque handle. */
static void *self_detach_worker(void *opaque)
{
    struct held_worker *worker = opaque;

    worker->initial_errno = errno;
    worker->self_detach_result = pthread_detach(pthread_self());
    wait_for_release(worker);
    return 0;
}

static int run_candidate_self_detach_completion_round(void)
{
    struct held_worker worker = {0, 0, 0, -1};
    pthread_t thread = 0;

    errno = parent_errno_sentinel;
    if (pthread_create(&thread, 0, self_detach_worker, &worker) != 0)
        return 50;
    if (wait_until_set(&worker.entered))
        return 51;
    if (worker.initial_errno != 0 || worker.self_detach_result != 0 ||
        errno != parent_errno_sentinel)
        return 52;
    __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
    if (wait_until_set(&worker.completed) || errno != parent_errno_sentinel)
        return 53;
    return 0;
}

static int run_candidate_null_detach_rejection_round(void)
{
    errno = parent_errno_sentinel;
    if (pthread_detach(0) != EINVAL || thrd_detach(0) != thrd_error ||
        errno != parent_errno_sentinel)
        return 80;
    return 0;
}

struct detach_race {
    struct held_worker target;
    pthread_t target_thread;
    volatile int go;
    volatile int first_ready;
    volatile int second_ready;
    volatile int first_result;
    volatile int second_result;
};

struct detach_racer {
    struct detach_race *race;
    volatile int *ready;
    volatile int *result;
};

/* These concurrent ownership routes are candidate-only registry diagnostics,
 * not an admitted pthread/C11 contract.  They verify that the bounded private
 * state machine chooses one owner rather than retaining a stale raw control
 * pointer while a later lifecycle boundary can reclaim mappings. */
static void *detach_racer_worker(void *opaque)
{
    struct detach_racer *racer = opaque;
    int result;

    __atomic_store_n(racer->ready, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&racer->race->go, __ATOMIC_ACQUIRE) == 0)
        __asm__ volatile("pause" ::: "memory");
    result = pthread_detach(racer->race->target_thread);
    __atomic_store_n(racer->result, result, __ATOMIC_RELEASE);
    return 0;
}

static int run_candidate_detach_race_round(void)
{
    struct detach_race race = {{0, 0, 0, -1}, 0, 0, 0, 0, -1, -1};
    struct detach_racer first = {&race, &race.first_ready, &race.first_result};
    struct detach_racer second = {&race, &race.second_ready, &race.second_result};
    pthread_t first_thread = 0;
    pthread_t second_thread = 0;
    int first_result;
    int second_result;

    errno = parent_errno_sentinel;
    if (pthread_create(&race.target_thread, 0, pthread_normal_worker,
            &race.target) != 0 || wait_until_set(&race.target.entered))
        return 81;
    if (pthread_create(&first_thread, 0, detach_racer_worker, &first) != 0 ||
        pthread_create(&second_thread, 0, detach_racer_worker, &second) != 0 ||
        wait_until_set(&race.first_ready) || wait_until_set(&race.second_ready))
        return 82;
    __atomic_store_n(&race.go, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&race.target.release, 1, __ATOMIC_RELEASE);
    if (pthread_join(first_thread, 0) != 0 || pthread_join(second_thread, 0) != 0)
        return 83;
    first_result = __atomic_load_n(&race.first_result, __ATOMIC_ACQUIRE);
    second_result = __atomic_load_n(&race.second_result, __ATOMIC_ACQUIRE);
    if ((first_result == 0) + (second_result == 0) != 1 ||
        (first_result != 0 && first_result != EINVAL) ||
        (second_result != 0 && second_result != EINVAL) ||
        errno != parent_errno_sentinel)
        return 84;
    if (wait_until_set(&race.target.completed))
        return 85;
    return 0;
}

struct join_detach_race {
    struct held_worker target;
    pthread_t target_thread;
    volatile int go;
    volatile int join_ready;
    volatile int detach_ready;
    volatile int join_result;
    volatile int detach_result;
};

static void *join_racer_worker(void *opaque)
{
    struct join_detach_race *race = opaque;
    int result;

    __atomic_store_n(&race->join_ready, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&race->go, __ATOMIC_ACQUIRE) == 0)
        __asm__ volatile("pause" ::: "memory");
    result = pthread_join(race->target_thread, 0);
    __atomic_store_n(&race->join_result, result, __ATOMIC_RELEASE);
    return 0;
}

static void *join_detach_racer_worker(void *opaque)
{
    struct join_detach_race *race = opaque;
    int result;

    __atomic_store_n(&race->detach_ready, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&race->go, __ATOMIC_ACQUIRE) == 0)
        __asm__ volatile("pause" ::: "memory");
    result = pthread_detach(race->target_thread);
    __atomic_store_n(&race->detach_result, result, __ATOMIC_RELEASE);
    return 0;
}

static int run_candidate_join_detach_race_round(void)
{
    struct join_detach_race race = {{0, 0, 0, -1}, 0, 0, 0, 0, -1, -1};
    pthread_t join_thread = 0;
    pthread_t detach_thread = 0;
    int join_result;
    int detach_result;

    errno = parent_errno_sentinel;
    if (pthread_create(&race.target_thread, 0, pthread_normal_worker,
            &race.target) != 0 || wait_until_set(&race.target.entered))
        return 86;
    if (pthread_create(&join_thread, 0, join_racer_worker, &race) != 0 ||
        pthread_create(&detach_thread, 0, join_detach_racer_worker, &race) != 0 ||
        wait_until_set(&race.join_ready) || wait_until_set(&race.detach_ready))
        return 87;
    __atomic_store_n(&race.go, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&race.target.release, 1, __ATOMIC_RELEASE);
    if (pthread_join(join_thread, 0) != 0 || pthread_join(detach_thread, 0) != 0)
        return 88;
    join_result = __atomic_load_n(&race.join_result, __ATOMIC_ACQUIRE);
    detach_result = __atomic_load_n(&race.detach_result, __ATOMIC_ACQUIRE);
    if ((join_result == 0) + (detach_result == 0) != 1 ||
        (join_result != 0 && join_result != EINVAL) ||
        (detach_result != 0 && detach_result != EINVAL) ||
        errno != parent_errno_sentinel)
        return 89;
    if (wait_until_set(&race.target.completed))
        return 90;
    return 0;
}

/* POSIX does not admit pthread_join/thrd_join after successful detach.  This
 * candidate-only diagnostic invokes it while the worker is deliberately held
 * live, so the selected lazy reaper has not withdrawn its record.  It must
 * fail without changing errno; no path uses either handle after release. */
static int run_candidate_join_after_detach_diagnostic(void)
{
    struct held_worker pthread_worker = {0, 0, 0, -1};
    struct held_worker thrd_worker = {0, 0, 0, -1};
    pthread_t pthread_thread = 0;
    thrd_t thrd_thread = 0;

    errno = parent_errno_sentinel;
    if (pthread_create(&pthread_thread, 0, pthread_normal_worker,
            &pthread_worker) != 0 || wait_until_set(&pthread_worker.entered))
        return 54;
    if (pthread_detach(pthread_thread) != 0 || pthread_join(pthread_thread, 0) == 0 ||
        errno != parent_errno_sentinel)
        return 55;
    __atomic_store_n(&pthread_worker.release, 1, __ATOMIC_RELEASE);
    if (wait_until_set(&pthread_worker.completed))
        return 56;

    errno = parent_errno_sentinel;
    if (thrd_create(&thrd_thread, thrd_normal_worker, &thrd_worker) != thrd_success ||
        wait_until_set(&thrd_worker.entered))
        return 57;
    if (thrd_detach(thrd_thread) != thrd_success ||
        thrd_join(thrd_thread, 0) == thrd_success ||
        errno != parent_errno_sentinel)
        return 58;
    __atomic_store_n(&thrd_worker.release, 1, __ATOMIC_RELEASE);
    if (wait_until_set(&thrd_worker.completed))
        return 59;
    return 0;
}
#endif

#if defined(CRABC_PTHREAD_DETACH_SELECTED_WORKER_LIMIT)
/* The held workers publish completion before their return.  A later selected
 * pthread_create must observe the following CLONE_CHILD_CLEARTID transition,
 * lazily withdraw one completed detached slot, and reuse it. */
static int run_detached_completion_reuse_round(void)
{
    struct held_worker workers[CRABC_PTHREAD_DETACH_SELECTED_WORKER_LIMIT] = {{0}};
    pthread_t threads[CRABC_PTHREAD_DETACH_SELECTED_WORKER_LIMIT] = {0};
    struct held_worker reuse = {0, 0, 0, -1};
    pthread_t reuse_thread = 0;
    unsigned int index;
    unsigned long retry;

    errno = parent_errno_sentinel;
    for (index = 0; index != CRABC_PTHREAD_DETACH_SELECTED_WORKER_LIMIT; ++index) {
        workers[index].initial_errno = -1;
        if (pthread_create(&threads[index], 0, pthread_normal_worker,
                &workers[index]) != 0)
            return 60;
        if (wait_until_set(&workers[index].entered))
            return 61;
        if (pthread_detach(threads[index]) != 0)
            return 62;
    }
    for (index = 0; index != CRABC_PTHREAD_DETACH_SELECTED_WORKER_LIMIT; ++index)
        __atomic_store_n(&workers[index].release, 1, __ATOMIC_RELEASE);
    for (index = 0; index != CRABC_PTHREAD_DETACH_SELECTED_WORKER_LIMIT; ++index) {
        if (wait_until_set(&workers[index].completed) ||
            workers[index].initial_errno != 0)
            return 63;
    }

    /* No handle from the detached set is used here or below.  Completion is
     * published just before return, whereas CLONE_CHILD_CLEARTID follows in
     * kernel exit.  Retry the later selected create entry until it can observe
     * that clear and lazily reclaim a detached slot. */
    for (retry = 0; retry != 100000000UL; ++retry) {
        if (pthread_create(&reuse_thread, 0, pthread_normal_worker, &reuse) == 0)
            break;
        __asm__ volatile("pause" ::: "memory");
    }
    if (retry == 100000000UL)
        return 64;
    if (wait_until_set(&reuse.entered))
        return 65;
    __atomic_store_n(&reuse.release, 1, __ATOMIC_RELEASE);
    if (pthread_join(reuse_thread, 0) != 0 || reuse.initial_errno != 0 ||
        errno != parent_errno_sentinel)
        return 66;
    return 0;
}
#endif

static int run_detach_lifecycle(void)
{
    int result;

    if ((result = run_pthread_round(pthread_normal_worker, 0)) != 0 ||
        (result = run_pthread_round(pthread_normal_worker, 1)) != 0 ||
        (result = run_pthread_round(pthread_explicit_exit_worker, 0)) != 0 ||
        (result = run_pthread_round(pthread_explicit_exit_worker, 1)) != 0 ||
        (result = run_thrd_round(thrd_normal_worker, 0)) != 0 ||
        (result = run_thrd_round(thrd_normal_worker, 1)) != 0 ||
        (result = run_thrd_round(thrd_explicit_exit_worker, 0)) != 0 ||
        (result = run_thrd_round(thrd_explicit_exit_worker, 1)) != 0)
        return result;
#if defined(CRABC_PTHREAD_DETACH_FREESTANDING)
    if ((result = run_double_detach_round()) != 0)
        return result;
    if ((result = run_thrd_double_detach_round()) != 0)
        return result;
    if ((result = run_candidate_self_detach_completion_round()) != 0)
        return result;
    if ((result = run_candidate_null_detach_rejection_round()) != 0)
        return result;
    if ((result = run_candidate_detach_race_round()) != 0)
        return result;
    if ((result = run_candidate_join_detach_race_round()) != 0)
        return result;
    if ((result = run_candidate_join_after_detach_diagnostic()) != 0)
        return result;
#endif
#if defined(CRABC_PTHREAD_DETACH_SELECTED_WORKER_LIMIT)
    if ((result = run_detached_completion_reuse_round()) != 0)
        return result;
#endif
    return 0;
}

#if defined(CRABC_PTHREAD_DETACH_FREESTANDING)
int crabc_x86_64_pthread_detach_probe(void)
{
    return run_detach_lifecycle();
}
#else
int main(void)
{
    return run_detach_lifecycle();
}
#endif
