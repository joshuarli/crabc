#define _GNU_SOURCE
#include <pthread.h>
#include <threads.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "pthread_futex_wait_witness.h"

/* PI relock sleeps in the kernel's private FUTEX_LOCK_PI operation. */
enum { FUTEX_LOCK_PI_PRIVATE = 6 | 128 };

static pthread_mutex_t mutex;
static pthread_cond_t condition;
static pthread_t waiter;
static atomic_int ready, waiter_tid, observed_result, cleaned;
static int cancel_during_relock, unrecoverable, pi_robust;

static struct timespec deadline(clockid_t clock, long milliseconds)
{
    struct timespec value;
    if (clock_gettime(clock, &value)) _Exit(60);
    value.tv_nsec += milliseconds * 1000000;
    value.tv_sec += value.tv_nsec / 1000000000;
    value.tv_nsec %= 1000000000;
    return value;
}
static int owned_mutex(pthread_mutex_t *object)
{
    return pthread_mutex_trylock(object) == EBUSY;
}
static void init_condition(clockid_t clock)
{
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) || pthread_condattr_setclock(&attr, clock) ||
        pthread_cond_init(&condition, &attr) || pthread_condattr_destroy(&attr)) _Exit(61);
}
static int timeout_cases(clockid_t clock)
{
    init_condition(clock);
    if (pthread_mutex_init(&mutex, 0) || pthread_mutex_lock(&mutex)) return 1;
    struct timespec expired = { .tv_sec = -1, .tv_nsec = 0 };
    errno = E2BIG;
    if (pthread_cond_timedwait(&condition, &mutex, &expired) != ETIMEDOUT ||
        !owned_mutex(&mutex) || errno != E2BIG) return 2;
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = -1 };
    if (pthread_cond_timedwait(&condition, &mutex, &invalid) != EINVAL ||
        !owned_mutex(&mutex) || errno != E2BIG) return 3;
    invalid.tv_nsec = 1000000000;
    if (pthread_cond_timedwait(&condition, &mutex, &invalid) != EINVAL ||
        !owned_mutex(&mutex) || errno != E2BIG) return 4;
    struct timespec future = deadline(clock, 20);
    if (pthread_cond_timedwait(&condition, &mutex, &future) != ETIMEDOUT ||
        !owned_mutex(&mutex) || errno != E2BIG) return 5;
    struct timespec after = deadline(clock, 0);
    if (after.tv_sec < future.tv_sec ||
        (after.tv_sec == future.tv_sec && after.tv_nsec < future.tv_nsec)) return 6;
    if (pthread_mutex_unlock(&mutex) || pthread_cond_destroy(&condition) ||
        pthread_mutex_destroy(&mutex)) return 7;
    puts("pthread timed condition clock, timeout and mutex ownership: PASS");
    return 0;
}
static int attribute_cases(void)
{
    pthread_condattr_t attr;
    clockid_t clock;
    int shared;
    if (pthread_condattr_init(&attr) || pthread_condattr_getclock(&attr, &clock) ||
        clock != CLOCK_REALTIME || pthread_condattr_getpshared(&attr, &shared) || shared) return 8;
    /* Musl retains arbitrary nonnegative non-CPU clock IDs in attributes;
     * using an invalid ID fails at clock observation and publishes errno. */
    if (pthread_condattr_setclock(&attr, 12345) || pthread_cond_init(&condition, &attr) ||
        pthread_condattr_destroy(&attr) || pthread_mutex_init(&mutex, 0) ||
        pthread_mutex_lock(&mutex)) return 9;
    struct timespec expired = { .tv_sec = 0, .tv_nsec = 0 };
    errno = E2BIG;
    if (pthread_cond_timedwait(&condition, &mutex, &expired) != EINVAL ||
        errno != EINVAL || !owned_mutex(&mutex)) return 10;
    if (pthread_mutex_unlock(&mutex) || pthread_cond_destroy(&condition) ||
        pthread_mutex_destroy(&mutex)) return 11;
    puts("pthread condition attributes and invalid-clock errno: PASS");
    return 0;
}
static void cleanup(void *unused)
{
    (void)unused;
    atomic_store(&cleaned, 1);
}
static void *invalid_pending_waiter(void *unused)
{
    (void)unused;
    pthread_cleanup_push(cleanup, 0);
    if (pthread_mutex_lock(&mutex) || pthread_cancel(pthread_self())) _Exit(12);
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = -1 };
    if (pthread_cond_timedwait(&condition, &mutex, &invalid) != EINVAL ||
        !owned_mutex(&mutex) || pthread_mutex_unlock(&mutex)) _Exit(13);
    atomic_store(&observed_result, EINVAL);
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return 0;
}
static int pending_validation(void)
{
    init_condition(CLOCK_REALTIME);
    if (pthread_mutex_init(&mutex, 0) || pthread_create(&waiter, 0, invalid_pending_waiter, 0)) return 14;
    void *result;
    if (pthread_join(waiter, &result) || result != PTHREAD_CANCELED ||
        atomic_load(&observed_result) != EINVAL || !atomic_load(&cleaned) ||
        pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) return 15;
    puts("pthread condition validation precedes pending cancellation: PASS");
    return 0;
}
static void *robust_waiter(void *unused)
{
    (void)unused;
    pthread_cleanup_push(cleanup, 0);
    if (pthread_mutex_lock(&mutex)) _Exit(16);
    atomic_store(&waiter_tid, (int)syscall(SYS_gettid));
    struct timespec until = deadline(CLOCK_MONOTONIC, cancel_during_relock ? 30000 : 100);
    atomic_store(&ready, 1);
    errno = E2BIG;
    int result = pthread_cond_timedwait(&condition, &mutex, &until);
    /* Relocking acquires the now owner-dead mutex. Its result overrides both
     * expiration and cancellation; the request remains pending for later. */
    int expected = unrecoverable ? ENOTRECOVERABLE : EOWNERDEAD;
    if (result != expected || errno != E2BIG) _Exit(17);
    atomic_store(&observed_result, result);
    if (unrecoverable) {
        if (pthread_mutex_trylock(&mutex) != ENOTRECOVERABLE) _Exit(37);
    } else if (!owned_mutex(&mutex) || pthread_mutex_consistent(&mutex) ||
        pthread_mutex_unlock(&mutex)) _Exit(18);
    if (cancel_during_relock) {
        int state;
        if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state) || state != PTHREAD_CANCEL_ENABLE ||
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0)) _Exit(19);
        pthread_testcancel();
        _Exit(20);
    }
    pthread_cleanup_pop(0);
    return (void *)(uintptr_t)EOWNERDEAD;
}
static void *robust_owner(void *unused)
{
    (void)unused;
    while (!atomic_load(&ready)) sched_yield();
    witness_pthread_futex_wait(atomic_load(&waiter_tid), 128);
    if (pthread_mutex_lock(&mutex)) _Exit(21);
    if (unrecoverable) return 0;
    if (cancel_during_relock && pthread_cancel(waiter)) _Exit(22);
    /* For expiration and cancellation alike, retain ownership until the
     * waiter has left its condition futex and blocked on this exact mutex. */
    witness_pthread_futex_wait_at(atomic_load(&waiter_tid),
        pi_robust ? FUTEX_LOCK_PI_PRIVATE : 128,
        (unsigned long)(uintptr_t)((char *)&mutex + 4));
    return 0;
}
static int robust_relock(void)
{
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) || pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) ||
        (pi_robust && pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT)) ||
        pthread_mutex_init(&mutex, &attr) || pthread_mutexattr_destroy(&attr)) return 23;
    init_condition(CLOCK_MONOTONIC);
    /* Owner validation precedes timespec validation for non-normal mutexes. */
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = -1 };
    if (pthread_cond_timedwait(&condition, &mutex, &invalid) != EPERM) return 24;
    pthread_t owner;
    if (pthread_create(&waiter, 0, robust_waiter, 0) ||
        pthread_create(&owner, 0, robust_owner, 0)) return 25;
    void *result;
    if (pthread_join(owner, 0)) return 38;
    if (unrecoverable && (pthread_mutex_lock(&mutex) != EOWNERDEAD ||
        pthread_mutex_unlock(&mutex) || pthread_cancel(waiter))) return 39;
    if (pthread_join(waiter, &result) ||
        result != (cancel_during_relock ? PTHREAD_CANCELED : (void *)(uintptr_t)EOWNERDEAD) ||
        atomic_load(&observed_result) != (unrecoverable ? ENOTRECOVERABLE : EOWNERDEAD) ||
        atomic_load(&cleaned) != cancel_during_relock ||
        pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) return 26;
    puts("pthread condition robust relock overrides timeout or cancellation: PASS");
    return 0;
}
static atomic_int handoff_ready[4], handoff_tid[4];
static int handoff_count;
static void *handoff_waiter(void *argument)
{
    int index = (int)(uintptr_t)argument;
    if (pthread_mutex_lock(&mutex)) _Exit(28);
    atomic_store(&handoff_tid[index], (int)syscall(SYS_gettid));
    atomic_store(&handoff_ready[index], 1);
    struct timespec until = deadline(CLOCK_MONOTONIC, 30000);
    if (pthread_cond_timedwait(&condition, &mutex, &until)) _Exit(29);
    ++handoff_count;
    if (pthread_mutex_unlock(&mutex)) _Exit(30);
    return 0;
}
static int private_condition_shared_mutex(void)
{
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) ||
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) ||
        pthread_mutex_init(&mutex, &attr) || pthread_mutexattr_destroy(&attr)) return 31;
    init_condition(CLOCK_MONOTONIC);
    pthread_t threads[4];
    for (int index = 0; index != 4; ++index) {
        if (pthread_create(&threads[index], 0, handoff_waiter, (void *)(uintptr_t)index)) return 32;
        while (!atomic_load(&handoff_ready[index])) sched_yield();
        witness_pthread_futex_wait(atomic_load(&handoff_tid[index]), 128);
    }
    if (pthread_mutex_lock(&mutex) || pthread_cond_broadcast(&condition)) return 33;
    /* The oldest private waiter reaches this shared mutex first. Its release
     * must wake later private barriers, rather than requeue onto a shared key. */
    witness_pthread_futex_wait_at(atomic_load(&handoff_tid[0]), 0,
        (unsigned long)(uintptr_t)((char *)&mutex + 4));
    if (pthread_mutex_unlock(&mutex)) return 34;
    for (int index = 0; index != 4; ++index) {
        if (pthread_join(threads[index], 0)) return 35;
    }
    if (handoff_count != 4 || pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) return 36;
    puts("private condition broadcast releases waiters onto a shared mutex: PASS");
    return 0;
}
static void relock_timeout_cleanup(void *unused)
{
    (void)unused;
    if (!owned_mutex(&mutex) || pthread_mutex_unlock(&mutex)) _Exit(43);
    atomic_store(&cleaned, 1);
}
static void *relock_timeout_waiter(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&mutex)) _Exit(44);
    pthread_cleanup_push(relock_timeout_cleanup, 0);
    atomic_store(&waiter_tid, (int)syscall(SYS_gettid));
    struct timespec until = deadline(CLOCK_MONOTONIC, 1000);
    atomic_store(&ready, 1);
    errno = E2BIG;
    int result = pthread_cond_timedwait(&condition, &mutex, &until);
    if (result != ETIMEDOUT || errno != E2BIG || !owned_mutex(&mutex)) _Exit(45);
    atomic_store(&observed_result, result);
    /* Cancellation requested during the relock remains pending until this
     * explicit point. Cleanup must observe the reacquired mutex. */
    pthread_testcancel();
    _Exit(46);
    pthread_cleanup_pop(0);
    return 0;
}
static int cancel_after_shared_mutex_timeout(int shared_condition)
{
    pthread_mutexattr_t mutex_attr;
    pthread_condattr_t cond_attr;
    if (pthread_mutexattr_init(&mutex_attr) ||
        pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED) ||
        pthread_mutex_init(&mutex, &mutex_attr) || pthread_mutexattr_destroy(&mutex_attr) ||
        pthread_condattr_init(&cond_attr) ||
        pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC) ||
        (shared_condition && pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED)) ||
        pthread_cond_init(&condition, &cond_attr) || pthread_condattr_destroy(&cond_attr) ||
        pthread_create(&waiter, 0, relock_timeout_waiter, 0)) return 47;
    while (!atomic_load(&ready)) sched_yield();
    int tid = atomic_load(&waiter_tid);
    if (shared_condition) {
        witness_pthread_futex_wait_at(tid, 0,
            (unsigned long)(uintptr_t)((char *)&condition + 8));
    } else {
        witness_pthread_futex_wait(tid, 128);
    }
    if (pthread_mutex_lock(&mutex)) return 48;
    witness_pthread_futex_wait_at(tid, 0,
        (unsigned long)(uintptr_t)((char *)&mutex + 4));
    if (pthread_cancel(waiter) || pthread_mutex_unlock(&mutex)) return 49;
    void *result;
    if (pthread_join(waiter, &result) || result != PTHREAD_CANCELED ||
        atomic_load(&observed_result) != ETIMEDOUT || !atomic_load(&cleaned) ||
        pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) return 50;
    puts("pthread timed condition timeout wins cancellation during shared mutex relock: PASS");
    return 0;
}
static int c11_timeout(void)
{
    mtx_t lock;
    cnd_t cond;
    struct timespec expired = { .tv_sec = -1, .tv_nsec = 0 };
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = -1 };
    errno = E2BIG;
    if (mtx_init(&lock, mtx_plain) != thrd_success || cnd_init(&cond) != thrd_success ||
        mtx_lock(&lock) != thrd_success ||
        cnd_timedwait(&cond, &lock, &expired) != thrd_timedout ||
        cnd_timedwait(&cond, &lock, &invalid) != thrd_error ||
        mtx_trylock(&lock) != thrd_busy || errno != E2BIG ||
        mtx_unlock(&lock) != thrd_success) return 27;
    cnd_destroy(&cond);
    mtx_destroy(&lock);
    puts("C11 timed condition status and mutex ownership: PASS");
    return 0;
}
static atomic_int timed_ready[2], timed_tid[2], timed_completed;
static int timed_permits, timed_results[2];
static clockid_t timed_clock;
static void *timed_handoff_waiter(void *argument)
{
    int index = (int)(uintptr_t)argument;
    if (pthread_mutex_lock(&mutex)) _Exit(51);
    atomic_store(&timed_tid[index], (int)syscall(SYS_gettid));
    atomic_store(&timed_ready[index], 1);
    struct timespec until = deadline(timed_clock, 30000);
    while (!timed_permits) {
        int result = pthread_cond_timedwait(&condition, &mutex, &until);
        if (result || !owned_mutex(&mutex)) _Exit(52);
    }
    --timed_permits;
    timed_results[index] = 1;
    atomic_fetch_add(&timed_completed, 1);
    if (pthread_mutex_unlock(&mutex)) _Exit(53);
    return 0;
}
static int timed_handoff(clockid_t clock, int shared)
{
    pthread_condattr_t cond_attr;
    pthread_mutexattr_t mutex_attr;
    timed_clock = clock;
    if (pthread_mutexattr_init(&mutex_attr) ||
        (shared && pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED)) ||
        pthread_mutex_init(&mutex, &mutex_attr) || pthread_mutexattr_destroy(&mutex_attr) ||
        pthread_condattr_init(&cond_attr) || pthread_condattr_setclock(&cond_attr, clock) ||
        (shared && pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED)) ||
        pthread_cond_init(&condition, &cond_attr) || pthread_condattr_destroy(&cond_attr)) return 54;
    pthread_t threads[2];
    for (int index = 0; index != 2; ++index) {
        if (pthread_create(&threads[index], 0, timed_handoff_waiter,
            (void *)(uintptr_t)index)) return 55;
        while (!atomic_load(&timed_ready[index])) sched_yield();
        if (shared) {
            witness_pthread_futex_wait_at(atomic_load(&timed_tid[index]), 0,
                (unsigned long)(uintptr_t)((char *)&condition + 8));
        } else {
            witness_pthread_futex_wait(atomic_load(&timed_tid[index]), 128);
        }
    }
    if (pthread_mutex_lock(&mutex)) return 56;
    timed_permits = 1;
    if (pthread_cond_signal(&condition) || pthread_mutex_unlock(&mutex)) return 57;
    while (atomic_load(&timed_completed) != 1) sched_yield();
    if (pthread_mutex_lock(&mutex)) return 58;
    timed_permits = 1;
    if (pthread_cond_broadcast(&condition) || pthread_mutex_unlock(&mutex)) return 59;
    for (int index = 0; index != 2; ++index) {
        if (pthread_join(threads[index], 0)) return 62;
    }
    if (atomic_load(&timed_completed) != 2 || !timed_results[0] || !timed_results[1] ||
        pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) return 63;
    puts("pthread timed condition signal/broadcast handoff and relock: PASS");
    return 0;
}
static atomic_int race_ready, race_tid, race_result;
static void *timed_race_waiter(void *argument)
{
    int late = (int)(uintptr_t)argument;
    if (pthread_mutex_lock(&mutex)) _Exit(64);
    atomic_store(&race_tid, (int)syscall(SYS_gettid));
    struct timespec until = deadline(CLOCK_MONOTONIC, late ? 20 : 30000);
    atomic_store(&race_ready, 1);
    int result = pthread_cond_timedwait(&condition, &mutex, &until);
    if (!owned_mutex(&mutex) || (late ? result != ETIMEDOUT && result != 0 : result != 0)) _Exit(65);
    atomic_store(&race_result, result);
    if (pthread_mutex_unlock(&mutex)) _Exit(66);
    return 0;
}
static int timed_signal_timeout_race(void)
{
    init_condition(CLOCK_MONOTONIC);
    if (pthread_mutex_init(&mutex, 0)) return 67;
    for (int iteration = 0; iteration != 8; ++iteration) {
        int late = iteration & 1;
        atomic_store(&race_ready, 0);
        atomic_store(&race_result, -1);
        if (pthread_create(&waiter, 0, timed_race_waiter, (void *)(uintptr_t)late)) return 68;
        while (!atomic_load(&race_ready)) sched_yield();
        witness_pthread_futex_wait(atomic_load(&race_tid), 128);
        if (pthread_mutex_lock(&mutex)) return 69;
        if (late) {
            struct timespec pause = { .tv_sec = 0, .tv_nsec = 30000000 };
            if (nanosleep(&pause, 0)) return 71;
        }
        if (pthread_cond_signal(&condition) || pthread_mutex_unlock(&mutex) ||
            pthread_join(waiter, 0)) return 72;
        int result = atomic_load(&race_result);
        if (late ? result != 0 && result != ETIMEDOUT : result != 0) return 73;
    }
    if (pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) return 74;
    puts("pthread timed condition signal/timeout race and reuse: PASS");
    return 0;
}
static atomic_int spurious_ready, spurious_tid, spurious_returned;
static int spurious_permit;
static clockid_t spurious_clock;
static void *spurious_waiter(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&mutex)) _Exit(84);
    atomic_store(&spurious_tid, (int)syscall(SYS_gettid));
    atomic_store(&spurious_ready, 1);
    struct timespec until = deadline(spurious_clock, 30000);
    errno = E2BIG;
    while (!spurious_permit) {
        int result = pthread_cond_timedwait(&condition, &mutex, &until);
        if (result || !owned_mutex(&mutex) || errno != E2BIG) _Exit(85);
        atomic_fetch_add(&spurious_returned, 1);
    }
    if (pthread_mutex_unlock(&mutex)) _Exit(86);
    return 0;
}
static int shared_spurious_wake(clockid_t clock)
{
    pthread_mutexattr_t mutex_attr;
    pthread_condattr_t cond_attr;
    spurious_clock = clock;
    if (pthread_mutexattr_init(&mutex_attr) ||
        pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED) ||
        pthread_mutex_init(&mutex, &mutex_attr) || pthread_mutexattr_destroy(&mutex_attr) ||
        pthread_condattr_init(&cond_attr) ||
        pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED) ||
        pthread_condattr_setclock(&cond_attr, clock) ||
        pthread_cond_init(&condition, &cond_attr) || pthread_condattr_destroy(&cond_attr)) return 87;
    pthread_t thread;
    if (pthread_create(&thread, 0, spurious_waiter, 0)) return 88;
    while (!atomic_load(&spurious_ready)) sched_yield();
    int tid = atomic_load(&spurious_tid);
    unsigned long address = (unsigned long)(uintptr_t)((char *)&condition + 8);
    witness_pthread_futex_wait_at(tid, 0, address);
    /* Raw futex wakes leave the condition sequence unchanged. The waiter
     * must reenter its timed futex wait until a real condition signal arrives. */
    for (int wake = 0; wake != 2; ++wake) {
        for (;;) {
            long count = syscall(SYS_futex, (void *)(uintptr_t)address, 1, 1, 0);
            if (count == 1) break;
            if (count != 0) return 89;
            sched_yield();
        }
    }
    if (atomic_load(&spurious_returned) != 0 || pthread_mutex_lock(&mutex)) return 89;
    spurious_permit = 1;
    if (pthread_cond_signal(&condition) || pthread_mutex_unlock(&mutex) ||
        pthread_join(thread, 0)) return 90;
    if (atomic_load(&spurious_returned) != 1 ||
        pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) return 91;
    puts("pthread shared timed condition ignores raw futex wakes: PASS");
    return 0;
}
struct timed_shared_state {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    atomic_int ready;
    int permit;
};
static void timed_shared_child(struct timed_shared_state *state, clockid_t clock, int signal_child)
{
    if (pthread_mutex_lock(&state->mutex)) _Exit(75);
    struct timespec until = deadline(clock, signal_child ? 30000 : 1000);
    atomic_store(&state->ready, 1);
    int result = pthread_cond_timedwait(&state->condition, &state->mutex, &until);
    if (result != (signal_child ? 0 : ETIMEDOUT) || !owned_mutex(&state->mutex) ||
        state->permit != signal_child || pthread_mutex_unlock(&state->mutex)) _Exit(76);
    _Exit(0);
}
static int timed_shared_lifecycle(clockid_t clock)
{
    struct timed_shared_state *state = mmap(0, 4096, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) return 77;
    for (int pass = 0; pass != 2; ++pass) {
        pthread_mutexattr_t mutex_attr;
        pthread_condattr_t cond_attr;
        if (pthread_mutexattr_init(&mutex_attr) ||
            pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED) ||
            pthread_mutex_init(&state->mutex, &mutex_attr) ||
            pthread_mutexattr_destroy(&mutex_attr) || pthread_condattr_init(&cond_attr) ||
            pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED) ||
            pthread_condattr_setclock(&cond_attr, clock) ||
            pthread_cond_init(&state->condition, &cond_attr) ||
            pthread_condattr_destroy(&cond_attr)) return 78;
        atomic_store(&state->ready, 0);
        state->permit = 0;
        pid_t child = fork();
        if (child < 0) return 79;
        if (!child) timed_shared_child(state, clock, pass);
        while (!atomic_load(&state->ready)) sched_yield();
        witness_process_futex_wait_at(child, child, 0,
            (unsigned long)(uintptr_t)((char *)&state->condition + 8));
        if (pass) {
            if (pthread_mutex_lock(&state->mutex)) return 80;
            state->permit = 1;
            if (pthread_cond_signal(&state->condition) || pthread_mutex_unlock(&state->mutex)) return 81;
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) ||
            pthread_cond_destroy(&state->condition) || pthread_mutex_destroy(&state->mutex)) return 82;
    }
    if (munmap(state, 4096)) return 83;
    puts("pthread shared timed condition timeout, destroy/reinit and signal: PASS");
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 2) return 70;
    if (!strcmp(argv[1], "realtime")) return timeout_cases(CLOCK_REALTIME);
    if (!strcmp(argv[1], "monotonic")) return timeout_cases(CLOCK_MONOTONIC);
    if (!strcmp(argv[1], "attributes")) return attribute_cases();
    if (!strcmp(argv[1], "pending-validation")) return pending_validation();
    if (!strcmp(argv[1], "c11")) return c11_timeout();
    if (!strcmp(argv[1], "private-shared-mutex")) return private_condition_shared_mutex();
    if (!strcmp(argv[1], "private-timeout-relock-cancel")) return cancel_after_shared_mutex_timeout(0);
    if (!strcmp(argv[1], "shared-timeout-relock-cancel")) return cancel_after_shared_mutex_timeout(1);
    if (!strcmp(argv[1], "handoff-realtime")) return timed_handoff(CLOCK_REALTIME, 0);
    if (!strcmp(argv[1], "handoff-monotonic")) return timed_handoff(CLOCK_MONOTONIC, 0);
    if (!strcmp(argv[1], "handoff-shared")) return timed_handoff(CLOCK_MONOTONIC, 1);
    if (!strcmp(argv[1], "timeout-race")) return timed_signal_timeout_race();
    if (!strcmp(argv[1], "spurious-realtime")) return shared_spurious_wake(CLOCK_REALTIME);
    if (!strcmp(argv[1], "spurious-monotonic")) return shared_spurious_wake(CLOCK_MONOTONIC);
    if (!strcmp(argv[1], "shared-lifecycle-realtime")) return timed_shared_lifecycle(CLOCK_REALTIME);
    if (!strcmp(argv[1], "shared-lifecycle-monotonic")) return timed_shared_lifecycle(CLOCK_MONOTONIC);
    unrecoverable = !strcmp(argv[1], "robust-unrecoverable");
    pi_robust = !strcmp(argv[1], "pi-robust-cancel");
    cancel_during_relock = unrecoverable || pi_robust || !strcmp(argv[1], "robust-cancel");
    return robust_relock();
}
