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
#include "pthread_futex_wait_witness.h"

static pthread_mutex_t mutex;
static pthread_cond_t condition;
static pthread_t waiter;
static atomic_int ready, waiter_tid, observed_result, cleaned;
static int cancel_during_relock, unrecoverable;

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
    witness_pthread_futex_wait_at(atomic_load(&waiter_tid), 128,
        (unsigned long)(uintptr_t)((char *)&mutex + 4));
    return 0;
}
static int robust_relock(void)
{
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) || pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) ||
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
int main(int argc, char **argv)
{
    if (argc != 2) return 70;
    if (!strcmp(argv[1], "realtime")) return timeout_cases(CLOCK_REALTIME);
    if (!strcmp(argv[1], "monotonic")) return timeout_cases(CLOCK_MONOTONIC);
    if (!strcmp(argv[1], "attributes")) return attribute_cases();
    if (!strcmp(argv[1], "pending-validation")) return pending_validation();
    if (!strcmp(argv[1], "c11")) return c11_timeout();
    if (!strcmp(argv[1], "private-shared-mutex")) return private_condition_shared_mutex();
    unrecoverable = !strcmp(argv[1], "robust-unrecoverable");
    cancel_during_relock = unrecoverable || !strcmp(argv[1], "robust-cancel");
    return robust_relock();
}
