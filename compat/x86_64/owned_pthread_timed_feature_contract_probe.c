/*
 * One bounded installed-header consumer for the four x86 owned timed aliases.
 *
 * It checks only ordinary timeout/success, tryjoin ownership, and timedjoin
 * cancellation retention; it is not a pthread-family qualification.
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static int deadline_after(struct timespec *value, time_t seconds)
{
    if (clock_gettime(CLOCK_REALTIME, value))
        return errno ? errno : EINVAL;
    value->tv_sec += seconds;
    return 0;
}

static int wait_ready(atomic_int *value)
{
    for (int attempt = 0; attempt != 1000000; ++attempt) {
        if (atomic_load(value))
            return 0;
        sched_yield();
    }
    return 1;
}

static pthread_mutex_t timed_mutex;
static atomic_int mutex_locked;
static atomic_int mutex_release;

static void *mutex_holder(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&timed_mutex))
        return (void *)(uintptr_t)1;
    atomic_store(&mutex_locked, 1);
    while (!atomic_load(&mutex_release))
        sched_yield();
    return (void *)(uintptr_t)pthread_mutex_unlock(&timed_mutex);
}

static int test_mutex_timedlock(void)
{
    pthread_t holder;
    void *result;
    struct timespec past = { .tv_sec = 0, .tv_nsec = 0 };
    struct timespec future;

    if (deadline_after(&future, 5))
        return 9;
    if (pthread_mutex_init(&timed_mutex, 0) || pthread_create(&holder, 0, mutex_holder, 0))
        return 10;
    if (wait_ready(&mutex_locked))
        return 11;
    errno = E2BIG;
    if (pthread_mutex_timedlock(&timed_mutex, &past) != ETIMEDOUT || errno != E2BIG)
        return 12;
    atomic_store(&mutex_release, 1);
    if (pthread_join(holder, &result) || result)
        return 13;
    if (pthread_mutex_timedlock(&timed_mutex, &future) || pthread_mutex_unlock(&timed_mutex))
        return 14;
    return pthread_mutex_destroy(&timed_mutex) ? 15 : 0;
}

static pthread_mutex_t condition_mutex;
static pthread_cond_t condition;
static atomic_int signaler_ready;
static atomic_int force_spurious;
static atomic_int spurious_while_held;

/* Isolated regression wrapper: its first synthetic success must not consume
 * the predicate; the real timed wait still uses the original deadline. */
static int first_spurious_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                                    const struct timespec *deadline)
{
    if (atomic_exchange(&force_spurious, 0)) {
        if (pthread_mutex_trylock(mutex) != EBUSY)
            return EINVAL;
        atomic_store(&spurious_while_held, 1);
        return 0;
    }
    return pthread_cond_timedwait(cond, mutex, deadline);
}

static void *signaler(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&condition_mutex))
        return (void *)(uintptr_t)1;
    atomic_store(&signaler_ready, 1);
    if (pthread_cond_signal(&condition) || pthread_mutex_unlock(&condition_mutex))
        return (void *)(uintptr_t)2;
    return 0;
}

static int test_condition_timedwait(void)
{
    pthread_t thread;
    void *result;
    struct timespec past = { .tv_sec = 0, .tv_nsec = 0 };
    struct timespec future;
    int wait_status;

    if (deadline_after(&future, 5))
        return 19;
    if (pthread_mutex_init(&condition_mutex, 0) || pthread_cond_init(&condition, 0)
        || pthread_mutex_lock(&condition_mutex))
        return 20;
    errno = E2BIG;
    if (pthread_cond_timedwait(&condition, &condition_mutex, &past) != ETIMEDOUT || errno != E2BIG)
        return 21;
    atomic_store(&force_spurious, 1);
    atomic_store(&spurious_while_held, 0);
    if (pthread_create(&thread, 0, signaler, 0))
        return 22;
    while (!atomic_load(&signaler_ready)) {
        wait_status = first_spurious_timedwait(&condition, &condition_mutex, &future);
        if (wait_status)
            return 23;
    }
    if (!atomic_load(&spurious_while_held) || pthread_mutex_unlock(&condition_mutex)
        || pthread_join(thread, &result) || result)
        return 24;
    return (pthread_cond_destroy(&condition) || pthread_mutex_destroy(&condition_mutex)) ? 25 : 0;
}

static atomic_int target_ready;
static atomic_int target_release;

static void *target(void *unused)
{
    (void)unused;
    atomic_store(&target_ready, 1);
    while (!atomic_load(&target_release))
        sched_yield();
    return (void *)(uintptr_t)37;
}

static pthread_t cancel_target;
static atomic_int joiner_ready;

static void *cancelable_joiner(void *unused)
{
    void *result = 0;
    struct timespec future;
    if (deadline_after(&future, 30))
        return (void *)(uintptr_t)EINVAL;
    (void)unused;
    atomic_store(&joiner_ready, 1);
    return (void *)(uintptr_t)pthread_timedjoin_np(cancel_target, &result, &future);
}

static int test_join_modes(void)
{
    pthread_t thread, joiner;
    void *result = (void *)(uintptr_t)0x1234;
    void *joined;
    struct timespec past = { .tv_sec = 0, .tv_nsec = 0 };
    struct timespec future;

    if (deadline_after(&future, 5))
        return 29;
    if (pthread_create(&thread, 0, target, 0) || wait_ready(&target_ready))
        return 30;
    errno = E2BIG;
    if (pthread_tryjoin_np(thread, &result) != EBUSY || result != (void *)(uintptr_t)0x1234 || errno != E2BIG)
        return 31;
    if (pthread_timedjoin_np(thread, &result, &past) != ETIMEDOUT
        || result != (void *)(uintptr_t)0x1234 || errno != E2BIG)
        return 32;
    atomic_store(&target_release, 1);
    if (pthread_timedjoin_np(thread, &result, &future) || result != (void *)(uintptr_t)37 || errno != E2BIG)
        return 33;

    atomic_store(&target_ready, 0);
    atomic_store(&target_release, 0);
    result = (void *)(uintptr_t)0x4567;
    if (pthread_create(&thread, 0, target, 0) || wait_ready(&target_ready))
        return 34;
    if (pthread_tryjoin_np(thread, &result) != EBUSY || result != (void *)(uintptr_t)0x4567)
        return 35;
    atomic_store(&target_release, 1);
    for (int attempt = 0; attempt != 1000000; ++attempt) {
        if (!pthread_tryjoin_np(thread, &result)) {
            if (result != (void *)(uintptr_t)37)
                return 36;
            goto tryjoin_complete;
        }
        sched_yield();
    }
    return 37;

tryjoin_complete:

    atomic_store(&target_ready, 0);
    atomic_store(&target_release, 0);
    if (pthread_create(&cancel_target, 0, target, 0) || wait_ready(&target_ready)
        || pthread_create(&joiner, 0, cancelable_joiner, 0) || wait_ready(&joiner_ready)
        || pthread_cancel(joiner) || pthread_join(joiner, &joined) || joined != PTHREAD_CANCELED)
        return 38;
    atomic_store(&target_release, 1);
    if (pthread_join(cancel_target, &result) || result != (void *)(uintptr_t)37)
        return 39;
    return 0;
}

int main(void)
{
    int status;
    if ((status = test_mutex_timedlock())
        || (status = test_condition_timedwait())
        || (status = test_join_modes()))
        return status;
    puts("owned-pthread-timed-feature-contract-ok");
    return 0;
}
