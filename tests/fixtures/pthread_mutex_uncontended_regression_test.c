/* Direct pinned-Musl differential for the selected normal-mutex fast path. */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#include "../../compat/perf/fixtures/pthread_mutex_uncontended_contract.h"

struct normal_mutex_handoff {
    pthread_mutex_t mutex;
    atomic_int worker_started;
    atomic_int worker_acquired;
    int worker_result;
};

static void *normal_mutex_waiter(void *opaque)
{
    struct normal_mutex_handoff *handoff = opaque;

    atomic_store_explicit(&handoff->worker_started, 1, memory_order_release);
    handoff->worker_result = pthread_mutex_lock(&handoff->mutex);
    if (handoff->worker_result == 0) {
        atomic_store_explicit(&handoff->worker_acquired, 1, memory_order_release);
        handoff->worker_result = pthread_mutex_unlock(&handoff->mutex);
    }
    return (void *)(uintptr_t)handoff->worker_result;
}

static int test_normal_mutex_handoff(void)
{
    struct normal_mutex_handoff handoff;
    pthread_t worker;
    void *worker_result;

    if (pthread_mutex_init(&handoff.mutex, NULL) != 0)
        return 1;
    atomic_init(&handoff.worker_started, 0);
    atomic_init(&handoff.worker_acquired, 0);
    handoff.worker_result = -1;
    if (pthread_mutex_lock(&handoff.mutex) != 0)
        return 2;
    if (pthread_create(&worker, NULL, normal_mutex_waiter, &handoff) != 0)
        return 3;
    for (unsigned int attempt = 0; attempt < 100000; ++attempt) {
        if (atomic_load_explicit(&handoff.worker_started, memory_order_acquire) != 0)
            break;
        sched_yield();
    }
    if (atomic_load_explicit(&handoff.worker_started, memory_order_acquire) == 0)
        return 4;
    /* Give a running contender opportunities to block; ownership must not
     * transfer before the current holder explicitly releases the mutex. */
    for (unsigned int attempt = 0; attempt < 128; ++attempt)
        sched_yield();
    if (atomic_load_explicit(&handoff.worker_acquired, memory_order_acquire) != 0)
        return 5;
    if (pthread_mutex_unlock(&handoff.mutex) != 0)
        return 6;
    if (pthread_join(worker, &worker_result) != 0)
        return 7;
    if (worker_result != NULL || handoff.worker_result != 0
            || atomic_load_explicit(&handoff.worker_acquired, memory_order_acquire) != 1)
        return 8;
    if (pthread_mutex_destroy(&handoff.mutex) != 0)
        return 9;
    return 0;
}

int main(void)
{
    pthread_mutex_t mutex;
    uint64_t observed = 0;

    if (pthread_mutex_uncontended_run(1000000, &observed) != 0
            || observed != 1000000)
        return 1;
    if (pthread_mutex_init(&mutex, NULL) != 0)
        return 2;
    if (pthread_mutex_lock(&mutex) != 0)
        return 3;
    if (pthread_mutex_trylock(&mutex) != EBUSY)
        return 4;
    if (pthread_mutex_unlock(&mutex) != 0 || pthread_mutex_destroy(&mutex) != 0)
        return 5;
    if (test_normal_mutex_handoff() != 0)
        return 6;
    puts("pthread mutex uncontended contract ok");
    return 0;
}
