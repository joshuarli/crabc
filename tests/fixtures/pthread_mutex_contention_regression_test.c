/* Direct pinned-Musl differential for normal-mutex waiter bookkeeping. */
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdatomic.h>

enum {
    THREAD_COUNT = 16,
    ITERATIONS_PER_THREAD = 3000,
    ROUND_COUNT = 8,
};

struct worker {
    int result;
};

static pthread_mutex_t mutex;
static int counter;
static atomic_int workers_ready;
static atomic_int start_workers;

static void *run_worker(void *opaque)
{
    struct worker *worker = opaque;

    atomic_fetch_add_explicit(&workers_ready, 1, memory_order_release);
    while (atomic_load_explicit(&start_workers, memory_order_acquire) == 0)
        sched_yield();
    for (int iteration = 0; iteration < ITERATIONS_PER_THREAD; ++iteration) {
        if (pthread_mutex_lock(&mutex) != 0) {
            worker->result = 1;
            return NULL;
        }
        counter++;
        if (pthread_mutex_unlock(&mutex) != 0) {
            worker->result = 2;
            return NULL;
        }
    }
    return NULL;
}

static int run_round(void)
{
    pthread_t threads[THREAD_COUNT];
    struct worker workers[THREAD_COUNT] = {0};

    counter = 0;
    atomic_init(&workers_ready, 0);
    atomic_init(&start_workers, 0);
    if (pthread_mutex_init(&mutex, NULL) != 0)
        return 1;
    /* Hold the mutex while workers are created so their first acquisition
     * forms a highly contended wakeup chain rather than an uncontended loop. */
    if (pthread_mutex_lock(&mutex) != 0)
        return 2;
    for (int index = 0; index < THREAD_COUNT; ++index) {
        if (pthread_create(&threads[index], NULL, run_worker, &workers[index]) != 0)
            return 3;
    }
    while (atomic_load_explicit(&workers_ready, memory_order_acquire) != THREAD_COUNT)
        sched_yield();
    atomic_store_explicit(&start_workers, 1, memory_order_release);
    if (pthread_mutex_unlock(&mutex) != 0)
        return 4;
    for (int index = 0; index < THREAD_COUNT; ++index) {
        if (pthread_join(threads[index], NULL) != 0)
            return 5;
        if (workers[index].result != 0)
            return 6;
    }
    if (counter != THREAD_COUNT * ITERATIONS_PER_THREAD)
        return 7;
    if (pthread_mutex_destroy(&mutex) != 0)
        return 8;

    return 0;
}

int main(void)
{
    for (int round = 0; round < ROUND_COUNT; ++round) {
        if (run_round() != 0)
            return round + 1;
    }

    puts("pthread mutex contention contract ok");
    return 0;
}
