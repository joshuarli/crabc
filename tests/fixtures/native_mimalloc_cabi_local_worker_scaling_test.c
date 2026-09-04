/*
 * Each scale releases 1, 2, 4, or 8 independent pthread workers together.
 * A worker owns only its local C allocations while it allocates, grows and
 * shrinks one block with realloc, verifies the preserved bytes, and frees
 * every block before returning normally. The shared start gate contains no
 * allocation address, allocator identity, route, or completion token: it
 * merely makes the public local-operation interval overlap. `pthread_join`
 * then observes each worker's normal return, so libc performs its ordinary
 * pthread finish after the local work is complete. This deliberately does not
 * select pthread_exit or cancellation behavior.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum {
    MAX_WORKERS = 8,
    LOCAL_ROUNDS = 3,
};

struct local_worker_start_gate {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned int waiting;
    int released;
};

struct local_worker_context {
    struct local_worker_start_gate *gate;
    unsigned int worker_index;
};

static unsigned char marker(unsigned int worker, unsigned int round,
        unsigned int offset)
{
    return (unsigned char)(0x20 + worker * 13 + round * 3 + offset);
}

static int wait_for_local_start(struct local_worker_start_gate *gate)
{
    if (pthread_mutex_lock(&gate->lock) != 0)
        return 1;
    gate->waiting += 1;
    if (pthread_cond_broadcast(&gate->changed) != 0) {
        (void)pthread_mutex_unlock(&gate->lock);
        return 2;
    }
    while (!gate->released) {
        if (pthread_cond_wait(&gate->changed, &gate->lock) != 0) {
            (void)pthread_mutex_unlock(&gate->lock);
            return 3;
        }
    }
    if (pthread_mutex_unlock(&gate->lock) != 0)
        return 4;
    return 0;
}

static int run_local_reallocation_round(unsigned int worker, unsigned int round)
{
    size_t primary_size = 37 + worker * 19 + round * 7;
    size_t companion_size = 73 + worker * 11 + round * 5;
    size_t grown_size = primary_size + 257;
    size_t shrunk_size = primary_size + 3;
    unsigned char primary_first = marker(worker, round, 0);
    unsigned char primary_last = marker(worker, round, 1);
    unsigned char companion_first = marker(worker, round, 2);
    unsigned char companion_last = marker(worker, round, 3);
    unsigned char grown_last = marker(worker, round, 4);
    unsigned char shrunk_last = marker(worker, round, 5);
    unsigned char *primary;
    unsigned char *companion;
    unsigned char *grown;
    unsigned char *shrunk;

    primary = malloc(primary_size);
    if (primary == NULL)
        return 1;
    companion = malloc(companion_size);
    if (companion == NULL) {
        free(primary);
        return 2;
    }
    primary[0] = primary_first;
    primary[primary_size - 1] = primary_last;
    companion[0] = companion_first;
    companion[companion_size - 1] = companion_last;

    grown = realloc(primary, grown_size);
    if (grown == NULL) {
        free(companion);
        free(primary);
        return 3;
    }
    if (grown[0] != primary_first || grown[primary_size - 1] != primary_last
            || companion[0] != companion_first
            || companion[companion_size - 1] != companion_last) {
        free(companion);
        free(grown);
        return 4;
    }
    grown[grown_size - 1] = grown_last;
    free(companion);

    shrunk = realloc(grown, shrunk_size);
    if (shrunk == NULL) {
        free(grown);
        return 5;
    }
    if (shrunk[0] != primary_first
            || shrunk[primary_size - 1] != primary_last) {
        free(shrunk);
        return 6;
    }
    shrunk[shrunk_size - 1] = shrunk_last;
    if (shrunk[shrunk_size - 1] != shrunk_last) {
        free(shrunk);
        return 7;
    }
    free(shrunk);
    return 0;
}

static void *local_worker(void *opaque)
{
    const struct local_worker_context *context = opaque;
    unsigned int round;
    int start_result;

    start_result = wait_for_local_start(context->gate);
    if (start_result != 0)
        return (void *)(uintptr_t)start_result;
    for (round = 0; round < LOCAL_ROUNDS; round++) {
        int round_result = run_local_reallocation_round(context->worker_index,
                round);

        if (round_result != 0)
            return (void *)(uintptr_t)(10 + round_result);
    }
    return NULL;
}

static int release_workers(struct local_worker_start_gate *gate)
{
    int broadcast_result;
    int unlock_result;

    if (pthread_mutex_lock(&gate->lock) != 0)
        return 1;
    gate->released = 1;
    broadcast_result = pthread_cond_broadcast(&gate->changed);
    unlock_result = pthread_mutex_unlock(&gate->lock);
    if (broadcast_result != 0)
        return 2;
    return unlock_result == 0 ? 0 : 3;
}

static int run_worker_scale(unsigned int worker_count)
{
    struct local_worker_start_gate gate = {
        PTHREAD_MUTEX_INITIALIZER,
        PTHREAD_COND_INITIALIZER,
        0,
        0,
    };
    struct local_worker_context contexts[MAX_WORKERS];
    pthread_t workers[MAX_WORKERS];
    unsigned int created = 0;
    unsigned int index;
    int failed = 0;

    if (worker_count == 0 || worker_count > MAX_WORKERS)
        return 1;
    for (index = 0; index < worker_count; index++) {
        contexts[index].gate = &gate;
        contexts[index].worker_index = index;
        if (pthread_create(&workers[index], NULL, local_worker,
                &contexts[index]) != 0) {
            failed = 2;
            break;
        }
        created += 1;
    }

    if (failed == 0) {
        if (pthread_mutex_lock(&gate.lock) != 0) {
            failed = 3;
        } else {
            while (gate.waiting != worker_count) {
                if (pthread_cond_wait(&gate.changed, &gate.lock) != 0) {
                    failed = 4;
                    break;
                }
            }
            if (pthread_mutex_unlock(&gate.lock) != 0 && failed == 0)
                failed = 5;
        }
    }
    if (release_workers(&gate) != 0 && failed == 0)
        failed = 6;
    for (index = 0; index < created; index++) {
        void *result = (void *)(uintptr_t)1;

        if (pthread_join(workers[index], &result) != 0 || result != NULL)
            failed = 7;
    }
    if (pthread_cond_destroy(&gate.changed) != 0 && failed == 0)
        failed = 8;
    if (pthread_mutex_destroy(&gate.lock) != 0 && failed == 0)
        failed = 9;
    return failed;
}

int main(void)
{
    static const unsigned int worker_scales[] = { 1, 2, 4, 8 };
    unsigned int index;

    for (index = 0; index < sizeof(worker_scales) / sizeof(worker_scales[0]);
            index++) {
        if (run_worker_scale(worker_scales[index]) != 0)
            return (int)(index + 1);
    }
    puts("native mimalloc C ABI local worker scaling ok");
    return 0;
}
