/*
 * A deterministic one-worker condition-variable protocol.
 *
 * The parent and worker alternate ownership of one normal mutex. Each side
 * increments the same protected counter once per round, publishes the next
 * turn while holding the mutex, and signals the peer. The final value proves
 * that no wakeup was lost, duplicated, or observed without the mutex.
 */
#ifndef CRABC_PTHREAD_MUTEX_COND_PING_PONG_CONTRACT_H
#define CRABC_PTHREAD_MUTEX_COND_PING_PONG_CONTRACT_H

#include <pthread.h>
#include <stdint.h>

struct pthread_mutex_cond_ping_pong_state {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned long long rounds;
    uint64_t protected_value;
    int turn;
};

static void *pthread_mutex_cond_ping_pong_worker(void *opaque)
{
    struct pthread_mutex_cond_ping_pong_state *const state = opaque;

    if (pthread_mutex_lock(&state->mutex) != 0)
        return (void *)(uintptr_t)1;
    for (unsigned long long round = 0; round < state->rounds; ++round) {
        while (state->turn != 1) {
            if (pthread_cond_wait(&state->condition, &state->mutex) != 0) {
                (void)pthread_mutex_unlock(&state->mutex);
                return (void *)(uintptr_t)2;
            }
        }
        state->protected_value += 1;
        state->turn = 0;
        if (pthread_cond_signal(&state->condition) != 0) {
            (void)pthread_mutex_unlock(&state->mutex);
            return (void *)(uintptr_t)3;
        }
    }
    if (pthread_mutex_unlock(&state->mutex) != 0)
        return (void *)(uintptr_t)4;
    return NULL;
}

static int pthread_mutex_cond_ping_pong_run(unsigned long long rounds,
        uint64_t *observed)
{
    struct pthread_mutex_cond_ping_pong_state state;
    pthread_t worker;
    void *worker_result = NULL;

    if (pthread_mutex_init(&state.mutex, NULL) != 0)
        return 1;
    if (pthread_cond_init(&state.condition, NULL) != 0) {
        (void)pthread_mutex_destroy(&state.mutex);
        return 2;
    }
    state.rounds = rounds;
    state.protected_value = 0;
    state.turn = 0;
    if (pthread_create(&worker, NULL, pthread_mutex_cond_ping_pong_worker, &state) != 0) {
        (void)pthread_cond_destroy(&state.condition);
        (void)pthread_mutex_destroy(&state.mutex);
        return 3;
    }
    if (pthread_mutex_lock(&state.mutex) != 0)
        return 4;
    for (unsigned long long round = 0; round < rounds; ++round) {
        while (state.turn != 0) {
            if (pthread_cond_wait(&state.condition, &state.mutex) != 0) {
                (void)pthread_mutex_unlock(&state.mutex);
                return 5;
            }
        }
        state.protected_value += 1;
        state.turn = 1;
        if (pthread_cond_signal(&state.condition) != 0) {
            (void)pthread_mutex_unlock(&state.mutex);
            return 6;
        }
    }
    while (state.turn != 0) {
        if (pthread_cond_wait(&state.condition, &state.mutex) != 0) {
            (void)pthread_mutex_unlock(&state.mutex);
            return 7;
        }
    }
    if (pthread_mutex_unlock(&state.mutex) != 0)
        return 8;
    if (pthread_join(worker, &worker_result) != 0)
        return 9;
    if (worker_result != NULL)
        return 10;
    if (state.protected_value != rounds * 2U)
        return 11;
    if (pthread_cond_destroy(&state.condition) != 0)
        return 12;
    if (pthread_mutex_destroy(&state.mutex) != 0)
        return 13;
    *observed = state.protected_value;
    return 0;
}

#endif
