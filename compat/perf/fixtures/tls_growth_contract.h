/*
 * Dynamic TLS growth for a thread that predates every dlopen.
 *
 * Each DSO has its own TLS module and one common entry point. The parent loads
 * all modules after the worker is waiting, initializes its own instances, then
 * releases the worker. The worker must observe every module initializer in its
 * newly grown TLS block and write only its own instances. The parent verifies
 * that its values survived, then unloads the modules after the worker exits.
 */
#ifndef CRABC_TLS_GROWTH_CONTRACT_H
#define CRABC_TLS_GROWTH_CONTRACT_H

#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

enum { TLS_GROWTH_MAX_MODULES = 8 };

typedef int *(*tls_growth_slot_fn)(void);

struct tls_growth_state {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned int module_count;
    int command;
    int worker_status;
    tls_growth_slot_fn slots[TLS_GROWTH_MAX_MODULES];
};

static void *tls_growth_worker(void *opaque)
{
    struct tls_growth_state *const state = opaque;

    if (pthread_mutex_lock(&state->mutex) != 0)
        return (void *)(uintptr_t)1;
    while (state->command == 0) {
        if (pthread_cond_wait(&state->condition, &state->mutex) != 0) {
            (void)pthread_mutex_unlock(&state->mutex);
            return (void *)(uintptr_t)2;
        }
    }
    if (state->command < 0) {
        (void)pthread_mutex_unlock(&state->mutex);
        return NULL;
    }
    for (unsigned int index = 0; index < state->module_count; ++index) {
        int *const slot = state->slots[index]();
        if (slot == NULL || *slot != 100 + (int)index) {
            fprintf(stderr, "dynamic TLS worker index=%u value=%d\n", index,
                slot == NULL ? -1 : *slot);
            state->worker_status = 1;
            break;
        }
        *slot = 2000 + (int)index;
    }
    if (pthread_mutex_unlock(&state->mutex) != 0)
        return (void *)(uintptr_t)3;
    return NULL;
}

static void tls_growth_close_handles(void *handles[TLS_GROWTH_MAX_MODULES],
        unsigned int count)
{
    while (count > 0) {
        --count;
        if (handles[count] != NULL)
            (void)dlclose(handles[count]);
    }
}

static int tls_growth_stop_worker(struct tls_growth_state *state, pthread_t worker)
{
    if (pthread_mutex_lock(&state->mutex) != 0)
        return 1;
    state->command = -1;
    if (pthread_cond_broadcast(&state->condition) != 0) {
        (void)pthread_mutex_unlock(&state->mutex);
        return 2;
    }
    if (pthread_mutex_unlock(&state->mutex) != 0)
        return 3;
    return pthread_join(worker, NULL) == 0 ? 0 : 4;
}

static int tls_growth_run(const char *directory, unsigned int module_count,
        uint64_t *observed)
{
    struct tls_growth_state state;
    void *handles[TLS_GROWTH_MAX_MODULES] = {0};
    pthread_t worker;
    void *worker_result = NULL;

    if (directory == NULL || module_count == 0 || module_count > TLS_GROWTH_MAX_MODULES)
        return 1;
    if (pthread_mutex_init(&state.mutex, NULL) != 0)
        return 2;
    if (pthread_cond_init(&state.condition, NULL) != 0) {
        (void)pthread_mutex_destroy(&state.mutex);
        return 3;
    }
    state.module_count = module_count;
    state.command = 0;
    state.worker_status = 0;
    if (pthread_create(&worker, NULL, tls_growth_worker, &state) != 0) {
        (void)pthread_cond_destroy(&state.condition);
        (void)pthread_mutex_destroy(&state.mutex);
        return 4;
    }
    for (unsigned int index = 0; index < module_count; ++index) {
        char path[PATH_MAX];
        const int path_length = snprintf(path, sizeof(path),
            "%s/libbench_tls_growth_%u.so", directory, index);
        if (path_length < 0 || (unsigned int)path_length >= sizeof(path)) {
            (void)tls_growth_stop_worker(&state, worker);
            tls_growth_close_handles(handles, index);
            return 5;
        }
        handles[index] = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (handles[index] == NULL) {
            (void)tls_growth_stop_worker(&state, worker);
            tls_growth_close_handles(handles, index);
            return 6;
        }
        state.slots[index] = (tls_growth_slot_fn)dlsym(handles[index], "tls_growth_slot");
        if (state.slots[index] == NULL || state.slots[index]() == NULL
                || *state.slots[index]() != 100 + (int)index) {
            (void)tls_growth_stop_worker(&state, worker);
            tls_growth_close_handles(handles, index + 1);
            return 7;
        }
        *state.slots[index]() = 1000 + (int)index;
    }
    if (pthread_mutex_lock(&state.mutex) != 0)
        return 8;
    state.command = 1;
    if (pthread_cond_signal(&state.condition) != 0) {
        (void)pthread_mutex_unlock(&state.mutex);
        return 9;
    }
    if (pthread_mutex_unlock(&state.mutex) != 0)
        return 10;
    if (pthread_join(worker, &worker_result) != 0)
        return 11;
    if (worker_result != NULL)
        return 12;
    if (state.worker_status != 0)
        return 13;
    for (unsigned int index = 0; index < module_count; ++index) {
        if (*state.slots[index]() != 1000 + (int)index)
            return 14;
    }
    tls_growth_close_handles(handles, module_count);
    if (pthread_cond_destroy(&state.condition) != 0)
        return 15;
    if (pthread_mutex_destroy(&state.mutex) != 0)
        return 16;
    *observed = module_count;
    return 0;
}

#endif
