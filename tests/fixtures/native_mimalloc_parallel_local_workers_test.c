/*
 * A owns the one parked native live-owner route while B owns a distinct
 * parked native session containing only B's local C allocation.  No pointer
 * crosses between workers: the point is that the one static raw-TLS route is
 * not mistaken for a process-wide worker admission lock.  Both sessions are
 * simultaneously parked before B frees its own block and A later frees its
 * own block, after which ticket zero must resume normally.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct parallel_local_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t release;
    int owner_ready;
    int worker_parked;
    int release_worker;
    int worker_finished;
};

static struct parallel_local_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    0,
    0,
    0,
    0,
};

static void *owner_worker(void *opaque)
{
    unsigned char *local;

    (void)opaque;
    local = malloc(37);
    if (local == NULL)
        return (void *)(uintptr_t)1;
    local[0] = 0x31;
    local[36] = 0x32;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    state.owner_ready = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    while (!state.worker_finished) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)4;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)5;

    if (local[0] != 0x31 || local[36] != 0x32)
        return (void *)(uintptr_t)6;
    free(local);
    return NULL;
}

static void *local_worker(void *opaque)
{
    unsigned char *local;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    while (!state.owner_ready) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)2;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)3;

    /* A has already published its live route. B must still receive a local
     * C allocation and park its independent page engine rather than retaining
     * the process because B cannot become a second remote-free owner. */
    local = malloc(73);
    if (local == NULL)
        return (void *)(uintptr_t)4;
    local[0] = 0x41;
    local[72] = 0x42;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)5;
    state.worker_parked = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)6;
    }
    while (!state.release_worker) {
        if (pthread_cond_wait(&state.release, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)7;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)8;

    if (local[0] != 0x41 || local[72] != 0x42)
        return (void *)(uintptr_t)9;
    free(local);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)10;
    state.worker_finished = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)11;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)12;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t worker;
    void *result = (void *)(uintptr_t)13;
    unsigned char *after;

    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 1;
    if (pthread_create(&worker, NULL, local_worker, NULL) != 0)
        return 2;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 3;
    while (!state.owner_ready || !state.worker_parked) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return 4;
        }
    }
    state.release_worker = 1;
    if (pthread_cond_broadcast(&state.release) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return 5;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 6;
    if (pthread_join(worker, &result) != 0 || result != NULL)
        return 7;
    result = (void *)(uintptr_t)14;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 8;

    after = malloc(53);
    if (after == NULL)
        return 9;
    after[0] = 0x51;
    after[52] = 0x52;
    if (after[0] != 0x51 || after[52] != 0x52)
        return 10;
    free(after);

    puts("native mimalloc parallel local workers ok");
    return 0;
}
