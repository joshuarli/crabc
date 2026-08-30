/*
 * A owns one live native allocation while B first establishes its own parked
 * native session. B then returns A's exact pointer through the source remote
 * producer path and continues to free its own local block. This is the
 * boundary exercised by upstream test-stress.c once two allocation workers
 * exchange pointers: the receiving worker is not a fresh no-page publisher.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct live_remote_from_parked_worker_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t released;
    unsigned char *remote;
    int owner_ready;
    int releaser_ready;
    int remote_released;
};

static struct live_remote_from_parked_worker_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    NULL,
    0,
    0,
    0,
};

static void *owner_worker(void *opaque)
{
    unsigned char *remote;
    unsigned char *local;
    unsigned char *probe;

    (void)opaque;
    /* B publishes its own parked owner first, so A's later entry sits at the
     * registry head. B must still be able to hold A's route while it resumes
     * its own older parked session for the source publication below. */
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    while (!state.releaser_ready) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)2;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)3;

    remote = malloc(37);
    local = malloc(73);
    if (remote == NULL || local == NULL)
        return (void *)(uintptr_t)4;
    remote[0] = 0x41;
    remote[36] = 0x42;
    local[0] = 0x43;
    local[72] = 0x44;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)5;
    state.remote = remote;
    state.owner_ready = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)6;
    }
    while (!state.remote_released) {
        if (pthread_cond_wait(&state.released, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)7;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)8;

    /* B's source publication restored A to its normal parked session. */
    probe = malloc(37);
    if (probe == NULL)
        return (void *)(uintptr_t)9;
    probe[0] = 0x45;
    probe[36] = 0x46;
    if (probe[0] != 0x45 || probe[36] != 0x46
        || local[0] != 0x43 || local[72] != 0x44)
        return (void *)(uintptr_t)10;
    free(probe);
    free(local);
    return NULL;
}

static void *releaser_worker(void *opaque)
{
    unsigned char *remote;
    unsigned char *local;

    (void)opaque;
    /* This creates and publishes B's independent native session before A's
     * entry exists. The head ordering is deliberate: A's route will be BUSY
     * while B reclaims this older local session. */
    local = malloc(89);
    if (local == NULL)
        return (void *)(uintptr_t)1;
    local[0] = 0x51;
    local[88] = 0x52;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    state.releaser_ready = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    while (!state.owner_ready) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)4;
        }
    }
    remote = state.remote;
    if (remote == NULL || remote[0] != 0x41 || remote[36] != 0x42) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)5;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)6;

    free(remote);

    if (local[0] != 0x51 || local[88] != 0x52)
        return (void *)(uintptr_t)7;
    free(local);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)8;
    state.remote_released = 1;
    if (pthread_cond_broadcast(&state.released) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)9;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)10;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)10;
    unsigned char *after;

    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 1;
    if (pthread_create(&releaser, NULL, releaser_worker, NULL) != 0)
        return 2;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 3;
    result = (void *)(uintptr_t)11;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 4;

    after = malloc(53);
    if (after == NULL)
        return 5;
    after[0] = 0x61;
    after[52] = 0x62;
    if (after[0] != 0x61 || after[52] != 0x62)
        return 6;
    free(after);

    puts("native mimalloc live remote from parked worker ok");
    return 0;
}
