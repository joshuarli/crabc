/*
 * A owns one ordinary direct-small C allocation while B publishes that exact
 * client to A's source remote head.  A then exits without another local
 * allocation or free.  Its pthread destructor must therefore recognize that
 * the session is still page-bearing, force-collect B's remote head through
 * the typed all-free drain, and release its admission only after the page and
 * attachment teardown complete.  This is a lifecycle witness, not a general
 * cross-thread pointer route: B receives the one C address only to query and
 * free it, and no allocator or page capability crosses the boundary.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct source_published_exit_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t released;
    unsigned char *remote;
    int owner_ready;
    int remote_released;
};

static struct source_published_exit_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    NULL,
    0,
    0,
};

static void *owner_worker(void *opaque)
{
    unsigned char *remote;

    (void)opaque;
    remote = malloc(37);
    if (remote == NULL)
        return (void *)(uintptr_t)1;
    remote[0] = 0x41;
    remote[36] = 0x42;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    state.remote = remote;
    state.owner_ready = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    while (!state.remote_released) {
        if (pthread_cond_wait(&state.released, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)4;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)5;

    /* B has published the exact client to A's atomic source head.  A owns no
     * locally live client now, but its normal pthread finish must still run
     * the source all-free drain rather than the no-page finalizer. */
    return NULL;
}

static void *releaser_worker(void *opaque)
{
    unsigned char *remote;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    while (!state.owner_ready) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)2;
        }
    }
    remote = state.remote;
    if (remote == NULL || remote[0] != 0x41 || remote[36] != 0x42) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)4;

    if (malloc_usable_size(remote) < 37)
        return (void *)(uintptr_t)5;
    free(remote);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)6;
    state.remote = NULL;
    state.remote_released = 1;
    if (pthread_cond_broadcast(&state.released) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)7;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)8;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)1;
    unsigned char *after;

    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 1;
    if (pthread_create(&releaser, NULL, releaser_worker, NULL) != 0)
        return 2;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 3;
    result = (void *)(uintptr_t)4;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 4;

    /* The only observable postcondition is that A's typed all-free drain and
     * normal pthread teardown returned ticket zero to its dormant owner. */
    after = malloc(53);
    if (after == NULL)
        return 5;
    after[0] = 0x51;
    after[52] = 0x52;
    if (after[0] != 0x51 || after[52] != 0x52)
        return 6;
    free(after);

    puts("native mimalloc source published exit ok");
    return 0;
}
