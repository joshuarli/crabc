/*
 * A keeps a native allocator session parked while B returns one exact client
 * through the source remote-free path. A then resumes to collect that remote
 * head and exits with a distinct regular pair still live. C can only reach
 * those final clients through the existing opaque post-exit route.
 *
 * This composes the existing live-owner and owner-exit paths; it does not add
 * a new C pointer registry or an owner-exit route for this workload shape.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>

struct live_remote_owner_exit_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t released;
    unsigned char *remote;
    unsigned char *medium;
    unsigned char *resumed;
    int owner_ready;
    int remote_released;
};

static struct live_remote_owner_exit_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    NULL,
    NULL,
    NULL,
    0,
    0,
};

static int reset_state(void)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return 0;
    state.remote = NULL;
    state.medium = NULL;
    state.resumed = NULL;
    state.owner_ready = 0;
    state.remote_released = 0;
    return pthread_mutex_unlock(&state.lock) == 0;
}

static void *owner_worker(void *opaque)
{
    unsigned char *remote;
    unsigned char *medium;
    unsigned char *resumed;

    (void)opaque;
    remote = malloc(37);
    medium = malloc(64 * 1024);
    if (remote == NULL || medium == NULL)
        return (void *)(uintptr_t)1;
    remote[0] = 0x41;
    remote[36] = 0x42;
    medium[0] = 0x43;
    medium[64 * 1024 - 1] = 0x44;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    state.remote = remote;
    state.medium = medium;
    state.owner_ready = 1;
    if (pthread_cond_signal(&state.ready) != 0) {
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

    /* A's normal parked-session operation must collect B's remote head
     * before it can cross owner exit. Keep this new small client and the
     * medium client live so C later consumes the same general aggregate. */
    resumed = malloc(37);
    if (resumed == NULL)
        return (void *)(uintptr_t)6;
    resumed[0] = 0x45;
    resumed[36] = 0x46;
    if (medium[0] != 0x43 || medium[64 * 1024 - 1] != 0x44)
        return (void *)(uintptr_t)7;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)8;
    state.resumed = resumed;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)9;
    return NULL;
}

static void *live_releaser_worker(void *opaque)
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
    if (pthread_cond_signal(&state.released) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)7;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)8;
    return NULL;
}

static void *post_exit_releaser_worker(void *opaque)
{
    unsigned char *medium;
    unsigned char *resumed;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    medium = state.medium;
    resumed = state.resumed;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    if (medium == NULL || resumed == NULL)
        return (void *)(uintptr_t)3;
    if (medium[0] != 0x43 || medium[64 * 1024 - 1] != 0x44
            || resumed[0] != 0x45 || resumed[36] != 0x46)
        return (void *)(uintptr_t)4;
    if (malloc_usable_size(medium) < 64 * 1024
            || malloc_usable_size(resumed) < 37)
        return (void *)(uintptr_t)5;

    free(medium);
    free(resumed);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)6;
    state.medium = NULL;
    state.resumed = NULL;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)7;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t live_releaser;
    pthread_t post_exit_releaser;
    void *result = (void *)(uintptr_t)1;
    unsigned char *after;

    for (unsigned int round = 0; round < 3; ++round) {
        if (!reset_state())
            return 1;
        if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
            return 2;
        if (pthread_create(&live_releaser, NULL, live_releaser_worker, NULL) != 0)
            return 3;
        if (pthread_join(live_releaser, &result) != 0 || result != NULL)
            return 4;
        result = (void *)(uintptr_t)2;
        if (pthread_join(owner, &result) != 0 || result != NULL)
            return 5;
        if (pthread_create(&post_exit_releaser, NULL, post_exit_releaser_worker, NULL) != 0)
            return 6;
        result = (void *)(uintptr_t)3;
        if (pthread_join(post_exit_releaser, &result) != 0 || result != NULL)
            return 7;
    }

    /* C's final route free and normal no-page finish must return ticket zero
     * before the initial owner can allocate again. */
    after = malloc(53);
    if (after == NULL)
        return 8;
    after[0] = 0x47;
    after[52] = 0x48;
    if (after[0] != 0x47 || after[52] != 0x48)
        return 9;
    free(after);

    puts("native mimalloc live remote owner exit ok");
    return 0;
}
