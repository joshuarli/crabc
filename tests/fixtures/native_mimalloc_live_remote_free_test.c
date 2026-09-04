/*
 * A remains a live native allocator owner while independently attached B and
 * C each return one exact C-facing block. Both first read their respective
 * source-recorded usable extents, then wait until the coordinator releases
 * them together to publish through the source remote-free path. The static
 * live-owner route must serialize those two publications without exposing a
 * client registry. Each publisher completes its own no-page pthread
 * lifecycle, leaving A able to resume ordinary malloc work before A tears
 * down. The fixture intentionally does not prescribe an exact reuse order: a
 * local free-list block may precede the remote head.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>

struct live_remote_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t publish;
    pthread_cond_t released;
    unsigned char *remote[2];
    int owner_ready;
    int publishers_ready;
    int publish_now;
    int remote_released;
};

static struct live_remote_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    { NULL, NULL },
    0,
    0,
    0,
    0,
};

static void *owner_worker(void *opaque)
{
    unsigned char *first;
    unsigned char *second;
    unsigned char *local;
    unsigned char *first_resumed;
    unsigned char *second_resumed;

    (void)opaque;
    first = malloc(37);
    second = malloc(53);
    local = malloc(73);
    if (first == NULL || second == NULL || local == NULL)
        return (void *)(uintptr_t)1;
    first[0] = 0x41;
    first[36] = 0x42;
    second[0] = 0x43;
    second[52] = 0x44;
    local[0] = 0x45;
    local[72] = 0x46;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    state.remote[0] = first;
    state.remote[1] = second;
    state.owner_ready = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    while (state.remote_released != 2) {
        if (pthread_cond_wait(&state.released, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)4;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)5;

    /* B and C now own no client identity. A may resume normally; source
     * collection chooses when either remote-head entry joins A's local free
     * list. */
    first_resumed = malloc(37);
    second_resumed = malloc(53);
    if (first_resumed == NULL || second_resumed == NULL)
        return (void *)(uintptr_t)6;
    first_resumed[0] = 0x47;
    first_resumed[36] = 0x48;
    second_resumed[0] = 0x49;
    second_resumed[52] = 0x4a;
    if (first_resumed[0] != 0x47 || first_resumed[36] != 0x48
        || second_resumed[0] != 0x49 || second_resumed[52] != 0x4a
        || local[0] != 0x45 || local[72] != 0x46)
        return (void *)(uintptr_t)7;
    free(first_resumed);
    free(second_resumed);
    free(local);
    return NULL;
}

static void *releaser_worker(void *opaque)
{
    unsigned char *remote;
    unsigned int index = (unsigned int)(uintptr_t)opaque;
    size_t request;
    unsigned char first_byte;
    unsigned char last_byte;

    if (index > 1)
        return (void *)(uintptr_t)1;
    request = index == 0 ? 37 : 53;
    first_byte = index == 0 ? 0x41 : 0x43;
    last_byte = index == 0 ? 0x42 : 0x44;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    while (!state.owner_ready) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)3;
        }
    }
    remote = state.remote[index];
    if (remote == NULL || remote[0] != first_byte || remote[request - 1] != last_byte) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)4;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)5;

    if (malloc_usable_size(remote) < request)
        return (void *)(uintptr_t)6;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)7;
    state.publishers_ready += 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)8;
    }
    while (!state.publish_now) {
        if (pthread_cond_wait(&state.publish, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)9;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)10;

    free(remote);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)11;
    state.remote_released += 1;
    if (pthread_cond_broadcast(&state.released) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)12;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)13;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t releasers[2];
    void *result = (void *)(uintptr_t)8;
    unsigned char *after;

    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 1;
    if (pthread_create(&releasers[0], NULL, releaser_worker, (void *)(uintptr_t)0) != 0)
        return 2;
    if (pthread_create(&releasers[1], NULL, releaser_worker, (void *)(uintptr_t)1) != 0)
        return 3;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 4;
    while (!state.owner_ready || state.publishers_ready != 2) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return 5;
        }
    }
    state.publish_now = 1;
    if (pthread_cond_broadcast(&state.publish) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return 6;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 7;
    if (pthread_join(releasers[0], &result) != 0 || result != NULL)
        return 8;
    result = (void *)(uintptr_t)9;
    if (pthread_join(releasers[1], &result) != 0 || result != NULL)
        return 9;
    result = (void *)(uintptr_t)9;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 10;

    /* A's all-free collector and normal finish must restore ticket zero. */
    after = malloc(53);
    if (after == NULL)
        return 11;
    after[0] = 0x4b;
    after[52] = 0x4c;
    if (after[0] != 0x4b || after[52] != 0x4c)
        return 12;
    free(after);

    puts("native mimalloc live remote free ok");
    return 0;
}
