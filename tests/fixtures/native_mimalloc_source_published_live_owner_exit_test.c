/*
 * A owns two ordinary C allocations. B source-publishes the direct-small
 * client and A then exits without another allocator operation while a distinct
 * medium client remains live. The native owner-exit traversal must collect the
 * source-published head privately, publish only the medium client to its typed
 * post-exit route, and keep A's admission until fresh C frees that exact
 * remaining address and completes its own ordinary pthread lifecycle.
 *
 * This is a serialized lifecycle witness, not a general pointer route: B sees
 * the one source-published C address and C sees only the independent live C
 * address. Neither receives an allocator, page, or route capability.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct source_published_live_owner_exit_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t released;
    unsigned char *published;
    unsigned char *live;
    int owner_ready;
    int published_released;
};

static struct source_published_live_owner_exit_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    NULL,
    NULL,
    0,
    0,
};

static void *owner_worker(void *opaque)
{
    unsigned char *published;
    unsigned char *live;

    (void)opaque;
    published = malloc(37);
    live = malloc(64 * 1024);
    if (published == NULL || live == NULL)
        return (void *)(uintptr_t)1;
    published[0] = 0x41;
    published[36] = 0x42;
    live[0] = 0x43;
    live[64 * 1024 - 1] = 0x44;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    state.published = published;
    state.live = live;
    state.owner_ready = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    while (!state.published_released) {
        if (pthread_cond_wait(&state.released, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)4;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)5;

    /* B has placed `published` on A's source remote head. A intentionally
     * performs no ordinary allocator operation now: its pthread destructor
     * must collect that head before it detaches `live` into the private route.
     */
    if (live[0] != 0x43 || live[64 * 1024 - 1] != 0x44)
        return (void *)(uintptr_t)6;
    return NULL;
}

static void *source_publisher_worker(void *opaque)
{
    unsigned char *published;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    while (!state.owner_ready) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)2;
        }
    }
    published = state.published;
    if (published == NULL || published[0] != 0x41 || published[36] != 0x42) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)4;

    if (malloc_usable_size(published) < 37)
        return (void *)(uintptr_t)5;
    free(published);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)6;
    state.published = NULL;
    state.published_released = 1;
    if (pthread_cond_broadcast(&state.released) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)7;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)8;
    return NULL;
}

static void *post_exit_releaser_worker(void *opaque)
{
    unsigned char *live;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    live = state.live;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    if (live == NULL || live[0] != 0x43 || live[64 * 1024 - 1] != 0x44)
        return (void *)(uintptr_t)3;
    if (malloc_usable_size(live) < 64 * 1024)
        return (void *)(uintptr_t)4;

    /* C reaches only A's independently live C address through the typed
     * post-exit boundary. The source-published address was consumed by A.
     */
    free(live);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)5;
    state.live = NULL;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)6;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t publisher;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)1;
    unsigned char *after;

    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 1;
    if (pthread_create(&publisher, NULL, source_publisher_worker, NULL) != 0)
        return 2;
    if (pthread_join(publisher, &result) != 0 || result != NULL)
        return 3;
    result = (void *)(uintptr_t)4;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 4;
    if (pthread_create(&releaser, NULL, post_exit_releaser_worker, NULL) != 0)
        return 5;
    result = (void *)(uintptr_t)6;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 6;

    /* C's terminal route free and normal finish must release A's admission
     * before ticket zero can resume ordinary initial-thread allocation. */
    after = malloc(53);
    if (after == NULL)
        return 7;
    after[0] = 0x51;
    after[52] = 0x52;
    if (after[0] != 0x51 || after[52] != 0x52)
        return 8;
    free(after);

    puts("native mimalloc source published live owner exit ok");
    return 0;
}
