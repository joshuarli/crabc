/*
 * A leaves one medium client in the typed post-exit route. B creates its own
 * live direct-small/medium pair, lets D source-publish the small client, then
 * terminally frees A's medium. B therefore holds A's terminal proof while it
 * still must source-collect its own small client and detach its own medium
 * into a successor route. Fresh C may free only that successor medium.
 *
 * This is a serialized successor-lifecycle witness. It does not create a
 * general route chain or pointer registry: D receives B's one source client,
 * B receives A's one route client, and C receives B's one successor client.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct post_exit_source_published_successor_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t published;
    unsigned char *first_medium;
    unsigned char *published_small;
    unsigned char *successor_medium;
    int successor_ready;
    int small_published;
};

static struct post_exit_source_published_successor_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    NULL,
    NULL,
    NULL,
    0,
    0,
};

static void *first_owner_worker(void *opaque)
{
    unsigned char *medium;

    (void)opaque;
    medium = malloc(64 * 1024);
    if (medium == NULL)
        return (void *)(uintptr_t)1;
    medium[0] = 0x41;
    medium[64 * 1024 - 1] = 0x42;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    state.first_medium = medium;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)3;
    return NULL;
}

static void *successor_owner_worker(void *opaque)
{
    unsigned char *published_small;
    unsigned char *successor_medium;
    unsigned char *first_medium;

    (void)opaque;
    published_small = malloc(37);
    successor_medium = malloc(64 * 1024);
    if (published_small == NULL || successor_medium == NULL)
        return (void *)(uintptr_t)1;
    published_small[0] = 0x51;
    published_small[36] = 0x52;
    successor_medium[0] = 0x53;
    successor_medium[64 * 1024 - 1] = 0x54;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    first_medium = state.first_medium;
    if (first_medium == NULL) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    state.published_small = published_small;
    state.successor_medium = successor_medium;
    state.successor_ready = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)4;
    }
    while (!state.small_published) {
        if (pthread_cond_wait(&state.published, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)5;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)6;

    if (successor_medium[0] != 0x53 || successor_medium[64 * 1024 - 1] != 0x54)
        return (void *)(uintptr_t)7;
    /* B's own session is parked, so this confirms that it can query and then
     * terminally free A's exact address without borrowing either route.
     */
    if (first_medium[0] != 0x41 || first_medium[64 * 1024 - 1] != 0x42
            || malloc_usable_size(first_medium) < 64 * 1024)
        return (void *)(uintptr_t)8;
    free(first_medium);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)9;
    state.first_medium = NULL;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)10;

    /* A's terminal proof is now retained in B TLS. B deliberately performs
     * no further local operation: its pthread finish must source-collect
     * `published_small`, detach only `successor_medium`, and then settle A's
     * proof after B's own Theap/TLD has crossed the source boundary. */
    return NULL;
}

static void *source_publisher_worker(void *opaque)
{
    unsigned char *published_small;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    while (!state.successor_ready) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)2;
        }
    }
    published_small = state.published_small;
    if (published_small == NULL || published_small[0] != 0x51
            || published_small[36] != 0x52) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)4;

    if (malloc_usable_size(published_small) < 37)
        return (void *)(uintptr_t)5;
    free(published_small);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)6;
    state.published_small = NULL;
    state.small_published = 1;
    if (pthread_cond_broadcast(&state.published) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)7;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)8;
    return NULL;
}

static void *successor_releaser_worker(void *opaque)
{
    unsigned char *successor_medium;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    successor_medium = state.successor_medium;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    if (successor_medium == NULL || successor_medium[0] != 0x53
            || successor_medium[64 * 1024 - 1] != 0x54
            || malloc_usable_size(successor_medium) < 64 * 1024)
        return (void *)(uintptr_t)3;

    free(successor_medium);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)4;
    state.successor_medium = NULL;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)5;
    return NULL;
}

int main(void)
{
    pthread_t first_owner;
    pthread_t successor_owner;
    pthread_t publisher;
    pthread_t successor_releaser;
    void *result = (void *)(uintptr_t)1;
    unsigned char *after;

    if (pthread_create(&first_owner, NULL, first_owner_worker, NULL) != 0)
        return 1;
    if (pthread_join(first_owner, &result) != 0 || result != NULL)
        return 2;
    if (pthread_create(&successor_owner, NULL, successor_owner_worker, NULL) != 0)
        return 3;
    if (pthread_create(&publisher, NULL, source_publisher_worker, NULL) != 0)
        return 4;
    if (pthread_join(publisher, &result) != 0 || result != NULL)
        return 5;
    result = (void *)(uintptr_t)6;
    if (pthread_join(successor_owner, &result) != 0 || result != NULL)
        return 6;
    if (pthread_create(&successor_releaser, NULL, successor_releaser_worker, NULL) != 0)
        return 7;
    result = (void *)(uintptr_t)8;
    if (pthread_join(successor_releaser, &result) != 0 || result != NULL)
        return 8;

    /* C's normal finish must release B's successor admission before the
     * initial owner can resume from the dormant process pair. */
    after = malloc(53);
    if (after == NULL)
        return 9;
    after[0] = 0x61;
    after[52] = 0x62;
    if (after[0] != 0x61 || after[52] != 0x62)
        return 10;
    free(after);

    puts("native mimalloc post exit source published successor ok");
    return 0;
}
