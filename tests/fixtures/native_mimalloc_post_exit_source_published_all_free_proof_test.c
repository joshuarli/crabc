/*
 * A leaves one medium client in the typed post-exit route. B has one
 * direct-small client source-published by D, terminally frees A's medium,
 * and then performs no further allocator operation. B therefore holds A's
 * terminal proof while B itself must leave through the source all-free drain.
 * Only after that drain and B's own attachment teardown may B settle A's
 * proof and let ticket zero resume.
 *
 * This is a serialized lifecycle witness, not a route chain or pointer
 * registry: D receives B's one source client, B receives A's one route
 * client, and neither worker can select a route or retain an allocator.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct post_exit_source_published_all_free_proof_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t published;
    unsigned char *first_medium;
    unsigned char *published_small;
    int small_ready;
    int small_published;
};

static struct post_exit_source_published_all_free_proof_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
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

static void *proof_holder_worker(void *opaque)
{
    unsigned char *published_small;
    unsigned char *first_medium;

    (void)opaque;
    published_small = malloc(37);
    if (published_small == NULL)
        return (void *)(uintptr_t)1;
    published_small[0] = 0x51;
    published_small[36] = 0x52;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    first_medium = state.first_medium;
    if (first_medium == NULL) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    state.published_small = published_small;
    state.small_ready = 1;
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

    /* D now owns B's only local client through B's source remote head. B
     * can read A's captured PageMap extent and terminally free only A's exact
     * routed client. */
    if (first_medium[0] != 0x41 || first_medium[64 * 1024 - 1] != 0x42
            || malloc_usable_size(first_medium) < 64 * 1024)
        return (void *)(uintptr_t)7;
    free(first_medium);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)8;
    state.first_medium = NULL;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)9;

    /* B holds A's terminal proof, but makes no allocator call here. Its
     * native pthread finish must source-collect `published_small`, tear down
     * B's own attachment, and only then settle A's proof. */
    return NULL;
}

static void *source_publisher_worker(void *opaque)
{
    unsigned char *published_small;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    while (!state.small_ready) {
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

int main(void)
{
    pthread_t first_owner;
    pthread_t proof_holder;
    pthread_t publisher;
    void *result = (void *)(uintptr_t)1;
    unsigned char *after;

    if (pthread_create(&first_owner, NULL, first_owner_worker, NULL) != 0)
        return 1;
    if (pthread_join(first_owner, &result) != 0 || result != NULL)
        return 2;
    if (pthread_create(&proof_holder, NULL, proof_holder_worker, NULL) != 0)
        return 3;
    if (pthread_create(&publisher, NULL, source_publisher_worker, NULL) != 0)
        return 4;
    if (pthread_join(publisher, &result) != 0 || result != NULL)
        return 5;
    result = (void *)(uintptr_t)6;
    if (pthread_join(proof_holder, &result) != 0 || result != NULL)
        return 6;

    /* B's all-free drain and normal finish must settle both B and A before
     * the initial owner may resume its dormant process pair. */
    after = malloc(53);
    if (after == NULL)
        return 7;
    after[0] = 0x61;
    after[52] = 0x62;
    if (after[0] != 0x61 || after[52] != 0x62)
        return 8;
    free(after);

    puts("native mimalloc post exit source published all free proof ok");
    return 0;
}
