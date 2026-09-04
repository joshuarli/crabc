/*
 * Two live native worker sessions leave together.  Their A-side source exits
 * share the serialized PageMap transition, but each owns its distinct parked
 * scheduler token and deferred C route.  A peer that observes the short
 * `BUSY` handoff must wait and resume its own exact parked engine; it must not
 * turn a valid concurrent pthread exit into a retained process.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum { OWNER_COUNT = 2 };

struct owner_blocks {
    unsigned char *non_direct_small;
    unsigned char *medium;
    unsigned char *large;
    unsigned char *os_aligned;
};

struct concurrent_owner_exit_state {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned int arrived;
    int release;
    int failed;
};

static struct concurrent_owner_exit_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    0,
    0,
    0,
};

static struct owner_blocks owners[OWNER_COUNT];

static int allocate_owner_blocks(unsigned int index)
{
    struct owner_blocks *blocks = &owners[index];

    blocks->non_direct_small = malloc(1025);
    blocks->medium = malloc(64 * 1024);
    blocks->large = malloc(128 * 1024);
    blocks->os_aligned = aligned_alloc(128 * 1024, 7);
    if (blocks->non_direct_small == NULL || blocks->medium == NULL
            || blocks->large == NULL || blocks->os_aligned == NULL)
        return 1;
    if ((uintptr_t)blocks->os_aligned % (128 * 1024) != 0)
        return 2;

    blocks->non_direct_small[0] = (unsigned char)(0x20 + index);
    blocks->non_direct_small[1024] = (unsigned char)(0x30 + index);
    blocks->medium[0] = (unsigned char)(0x40 + index);
    blocks->medium[64 * 1024 - 1] = (unsigned char)(0x50 + index);
    blocks->large[0] = (unsigned char)(0x60 + index);
    blocks->large[128 * 1024 - 1] = (unsigned char)(0x70 + index);
    blocks->os_aligned[0] = (unsigned char)(0x80 + index);
    blocks->os_aligned[6] = (unsigned char)(0x90 + index);
    return 0;
}

static void *owner_worker(void *opaque)
{
    unsigned int index = (unsigned int)(uintptr_t)opaque;

    if (index >= OWNER_COUNT || allocate_owner_blocks(index) != 0) {
        if (pthread_mutex_lock(&state.lock) == 0) {
            state.failed = 1;
            (void)pthread_cond_broadcast(&state.changed);
            (void)pthread_mutex_unlock(&state.lock);
        }
        return (void *)(uintptr_t)1;
    }
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    state.arrived += 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)3;
    }
    while (!state.release && !state.failed) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)4;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)5;
    return state.failed ? (void *)(uintptr_t)6 : NULL;
}

static int verify_owner_blocks(unsigned int index)
{
    const struct owner_blocks *blocks = &owners[index];
    size_t non_direct_small_usable;
    size_t medium_usable;
    size_t large_usable;
    size_t os_aligned_usable;

    if (blocks->non_direct_small == NULL || blocks->medium == NULL
            || blocks->large == NULL || blocks->os_aligned == NULL)
        return 1;
    if (blocks->non_direct_small[0] != (unsigned char)(0x20 + index)
            || blocks->non_direct_small[1024] != (unsigned char)(0x30 + index)
            || blocks->medium[0] != (unsigned char)(0x40 + index)
            || blocks->medium[64 * 1024 - 1] != (unsigned char)(0x50 + index)
            || blocks->large[0] != (unsigned char)(0x60 + index)
            || blocks->large[128 * 1024 - 1] != (unsigned char)(0x70 + index)
            || blocks->os_aligned[0] != (unsigned char)(0x80 + index)
            || blocks->os_aligned[6] != (unsigned char)(0x90 + index))
        return 2;
    non_direct_small_usable = malloc_usable_size(blocks->non_direct_small);
    medium_usable = malloc_usable_size(blocks->medium);
    large_usable = malloc_usable_size(blocks->large);
    os_aligned_usable = malloc_usable_size(blocks->os_aligned);
    if (non_direct_small_usable < 1025
            || medium_usable < 64 * 1024
            || large_usable < 128 * 1024
            || os_aligned_usable < 7)
        return 3;
    return 0;
}

static void *release_worker(void *opaque)
{
    unsigned int index = (unsigned int)(uintptr_t)opaque;
    struct owner_blocks *blocks;
    int verification;

    if (index >= OWNER_COUNT)
        return (void *)(uintptr_t)1;
    verification = verify_owner_blocks(index);
    if (verification != 0)
        return (void *)(uintptr_t)1;
    blocks = &owners[index];
    free(blocks->os_aligned);
    free(blocks->large);
    free(blocks->medium);
    free(blocks->non_direct_small);
    blocks->os_aligned = NULL;
    blocks->large = NULL;
    blocks->medium = NULL;
    blocks->non_direct_small = NULL;
    return NULL;
}

int main(void)
{
    pthread_t first_owner;
    pthread_t second_owner;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)1;
    unsigned char *bookkeeping;
    unsigned char *after;
    unsigned int index;

    if (pthread_create(&first_owner, NULL, owner_worker, (void *)(uintptr_t)0) != 0)
        return 1;
    if (pthread_create(&second_owner, NULL, owner_worker, (void *)(uintptr_t)1) != 0)
        return 2;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 3;
    while (state.arrived != OWNER_COUNT && !state.failed) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return 4;
        }
    }
    if (state.failed) {
        (void)pthread_mutex_unlock(&state.lock);
        return 5;
    }
    state.release = 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return 6;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 7;
    if (pthread_join(first_owner, &result) != 0 || result != NULL)
        return 8;
    result = (void *)(uintptr_t)9;
    if (pthread_join(second_owner, &result) != 0 || result != NULL)
        return 9;

    /* The joined A routes retain their separate admission claims, but neither
     * owns ticket zero's next ordinary operation. */
    bookkeeping = calloc(2, sizeof(*bookkeeping));
    if (bookkeeping == NULL)
        return 10;
    bookkeeping[0] = 0xa1;
    bookkeeping[1] = 0xa2;
    if (bookkeeping[0] != 0xa1 || bookkeeping[1] != 0xa2)
        return 11;
    free(bookkeeping);

    for (index = 0; index < OWNER_COUNT; index++) {
        if (pthread_create(&releaser, NULL, release_worker,
                (void *)(uintptr_t)index) != 0)
            return 12;
        result = (void *)(uintptr_t)13;
        if (pthread_join(releaser, &result) != 0 || result != NULL)
            return 13;
    }

    after = malloc(53);
    if (after == NULL)
        return 14;
    after[0] = 0xb1;
    after[52] = 0xb2;
    if (after[0] != 0xb1 || after[52] != 0xb2)
        return 15;
    free(after);

    puts("native mimalloc concurrent owner exit ok");
    return 0;
}
