/*
 * A owns two same-sized live blocks. Two B producers reach one explicit
 * user-space start gate, each returns a distinct block through ordinary
 * free(), and A resumes only after both source publications complete. A then
 * creates two same-sized live replacements before exiting with those blocks
 * and a medium block still live. C frees that final owner-exit image only
 * through ordinary free().
 *
 * The two replacements must remain distinct while simultaneously live. That
 * catches a remote-head loss or duplicate consumption that returns one block
 * twice, while the full-byte patterns catch prefix corruption before and after
 * the owner-exit transition. The fixture intentionally uses no allocator
 * hooks, handles, or private lifecycle interface.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum {
    LIVE_PRODUCER_COUNT = 2,
    LIVE_REMOTE_REQUEST = 37,
    RESUMED_BLOCK_COUNT = 2,
    MEDIUM_REQUEST = 64 * 1024,
    OWNER_EXIT_EPOCHS = 8,
};

struct live_remote_owner_exit_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t release;
    unsigned char *remote[LIVE_PRODUCER_COUNT];
    unsigned char *resumed[RESUMED_BLOCK_COUNT];
    unsigned char *medium;
    int owner_ready;
    int live_producers_ready;
    int release_live_producers;
    int remote_released;
    int failure;
};

static struct live_remote_owner_exit_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    { NULL, NULL },
    { NULL, NULL },
    NULL,
    0,
    0,
    0,
    0,
    0,
};

static unsigned char pattern_byte(unsigned char seed, size_t index)
{
    return (unsigned char)(seed + (unsigned char)(index * 37U + 11U));
}

static void fill_pattern(unsigned char *block, size_t size, unsigned char seed)
{
    size_t index;

    for (index = 0; index < size; index++)
        block[index] = pattern_byte(seed, index);
}

static int pattern_matches(const unsigned char *block, size_t size, unsigned char seed)
{
    size_t index;

    for (index = 0; index < size; index++) {
        if (block[index] != pattern_byte(seed, index))
            return 0;
    }
    return 1;
}

static unsigned char remote_seed(unsigned int producer)
{
    return (unsigned char)(0x41 + producer * 0x10U);
}

static unsigned char resumed_seed(unsigned int index)
{
    return (unsigned char)(0x61 + index * 0x10U);
}

static int is_remote_source(
    const unsigned char *block,
    const uintptr_t remote_addresses[LIVE_PRODUCER_COUNT])
{
    unsigned int index;
    uintptr_t address = (uintptr_t)block;

    for (index = 0; index < LIVE_PRODUCER_COUNT; index++) {
        if (address == remote_addresses[index])
            return 1;
    }
    return 0;
}

static void report_failure(void)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return;
    state.failure = 1;
    (void)pthread_cond_broadcast(&state.ready);
    (void)pthread_cond_broadcast(&state.release);
    (void)pthread_mutex_unlock(&state.lock);
}

static int reset_state(void)
{
    unsigned int index;
    int clean = 1;

    if (pthread_mutex_lock(&state.lock) != 0)
        return 0;
    for (index = 0; index < LIVE_PRODUCER_COUNT; index++) {
        if (state.remote[index] != NULL)
            clean = 0;
        state.remote[index] = NULL;
    }
    for (index = 0; index < RESUMED_BLOCK_COUNT; index++) {
        if (state.resumed[index] != NULL)
            clean = 0;
        state.resumed[index] = NULL;
    }
    if (state.medium != NULL)
        clean = 0;
    state.medium = NULL;
    state.owner_ready = 0;
    state.live_producers_ready = 0;
    state.release_live_producers = 0;
    state.remote_released = 0;
    state.failure = 0;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 0;
    return clean;
}

static void *owner_worker(void *opaque)
{
    unsigned char *remote[LIVE_PRODUCER_COUNT];
    unsigned char *resumed[RESUMED_BLOCK_COUNT];
    uintptr_t remote_addresses[LIVE_PRODUCER_COUNT];
    unsigned char *medium;
    unsigned int index;

    (void)opaque;
    for (index = 0; index < LIVE_PRODUCER_COUNT; index++) {
        remote[index] = malloc(LIVE_REMOTE_REQUEST);
        if (remote[index] == NULL)
            return (void *)(uintptr_t)1;
        remote_addresses[index] = (uintptr_t)remote[index];
        fill_pattern(remote[index], LIVE_REMOTE_REQUEST, remote_seed(index));
    }
    if (remote[0] == remote[1])
        return (void *)(uintptr_t)2;

    medium = malloc(MEDIUM_REQUEST);
    if (medium == NULL)
        return (void *)(uintptr_t)3;
    fill_pattern(medium, MEDIUM_REQUEST, 0x51);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)4;
    for (index = 0; index < LIVE_PRODUCER_COUNT; index++)
        state.remote[index] = remote[index];
    state.medium = medium;
    state.owner_ready = 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)5;
    }
    while (state.remote_released != LIVE_PRODUCER_COUNT && !state.failure) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)6;
        }
    }
    if (state.failure) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)7;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)8;

    /* Both source remote heads are now eligible for A's normal collection.
     * Keep two replacements live at once and require their address set to
     * equal the source set: a lost head cannot be hidden by a fresh block and
     * an accidental duplicate free cannot hand one address to both calls. */
    for (index = 0; index < RESUMED_BLOCK_COUNT; index++) {
        resumed[index] = malloc(LIVE_REMOTE_REQUEST);
        if (resumed[index] == NULL)
            return (void *)(uintptr_t)9;
        fill_pattern(resumed[index], LIVE_REMOTE_REQUEST, resumed_seed(index));
    }
    if (resumed[0] == resumed[1]
            || !is_remote_source(resumed[0], remote_addresses)
            || !is_remote_source(resumed[1], remote_addresses)
            || !pattern_matches(medium, MEDIUM_REQUEST, 0x51)
            || !pattern_matches(resumed[0], LIVE_REMOTE_REQUEST, resumed_seed(0))
            || !pattern_matches(resumed[1], LIVE_REMOTE_REQUEST, resumed_seed(1)))
        return (void *)(uintptr_t)10;

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)11;
    for (index = 0; index < RESUMED_BLOCK_COUNT; index++)
        state.resumed[index] = resumed[index];
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)12;
    return NULL;
}

static void *live_releaser_worker(void *opaque)
{
    unsigned int producer = (unsigned int)(uintptr_t)opaque;
    unsigned char *remote;

    if (producer >= LIVE_PRODUCER_COUNT)
        return (void *)(uintptr_t)1;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    while (!state.owner_ready && !state.failure) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)3;
        }
    }
    if (state.failure) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)4;
    }
    remote = state.remote[producer];
    if (remote == NULL) {
        (void)pthread_mutex_unlock(&state.lock);
        report_failure();
        return (void *)(uintptr_t)5;
    }
    state.live_producers_ready += 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)6;
    }
    while (!state.release_live_producers && !state.failure) {
        if (pthread_cond_wait(&state.release, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)7;
        }
    }
    if (state.failure) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)8;
    }
    /* Reserve this exact C client before the public free. The owner still
     * waits for the post-free count below, so it cannot resume merely because
     * a producer has claimed an address. */
    if (state.remote[producer] != remote) {
        (void)pthread_mutex_unlock(&state.lock);
        report_failure();
        return (void *)(uintptr_t)9;
    }
    state.remote[producer] = NULL;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)10;

    if (!pattern_matches(remote, LIVE_REMOTE_REQUEST, remote_seed(producer))) {
        report_failure();
        return (void *)(uintptr_t)11;
    }
    free(remote);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)12;
    state.remote_released += 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)13;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)14;
    return NULL;
}

static void *post_exit_releaser_worker(void *opaque)
{
    unsigned char *medium;
    unsigned char *resumed[RESUMED_BLOCK_COUNT];
    unsigned int index;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    medium = state.medium;
    for (index = 0; index < RESUMED_BLOCK_COUNT; index++)
        resumed[index] = state.resumed[index];
    if (medium == NULL || resumed[0] == NULL || resumed[1] == NULL)
        goto unlock_failure;
    if (!pattern_matches(medium, MEDIUM_REQUEST, 0x51)
            || !pattern_matches(resumed[0], LIVE_REMOTE_REQUEST, resumed_seed(0))
            || !pattern_matches(resumed[1], LIVE_REMOTE_REQUEST, resumed_seed(1)))
        goto unlock_failure;

    /* C is the sole post-exit consumer after joining A. Reserve the image
     * before free so no fixture state compares a pointer after its lifetime
     * ends. */
    if (state.medium != medium
            || state.resumed[0] != resumed[0]
            || state.resumed[1] != resumed[1])
        goto unlock_failure;
    state.medium = NULL;
    for (index = 0; index < RESUMED_BLOCK_COUNT; index++)
        state.resumed[index] = NULL;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)2;

    free(medium);
    for (index = 0; index < RESUMED_BLOCK_COUNT; index++)
        free(resumed[index]);
    return NULL;

unlock_failure:
    (void)pthread_mutex_unlock(&state.lock);
    return (void *)(uintptr_t)3;
}

int main(void)
{
    unsigned int round;
    unsigned int producer;

    for (round = 0; round < OWNER_EXIT_EPOCHS; round++) {
        pthread_t owner;
        pthread_t live_releasers[LIVE_PRODUCER_COUNT];
        pthread_t post_exit_releaser;
        void *result = (void *)(uintptr_t)1;

        if (!reset_state())
            return 1;
        if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
            return 2;
        for (producer = 0; producer < LIVE_PRODUCER_COUNT; producer++) {
            if (pthread_create(&live_releasers[producer], NULL, live_releaser_worker,
                    (void *)(uintptr_t)producer) != 0)
                return 3;
        }

        if (pthread_mutex_lock(&state.lock) != 0)
            return 4;
        while (state.live_producers_ready != LIVE_PRODUCER_COUNT && !state.failure) {
            if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
                (void)pthread_mutex_unlock(&state.lock);
                return 5;
            }
        }
        if (state.failure) {
            (void)pthread_mutex_unlock(&state.lock);
            return 6;
        }
        state.release_live_producers = 1;
        if (pthread_cond_broadcast(&state.release) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return 7;
        }
        if (pthread_mutex_unlock(&state.lock) != 0)
            return 8;

        for (producer = 0; producer < LIVE_PRODUCER_COUNT; producer++) {
            result = (void *)(uintptr_t)9;
            if (pthread_join(live_releasers[producer], &result) != 0 || result != NULL)
                return 9;
        }
        result = (void *)(uintptr_t)10;
        if (pthread_join(owner, &result) != 0 || result != NULL)
            return 10;

        if (pthread_create(&post_exit_releaser, NULL, post_exit_releaser_worker, NULL) != 0)
            return 11;
        result = (void *)(uintptr_t)12;
        if (pthread_join(post_exit_releaser, &result) != 0 || result != NULL)
            return 12;
        if (!reset_state())
            return 13;
    }

    /* The post-exit final release and releaser teardown must leave the initial
     * thread able to make an ordinary allocator call. */
    {
        unsigned char *after = malloc(53);

        if (after == NULL)
            return 14;
        fill_pattern(after, 53, 0x71);
        if (!pattern_matches(after, 53, 0x71))
            return 15;
        free(after);
    }

    puts("native mimalloc live remote multi-producer owner exit ok");
    return 0;
}
