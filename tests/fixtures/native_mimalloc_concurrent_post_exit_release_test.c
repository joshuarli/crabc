/*
 * A leaves a genuinely mixed native owner-exit image behind. Several fresh B
 * workers are released together and each frees a disjoint subset of A's C
 * clients. The runtime may serialize source PageMap mutation internally, but
 * it must not require one preselected releaser or leak the terminal proof:
 * the B that releases the final client owns that proof until its normal
 * pthread finish, while every earlier B finishes normally on its own.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum {
    /* Eighty 1 KiB clients cross the first direct-small source page before
     * reaching a second page. The remaining entries give the aggregate its
     * non-direct-small, medium, large, arena-singleton, and OS-singleton
     * tails. */
    DIRECT_SMALL_BLOCK_COUNT = 80,
    NON_DIRECT_SMALL_INDEX = DIRECT_SMALL_BLOCK_COUNT,
    MEDIUM_INDEX = NON_DIRECT_SMALL_INDEX + 1,
    LARGE_INDEX = MEDIUM_INDEX + 1,
    ARENA_SINGLETON_INDEX = LARGE_INDEX + 1,
    OS_SINGLETON_INDEX = ARENA_SINGLETON_INDEX + 1,
    LIVE_BLOCK_COUNT = OS_SINGLETON_INDEX + 1,
    RELEASER_COUNT = 4,
    OWNER_EXIT_EPOCHS = 8,
};

static unsigned char *shared_blocks[LIVE_BLOCK_COUNT];
static pthread_barrier_t release_barrier;

static size_t block_size(size_t index)
{
    if (index < DIRECT_SMALL_BLOCK_COUNT)
        return 1024;
    switch (index) {
    case NON_DIRECT_SMALL_INDEX:
        return 1025;
    case MEDIUM_INDEX:
        return 64 * 1024;
    case LARGE_INDEX:
        return 128 * 1024;
    case ARENA_SINGLETON_INDEX:
        return 1024 * 1024;
    default:
        return 7;
    }
}

static void *owner_worker(void *opaque)
{
    size_t index;

    (void)opaque;
    for (index = 0; index < LIVE_BLOCK_COUNT; index++) {
        size_t size = block_size(index);

        if (index == OS_SINGLETON_INDEX)
            shared_blocks[index] = aligned_alloc(128 * 1024, size);
        else
            shared_blocks[index] = malloc(size);
        if (shared_blocks[index] == NULL)
            return (void *)(uintptr_t)1;
        if (index == OS_SINGLETON_INDEX
                && (uintptr_t)shared_blocks[index] % (128 * 1024) != 0)
            return (void *)(uintptr_t)2;
        shared_blocks[index][0] = (unsigned char)(0x20 + index);
        shared_blocks[index][size - 1] = (unsigned char)(0x80 + index);
    }
    return NULL;
}

static void *release_worker(void *opaque)
{
    size_t index;
    unsigned int releaser = (unsigned int)(uintptr_t)opaque;

    int barrier = pthread_barrier_wait(&release_barrier);
    if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD)
        return (void *)(uintptr_t)1;

    for (index = releaser; index < LIVE_BLOCK_COUNT; index += RELEASER_COUNT) {
        size_t size = block_size(index);
        unsigned char *block = shared_blocks[index];

        if (block == NULL || block[0] != (unsigned char)(0x20 + index)
                || block[size - 1] != (unsigned char)(0x80 + index)
                || malloc_usable_size(block) < size)
            return (void *)(uintptr_t)5;
        free(block);
        shared_blocks[index] = NULL;
    }
    return NULL;
}

int main(void)
{
    size_t epoch;

    if (pthread_barrier_init(&release_barrier, NULL, RELEASER_COUNT + 1) != 0)
        return 1;
    for (epoch = 0; epoch < OWNER_EXIT_EPOCHS; epoch++) {
        pthread_t owner;
        pthread_t releasers[RELEASER_COUNT];
        void *result = (void *)(uintptr_t)1;
        unsigned int releaser;
        unsigned char *after;

        if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
            return 2;
        if (pthread_join(owner, &result) != 0 || result != NULL)
            return 3;

        for (releaser = 0; releaser < RELEASER_COUNT; releaser++) {
            if (pthread_create(&releasers[releaser], NULL, release_worker,
                    (void *)(uintptr_t)releaser) != 0)
                return 4;
        }
        int barrier = pthread_barrier_wait(&release_barrier);
        if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD)
            return 5;

        for (releaser = 0; releaser < RELEASER_COUNT; releaser++) {
            result = (void *)(uintptr_t)9;
            if (pthread_join(releasers[releaser], &result) != 0 || result != NULL)
                return 9;
        }
        for (size_t index = 0; index < LIVE_BLOCK_COUNT; index++) {
            if (shared_blocks[index] != NULL)
                return 10;
        }

        /* Every nonterminal B has already finished, and the B holding the
         * typed final proof has now passed its own native finish boundary. */
        after = malloc(53);
        if (after == NULL)
            return 11;
        after[0] = 0x51;
        after[52] = 0x52;
        if (after[0] != 0x51 || after[52] != 0x52)
            return 12;
        free(after);
    }
    if (pthread_barrier_destroy(&release_barrier) != 0)
        return 13;

    puts("native mimalloc concurrent post-exit release ok");
    return 0;
}
