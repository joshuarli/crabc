/*
 * A native-shadow owner exits with more C clients than the historical inline
 * post-exit ledger. The blocks stay address-private to the runtime: B learns
 * them only because C `free` receives the exact addresses. Repeating the
 * cycle proves that B's terminal route release and its ordinary pthread
 * teardown return A's admission before ticket zero allocates again.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum {
    /*
     * Eighty 1 KiB direct-small requests fill the first 64 KiB source page
     * before this owner reaches the second page. The tail then adds
     * non-direct-small, medium, large, and arena-singleton members. The owner
     * therefore exits through one ordinary native session with an unchanged
     * full direct-small member, a later nonfull member in the same source bin,
     * and pages from the other regular source classes. This is not a bespoke
     * full-page route: the private ledger and the one aggregate
     * `_mi_theap_collect_abandon` traversal must account for every client.
     */
    DIRECT_SMALL_BLOCK_COUNT = 80,
    LIVE_BLOCK_COUNT = DIRECT_SMALL_BLOCK_COUNT + 4,
    OWNER_EXIT_EPOCHS = 8,
};

static unsigned char *shared_blocks[LIVE_BLOCK_COUNT];

static size_t block_size(size_t index)
{
    if (index < DIRECT_SMALL_BLOCK_COUNT)
        return 1024;
    switch (index - DIRECT_SMALL_BLOCK_COUNT) {
    case 0:
        return 1025;
    case 1:
        return 64 * 1024;
    case 2:
        return 128 * 1024;
    default:
        return 1024 * 1024;
    }
}

static void *owner_worker(void *opaque)
{
    size_t index;

    (void)opaque;
    for (index = 0; index < LIVE_BLOCK_COUNT; index++) {
        size_t size = block_size(index);

        shared_blocks[index] = malloc(size);
        if (shared_blocks[index] == NULL)
            return (void *)(uintptr_t)1;
        shared_blocks[index][0] = (unsigned char)(0x20 + index);
        shared_blocks[index][size - 1] = (unsigned char)(0x80 + index);
    }
    return NULL;
}

static void *release_worker(void *opaque)
{
    size_t index;

    (void)opaque;
    for (index = LIVE_BLOCK_COUNT; index != 0; index--) {
        size_t slot = index - 1;
        size_t size = block_size(slot);

        if (shared_blocks[slot] == NULL
                || shared_blocks[slot][0] != (unsigned char)(0x20 + slot)
                || shared_blocks[slot][size - 1] != (unsigned char)(0x80 + slot)
                || malloc_usable_size(shared_blocks[slot]) < size)
            return (void *)(uintptr_t)1;
        free(shared_blocks[slot]);
        shared_blocks[slot] = NULL;
    }
    return NULL;
}

int main(void)
{
    size_t epoch;

    for (epoch = 0; epoch < OWNER_EXIT_EPOCHS; epoch++) {
        pthread_t owner;
        pthread_t releaser;
        void *result = (void *)(uintptr_t)2;
        unsigned char *after;

        if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
            return 1;
        if (pthread_join(owner, &result) != 0 || result != NULL)
            return 2;
        if (pthread_create(&releaser, NULL, release_worker, NULL) != 0)
            return 3;
        result = (void *)(uintptr_t)4;
        if (pthread_join(releaser, &result) != 0 || result != NULL)
            return 4;

        after = malloc(53);
        if (after == NULL)
            return 5;
        after[0] = 0x51;
        after[52] = 0x52;
        if (after[0] != 0x51 || after[52] != 0x52)
            return 6;
        free(after);
    }

    puts("native mimalloc many owner-exit allocations ok");
    return 0;
}
