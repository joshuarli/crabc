/*
 * A exits with a mixed ordinary C allocation image.  Its direct-small sibling
 * keeps source exit on the aggregate route, while two live 64 KiB clients and
 * one returned same-page spare leave a final mapped regular member that the
 * fresh B may reclaim only through the runtime's opaque exact-free route.
 *
 * B receives raw C addresses solely because `free` receives them. It never
 * receives an allocator, page identity, or reclaim handle; the candidate must
 * retain A's admission until B has terminally released the route and finished
 * its own pthread lifecycle.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum { medium_request = 64 * 1024 };

struct aggregate_reclaim_blocks {
    unsigned char *direct_small;
    unsigned char *first_medium;
    unsigned char *final_medium;
};

static struct aggregate_reclaim_blocks shared_blocks;

static void *owner_worker(void *opaque)
{
    unsigned char *spare_medium;

    (void)opaque;
    shared_blocks.direct_small = malloc(37);
    shared_blocks.first_medium = malloc(medium_request);
    shared_blocks.final_medium = malloc(medium_request);
    spare_medium = malloc(medium_request);
    if (shared_blocks.direct_small == NULL || shared_blocks.first_medium == NULL
            || shared_blocks.final_medium == NULL || spare_medium == NULL)
        return (void *)(uintptr_t)1;

    shared_blocks.direct_small[0] = 0x41;
    shared_blocks.direct_small[36] = 0x42;
    shared_blocks.first_medium[0] = 0x43;
    shared_blocks.first_medium[medium_request - 1] = 0x44;
    shared_blocks.final_medium[0] = 0x45;
    shared_blocks.final_medium[medium_request - 1] = 0x46;

    /* Keep two medium clients live while returning the third. Source owner
     * exit force-collects this deferred local block before it abandons the
     * still-live page. */
    free(spare_medium);
    return NULL;
}

static void *release_worker(void *opaque)
{
    (void)opaque;
    if (shared_blocks.direct_small == NULL || shared_blocks.first_medium == NULL
            || shared_blocks.final_medium == NULL)
        return (void *)(uintptr_t)1;
    if (shared_blocks.direct_small[0] != 0x41
            || shared_blocks.direct_small[36] != 0x42
            || shared_blocks.first_medium[0] != 0x43
            || shared_blocks.first_medium[medium_request - 1] != 0x44
            || shared_blocks.final_medium[0] != 0x45
            || shared_blocks.final_medium[medium_request - 1] != 0x46)
        return (void *)(uintptr_t)2;

    free(shared_blocks.direct_small);
    free(shared_blocks.first_medium);
    free(shared_blocks.final_medium);
    shared_blocks.direct_small = NULL;
    shared_blocks.first_medium = NULL;
    shared_blocks.final_medium = NULL;
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
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 2;
    if (pthread_create(&releaser, NULL, release_worker, NULL) != 0)
        return 3;
    result = (void *)(uintptr_t)4;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 4;

    /* B's terminal free is not enough: its normal pthread finish must also
     * settle the runtime completion before ticket zero can allocate again. */
    after = malloc(73);
    if (after == NULL)
        return 5;
    after[0] = 0x51;
    after[72] = 0x52;
    if (after[0] != 0x51 || after[72] != 0x52)
        return 6;
    free(after);

    puts("native mimalloc aggregate reclaim ok");
    return 0;
}
