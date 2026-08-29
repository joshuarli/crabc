/*
 * Two independent workers leave the selected mixed owner-exit shape live
 * before either fresh releaser begins.  This specifically exercises the
 * bounded native two-route publication: A2 must be able to detach while A1's
 * opaque route still owns its OS-aligned singleton in the static main Heap's
 * private abandoned list.  The releasers receive only ordinary C addresses;
 * the native route keeps all page, list, ledger, and admission facts private.
 */
#include <pthread.h>
#include <stdint.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>

struct owner_exit_blocks {
    unsigned char tag;
    unsigned char *small;
    unsigned char *non_direct_small;
    unsigned char *medium;
    unsigned char *large;
    unsigned char *arena_singleton;
    unsigned char *os_aligned;
};

static int allocate_owner_exit_blocks(struct owner_exit_blocks *blocks,
        unsigned char tag)
{
    blocks->small = malloc(37);
    /* 1025 is just above the native direct-cache boundary. */
    blocks->non_direct_small = malloc(1025);
    blocks->medium = malloc(64 * 1024);
    blocks->large = malloc(128 * 1024);
    blocks->arena_singleton = malloc(1024 * 1024);
    /* This enters the aggregate's OS-singleton terminal tail. */
    blocks->os_aligned = aligned_alloc(128 * 1024, 7);
    if (blocks->small == NULL || blocks->non_direct_small == NULL
            || blocks->medium == NULL || blocks->large == NULL
            || blocks->arena_singleton == NULL || blocks->os_aligned == NULL)
        return 1;
    if ((uintptr_t)blocks->os_aligned % (128 * 1024) != 0)
        return 2;

    blocks->small[0] = tag;
    blocks->small[36] = (unsigned char)(tag + 1);
    blocks->non_direct_small[0] = (unsigned char)(tag + 2);
    blocks->non_direct_small[1024] = (unsigned char)(tag + 3);
    blocks->medium[0] = (unsigned char)(tag + 4);
    blocks->medium[64 * 1024 - 1] = (unsigned char)(tag + 5);
    blocks->large[0] = (unsigned char)(tag + 6);
    blocks->large[128 * 1024 - 1] = (unsigned char)(tag + 7);
    blocks->arena_singleton[0] = (unsigned char)(tag + 8);
    blocks->arena_singleton[1024 * 1024 - 1] = (unsigned char)(tag + 9);
    blocks->os_aligned[0] = (unsigned char)(tag + 10);
    blocks->os_aligned[6] = (unsigned char)(tag + 11);
    return 0;
}

static int verify_owner_exit_blocks(const struct owner_exit_blocks *blocks,
        unsigned char tag)
{
    if (blocks->small == NULL || blocks->non_direct_small == NULL
            || blocks->medium == NULL || blocks->large == NULL
            || blocks->arena_singleton == NULL || blocks->os_aligned == NULL)
        return 1;
    if (blocks->small[0] != tag || blocks->small[36] != (unsigned char)(tag + 1)
            || blocks->non_direct_small[0] != (unsigned char)(tag + 2)
            || blocks->non_direct_small[1024] != (unsigned char)(tag + 3)
            || blocks->medium[0] != (unsigned char)(tag + 4)
            || blocks->medium[64 * 1024 - 1] != (unsigned char)(tag + 5)
            || blocks->large[0] != (unsigned char)(tag + 6)
            || blocks->large[128 * 1024 - 1] != (unsigned char)(tag + 7)
            || blocks->arena_singleton[0] != (unsigned char)(tag + 8)
            || blocks->arena_singleton[1024 * 1024 - 1] != (unsigned char)(tag + 9)
            || blocks->os_aligned[0] != (unsigned char)(tag + 10)
            || blocks->os_aligned[6] != (unsigned char)(tag + 11))
        return 2;
    if (malloc_usable_size(blocks->small) < 37
            || malloc_usable_size(blocks->non_direct_small) < 1025
            || malloc_usable_size(blocks->medium) < 64 * 1024
            || malloc_usable_size(blocks->large) < 128 * 1024
            || malloc_usable_size(blocks->arena_singleton) < 1024 * 1024
            || malloc_usable_size(blocks->os_aligned) < 7)
        return 3;
    return 0;
}

static void *owner_worker(void *opaque)
{
    struct owner_exit_blocks *blocks = opaque;
    unsigned char tag = blocks == NULL ? 0 : blocks->tag;

    if (blocks == NULL || allocate_owner_exit_blocks(blocks, tag) != 0)
        return (void *)(uintptr_t)1;
    return NULL;
}

static void *release_worker(void *opaque)
{
    struct owner_exit_blocks *blocks = opaque;
    unsigned char tag = blocks == NULL ? 0 : blocks->tag;

    if (blocks == NULL || verify_owner_exit_blocks(blocks, tag) != 0)
        return (void *)(uintptr_t)1;

    /* Free A1's OS member while A2's newer member is still linked. This
     * proves each opaque route removes only its own exact private-list node. */
    free(blocks->os_aligned);
    free(blocks->arena_singleton);
    free(blocks->large);
    free(blocks->medium);
    free(blocks->non_direct_small);
    free(blocks->small);
    blocks->os_aligned = NULL;
    blocks->arena_singleton = NULL;
    blocks->large = NULL;
    blocks->medium = NULL;
    blocks->non_direct_small = NULL;
    blocks->small = NULL;
    return NULL;
}

int main(void)
{
    struct owner_exit_blocks first = { .tag = 0x31 };
    struct owner_exit_blocks second = { .tag = 0x61 };
    pthread_t owner;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)1;
    unsigned char *after;

    /* Joining A1 does not release its native worker-admission proof: its
     * typed route remains live until its fresh B finishes. A2 must therefore
     * install the second bounded route while the first one owns its OS list
     * member. */
    if (pthread_create(&owner, NULL, owner_worker, &first) != 0)
        return 1;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 2;
    result = (void *)(uintptr_t)3;
    if (pthread_create(&owner, NULL, owner_worker, &second) != 0)
        return 3;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 4;

    if (pthread_create(&releaser, NULL, release_worker, &first) != 0)
        return 5;
    result = (void *)(uintptr_t)6;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 6;
    if (pthread_create(&releaser, NULL, release_worker, &second) != 0)
        return 7;
    result = (void *)(uintptr_t)8;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 8;

    /* Both typed terminal completions have now reached their own B no-page
     * finish, so the initial worker may use the dormant ticket-zero pair. */
    after = malloc(53);
    if (after == NULL)
        return 9;
    after[0] = 0x71;
    after[52] = 0x72;
    if (after[0] != 0x71 || after[52] != 0x72)
        return 10;
    free(after);

    puts("native mimalloc two owner exit ok");
    return 0;
}
