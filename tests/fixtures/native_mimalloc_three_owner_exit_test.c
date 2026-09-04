/*
 * Three independent workers leave the selected mixed owner-exit shape live
 * before any fresh releaser begins. This is the C ABI counterpart of the
 * private registry regression: each A owns an OS-aligned singleton linked in
 * the static main Heap's private abandoned list, but later B workers receive
 * only ordinary C addresses. The native route keeps all list, page, ledger,
 * and admission state private.
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

    /* This worker may unlink only the exact OS-list member that its opaque
     * route owns; the other detached routes remain live until their own B
     * worker runs and finishes. */
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

static int run_owner(struct owner_exit_blocks *blocks)
{
    pthread_t owner;
    void *result = (void *)(uintptr_t)1;

    if (pthread_create(&owner, NULL, owner_worker, blocks) != 0)
        return 1;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 2;
    return 0;
}

static int run_releaser(struct owner_exit_blocks *blocks)
{
    pthread_t releaser;
    void *result = (void *)(uintptr_t)1;

    if (pthread_create(&releaser, NULL, release_worker, blocks) != 0)
        return 1;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 2;
    return 0;
}

int main(void)
{
    struct owner_exit_blocks first = { .tag = 0x31 };
    struct owner_exit_blocks second = { .tag = 0x61 };
    struct owner_exit_blocks third = { .tag = 0x91 };
    unsigned char *after;

    /* All three A workers exit before any B begins. The third route must
     * append beside two live private OS-list members without exposing either
     * sibling's page or client identity. */
    if (run_owner(&first) != 0)
        return 1;
    if (run_owner(&second) != 0)
        return 2;
    if (run_owner(&third) != 0)
        return 3;

    /* Release in non-FIFO order. Each B's pthread finish releases only the
     * terminal proof coupled to its own route; the initial owner returns only
     * after the last of the three independent lifecycle transitions. */
    if (run_releaser(&third) != 0)
        return 4;
    if (run_releaser(&first) != 0)
        return 5;
    if (run_releaser(&second) != 0)
        return 6;

    after = malloc(53);
    if (after == NULL)
        return 7;
    after[0] = 0x71;
    after[52] = 0x72;
    if (after[0] != 0x71 || after[52] != 0x72)
        return 8;
    free(after);

    puts("native mimalloc three owner exit ok");
    return 0;
}
