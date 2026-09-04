/*
 * A leaves the selected mixed owner-exit aggregate live. B consumes only
 * nonterminal singleton/large members and completes its own pthread finish;
 * C must still consume the remaining exact C inputs and return the typed
 * terminal proof before ticket zero can reactivate. This is a serialized
 * lifecycle witness, not a concurrent free or pointer-routing interface.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct owner_exit_blocks {
    unsigned char *small;
    unsigned char *non_direct_small;
    unsigned char *medium;
    unsigned char *large;
    unsigned char *arena_singleton;
    unsigned char *os_aligned;
};

static struct owner_exit_blocks shared_blocks;

static void *owner_worker(void *opaque)
{
    (void)opaque;
    shared_blocks.small = malloc(37);
    shared_blocks.non_direct_small = malloc(1025);
    shared_blocks.medium = malloc(64 * 1024);
    shared_blocks.large = malloc(128 * 1024);
    shared_blocks.arena_singleton = malloc(1024 * 1024);
    shared_blocks.os_aligned = aligned_alloc(128 * 1024, 7);
    if (shared_blocks.small == NULL || shared_blocks.non_direct_small == NULL
            || shared_blocks.medium == NULL || shared_blocks.large == NULL
            || shared_blocks.arena_singleton == NULL
            || shared_blocks.os_aligned == NULL)
        return (void *)(uintptr_t)1;
    if ((uintptr_t)shared_blocks.os_aligned % (128 * 1024) != 0)
        return (void *)(uintptr_t)2;

    shared_blocks.small[0] = 0x41;
    shared_blocks.small[36] = 0x42;
    shared_blocks.non_direct_small[0] = 0x43;
    shared_blocks.non_direct_small[1024] = 0x44;
    shared_blocks.medium[0] = 0x45;
    shared_blocks.medium[64 * 1024 - 1] = 0x46;
    shared_blocks.large[0] = 0x47;
    shared_blocks.large[128 * 1024 - 1] = 0x48;
    shared_blocks.arena_singleton[0] = 0x49;
    shared_blocks.arena_singleton[1024 * 1024 - 1] = 0x4a;
    shared_blocks.os_aligned[0] = 0x4b;
    shared_blocks.os_aligned[6] = 0x4c;
    return NULL;
}

static void *nonterminal_releaser_worker(void *opaque)
{
    (void)opaque;
    if (shared_blocks.large == NULL || shared_blocks.arena_singleton == NULL
            || shared_blocks.os_aligned == NULL)
        return (void *)(uintptr_t)1;
    if (shared_blocks.large[0] != 0x47
            || shared_blocks.large[128 * 1024 - 1] != 0x48
            || shared_blocks.arena_singleton[0] != 0x49
            || shared_blocks.arena_singleton[1024 * 1024 - 1] != 0x4a
            || shared_blocks.os_aligned[0] != 0x4b
            || shared_blocks.os_aligned[6] != 0x4c)
        return (void *)(uintptr_t)2;
    if (malloc_usable_size(shared_blocks.large) < 128 * 1024
            || malloc_usable_size(shared_blocks.arena_singleton) < 1024 * 1024
            || malloc_usable_size(shared_blocks.os_aligned) < 7)
        return (void *)(uintptr_t)3;

    free(shared_blocks.os_aligned);
    free(shared_blocks.arena_singleton);
    free(shared_blocks.large);
    shared_blocks.os_aligned = NULL;
    shared_blocks.arena_singleton = NULL;
    shared_blocks.large = NULL;
    return NULL;
}

static void *terminal_releaser_worker(void *opaque)
{
    (void)opaque;
    if (shared_blocks.large != NULL || shared_blocks.arena_singleton != NULL
            || shared_blocks.os_aligned != NULL || shared_blocks.small == NULL
            || shared_blocks.non_direct_small == NULL || shared_blocks.medium == NULL)
        return (void *)(uintptr_t)1;
    if (shared_blocks.small[0] != 0x41 || shared_blocks.small[36] != 0x42
            || shared_blocks.non_direct_small[0] != 0x43
            || shared_blocks.non_direct_small[1024] != 0x44
            || shared_blocks.medium[0] != 0x45
            || shared_blocks.medium[64 * 1024 - 1] != 0x46)
        return (void *)(uintptr_t)2;
    if (malloc_usable_size(shared_blocks.small) < 37
            || malloc_usable_size(shared_blocks.non_direct_small) < 1025
            || malloc_usable_size(shared_blocks.medium) < 64 * 1024)
        return (void *)(uintptr_t)3;

    free(shared_blocks.medium);
    free(shared_blocks.non_direct_small);
    free(shared_blocks.small);
    shared_blocks.medium = NULL;
    shared_blocks.non_direct_small = NULL;
    shared_blocks.small = NULL;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t nonterminal_releaser;
    pthread_t terminal_releaser;
    void *result = (void *)(uintptr_t)1;
    unsigned char *after;

    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 1;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 2;
    result = (void *)(uintptr_t)3;
    if (pthread_create(&nonterminal_releaser, NULL,
            nonterminal_releaser_worker, NULL) != 0)
        return 3;
    if (pthread_join(nonterminal_releaser, &result) != 0 || result != NULL)
        return 4;
    result = (void *)(uintptr_t)5;
    if (pthread_create(&terminal_releaser, NULL,
            terminal_releaser_worker, NULL) != 0)
        return 5;
    if (pthread_join(terminal_releaser, &result) != 0 || result != NULL)
        return 6;

    after = malloc(53);
    if (after == NULL)
        return 7;
    after[0] = 0x51;
    after[52] = 0x52;
    if (after[0] != 0x51 || after[52] != 0x52)
        return 8;
    free(after);

    puts("native mimalloc post exit split releaser ok");
    return 0;
}
