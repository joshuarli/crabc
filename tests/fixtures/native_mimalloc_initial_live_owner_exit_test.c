/*
 * The initial persistent owner keeps one client live while A leaves the
 * selected mixed owner-exit route behind. B receives only the ordinary C
 * addresses needed for free; its terminal pthread finish settles A's typed
 * route while the initial owner retains and later reuses its own client.
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

static void *release_worker(void *opaque)
{
    (void)opaque;
    if (shared_blocks.small == NULL || shared_blocks.non_direct_small == NULL
            || shared_blocks.medium == NULL || shared_blocks.large == NULL
            || shared_blocks.arena_singleton == NULL
            || shared_blocks.os_aligned == NULL)
        return (void *)(uintptr_t)1;
    if (shared_blocks.small[0] != 0x41 || shared_blocks.small[36] != 0x42
            || shared_blocks.non_direct_small[0] != 0x43
            || shared_blocks.non_direct_small[1024] != 0x44
            || shared_blocks.medium[0] != 0x45
            || shared_blocks.medium[64 * 1024 - 1] != 0x46
            || shared_blocks.large[0] != 0x47
            || shared_blocks.large[128 * 1024 - 1] != 0x48
            || shared_blocks.arena_singleton[0] != 0x49
            || shared_blocks.arena_singleton[1024 * 1024 - 1] != 0x4a
            || shared_blocks.os_aligned[0] != 0x4b
            || shared_blocks.os_aligned[6] != 0x4c)
        return (void *)(uintptr_t)2;
    if (malloc_usable_size(shared_blocks.small) < 37
            || malloc_usable_size(shared_blocks.non_direct_small) < 1025
            || malloc_usable_size(shared_blocks.medium) < 64 * 1024
            || malloc_usable_size(shared_blocks.large) < 128 * 1024
            || malloc_usable_size(shared_blocks.arena_singleton) < 1024 * 1024
            || malloc_usable_size(shared_blocks.os_aligned) < 7)
        return (void *)(uintptr_t)3;

    free(shared_blocks.os_aligned);
    free(shared_blocks.arena_singleton);
    free(shared_blocks.large);
    free(shared_blocks.medium);
    free(shared_blocks.non_direct_small);
    free(shared_blocks.small);
    shared_blocks.os_aligned = NULL;
    shared_blocks.arena_singleton = NULL;
    shared_blocks.large = NULL;
    shared_blocks.medium = NULL;
    shared_blocks.non_direct_small = NULL;
    shared_blocks.small = NULL;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)1;
    unsigned char *initial;
    unsigned char *after;

    initial = malloc(79);
    if (initial == NULL)
        return 1;
    initial[0] = 0x31;
    initial[78] = 0x32;

    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 2;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 3;
    result = (void *)(uintptr_t)4;
    if (pthread_create(&releaser, NULL, release_worker, NULL) != 0)
        return 4;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 5;

    if (initial[0] != 0x31 || initial[78] != 0x32
            || malloc_usable_size(initial) < 79)
        return 6;
    initial = realloc(initial, 151);
    if (initial == NULL)
        return 7;
    if (initial[0] != 0x31 || initial[78] != 0x32
            || malloc_usable_size(initial) < 151)
        return 8;
    initial[150] = 0x33;
    if (initial[150] != 0x33)
        return 9;
    free(initial);

    after = malloc(53);
    if (after == NULL)
        return 10;
    after[0] = 0x51;
    after[52] = 0x52;
    if (after[0] != 0x51 || after[52] != 0x52)
        return 11;
    free(after);

    puts("native mimalloc initial live owner exit ok");
    return 0;
}
