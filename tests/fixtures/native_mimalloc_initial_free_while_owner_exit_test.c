/*
 * Ticket zero frees its own live client while A's typed post-exit route is
 * still awaiting B.  A and B exchange only A's ordinary C address; the
 * initial operation must resume and re-park only ticket zero's own engine,
 * without releasing A's worker-admission claim or borrowing its route.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* This is the established mixed aggregate exit shape: it keeps the C
 * regression on the same source route already proved by the owner-exit
 * fixtures, rather than treating a sole-page geometry as this lifecycle
 * test's subject. */
struct owner_exit_blocks {
    unsigned char *small;
    unsigned char *non_direct_small;
    unsigned char *medium;
    unsigned char *large;
    unsigned char *arena_singleton;
    unsigned char *os_aligned;
};

static struct owner_exit_blocks owner_blocks;

static void *owner_worker(void *opaque)
{
    (void)opaque;
    owner_blocks.small = malloc(37);
    owner_blocks.non_direct_small = malloc(1025);
    owner_blocks.medium = malloc(64 * 1024);
    owner_blocks.large = malloc(128 * 1024);
    owner_blocks.arena_singleton = malloc(1024 * 1024);
    owner_blocks.os_aligned = aligned_alloc(128 * 1024, 7);
    if (owner_blocks.small == NULL || owner_blocks.non_direct_small == NULL
            || owner_blocks.medium == NULL || owner_blocks.large == NULL
            || owner_blocks.arena_singleton == NULL
            || owner_blocks.os_aligned == NULL)
        return (void *)(uintptr_t)1;
    if ((uintptr_t)owner_blocks.os_aligned % (128 * 1024) != 0)
        return (void *)(uintptr_t)2;
    owner_blocks.small[0] = 0x41;
    owner_blocks.small[36] = 0x42;
    owner_blocks.non_direct_small[0] = 0x43;
    owner_blocks.non_direct_small[1024] = 0x44;
    owner_blocks.medium[0] = 0x45;
    owner_blocks.medium[64 * 1024 - 1] = 0x46;
    owner_blocks.large[0] = 0x47;
    owner_blocks.large[128 * 1024 - 1] = 0x48;
    owner_blocks.arena_singleton[0] = 0x49;
    owner_blocks.arena_singleton[1024 * 1024 - 1] = 0x4a;
    owner_blocks.os_aligned[0] = 0x4b;
    owner_blocks.os_aligned[6] = 0x4c;
    return NULL;
}

static void *release_worker(void *opaque)
{
    (void)opaque;
    if (owner_blocks.small == NULL || owner_blocks.non_direct_small == NULL
            || owner_blocks.medium == NULL || owner_blocks.large == NULL
            || owner_blocks.arena_singleton == NULL
            || owner_blocks.os_aligned == NULL)
        return (void *)(uintptr_t)1;
    if (owner_blocks.small[0] != 0x41 || owner_blocks.small[36] != 0x42
            || owner_blocks.non_direct_small[0] != 0x43
            || owner_blocks.non_direct_small[1024] != 0x44
            || owner_blocks.medium[0] != 0x45
            || owner_blocks.medium[64 * 1024 - 1] != 0x46
            || owner_blocks.large[0] != 0x47
            || owner_blocks.large[128 * 1024 - 1] != 0x48
            || owner_blocks.arena_singleton[0] != 0x49
            || owner_blocks.arena_singleton[1024 * 1024 - 1] != 0x4a
            || owner_blocks.os_aligned[0] != 0x4b
            || owner_blocks.os_aligned[6] != 0x4c)
        return (void *)(uintptr_t)2;
    if (malloc_usable_size(owner_blocks.small) < 37
            || malloc_usable_size(owner_blocks.non_direct_small) < 1025
            || malloc_usable_size(owner_blocks.medium) < 64 * 1024
            || malloc_usable_size(owner_blocks.large) < 128 * 1024
            || malloc_usable_size(owner_blocks.arena_singleton) < 1024 * 1024
            || malloc_usable_size(owner_blocks.os_aligned) < 7)
        return (void *)(uintptr_t)3;
    free(owner_blocks.os_aligned);
    free(owner_blocks.arena_singleton);
    free(owner_blocks.large);
    free(owner_blocks.medium);
    free(owner_blocks.non_direct_small);
    free(owner_blocks.small);
    owner_blocks.os_aligned = NULL;
    owner_blocks.arena_singleton = NULL;
    owner_blocks.large = NULL;
    owner_blocks.medium = NULL;
    owner_blocks.non_direct_small = NULL;
    owner_blocks.small = NULL;
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

    /* A's route is still live. This exact initial client must be released
     * through ticket zero's re-parked engine without settling A's route. */
    {
        size_t initial_usable = malloc_usable_size(initial);

        if (initial[0] != 0x31 || initial[78] != 0x32 || initial_usable < 79)
            return 4;
    }
    free(initial);

    result = (void *)(uintptr_t)5;
    if (pthread_create(&releaser, NULL, release_worker, NULL) != 0)
        return 5;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 6;

    /* B's terminal pthread finish consumes A's proof. Ticket zero may then
     * allocate normally rather than treating the interleaving as a release. */
    after = malloc(53);
    if (after == NULL)
        return 7;
    after[0] = 0x51;
    after[52] = 0x52;
    if (after[0] != 0x51 || after[52] != 0x52)
        return 8;
    free(after);

    puts("native mimalloc initial free while owner exit ok");
    return 0;
}
