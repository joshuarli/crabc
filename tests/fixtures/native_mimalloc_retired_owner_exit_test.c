/*
 * A locally retires a direct-small page, then exits with one medium client
 * still live. The native source traversal must release the retired page in
 * its prepass before B can consume the typed route for the surviving client.
 * This is a serialized source-order witness, not a new owner-exit shape or
 * pointer-routing interface.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned char *shared_medium;

static void *owner_worker(void *opaque)
{
    unsigned char *retired_direct_small;

    (void)opaque;
    retired_direct_small = malloc(37);
    shared_medium = malloc(64 * 1024);
    if (retired_direct_small == NULL || shared_medium == NULL)
        return (void *)(uintptr_t)1;

    shared_medium[0] = 0x41;
    shared_medium[64 * 1024 - 1] = 0x42;
    /* The later medium allocation is in another source bin, so this ordinary
     * local free leaves the direct-small page retired through A's exit. */
    free(retired_direct_small);
    return NULL;
}

static void *releaser_worker(void *opaque)
{
    (void)opaque;
    if (shared_medium == NULL)
        return (void *)(uintptr_t)1;
    if (shared_medium[0] != 0x41 || shared_medium[64 * 1024 - 1] != 0x42)
        return (void *)(uintptr_t)2;
    if (malloc_usable_size(shared_medium) < 64 * 1024)
        return (void *)(uintptr_t)3;

    free(shared_medium);
    shared_medium = NULL;
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
    result = (void *)(uintptr_t)3;
    if (pthread_create(&releaser, NULL, releaser_worker, NULL) != 0)
        return 3;
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

    puts("native mimalloc retired owner exit ok");
    return 0;
}
