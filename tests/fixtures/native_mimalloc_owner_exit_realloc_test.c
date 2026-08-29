/*
 * The native shadow deliberately has no B-side allocator after A exits with
 * a live client. A post-exit realloc must therefore fail without consuming
 * the source client; B can still observe and free the original allocation.
 *
 * This is a selected-shadow contract fixture, not a musl differential test:
 * musl is free to service the realloc from B's normal allocator, whereas the
 * bounded native route intentionally waits for a future allocate/copy/free
 * lifecycle before supporting that transition.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned char *shared_medium;

static void *owner_worker(void *opaque)
{
    (void)opaque;
    shared_medium = malloc(64 * 1024);
    if (shared_medium == NULL)
        return (void *)(uintptr_t)1;
    shared_medium[0] = 0x61;
    shared_medium[64 * 1024 - 1] = 0x62;
    return NULL;
}

static void *release_worker(void *opaque)
{
    unsigned char *replacement;

    (void)opaque;
    if (shared_medium == NULL)
        return (void *)(uintptr_t)1;
    errno = 0;
    replacement = realloc(shared_medium, 4096);
    if (replacement != NULL)
        return (void *)(uintptr_t)2;
    if (errno != ENOMEM)
        return (void *)(uintptr_t)3;
    if (shared_medium[0] != 0x61
            || shared_medium[64 * 1024 - 1] != 0x62)
        return (void *)(uintptr_t)4;
    free(shared_medium);
    shared_medium = NULL;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)5;
    unsigned char *after;

    for (unsigned int round = 0; round < 3; ++round) {
        if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
            return 1;
        if (pthread_join(owner, &result) != 0 || result != NULL)
            return 2;
        if (pthread_create(&releaser, NULL, release_worker, NULL) != 0)
            return 3;
        result = (void *)(uintptr_t)6;
        if (pthread_join(releaser, &result) != 0 || result != NULL)
            return 4;
    }

    after = malloc(53);
    if (after == NULL)
        return 5;
    after[0] = 0x63;
    after[52] = 0x64;
    if (after[0] != 0x63 || after[52] != 0x64)
        return 6;
    free(after);

    puts("native mimalloc owner exit realloc unavailable ok");
    return 0;
}
