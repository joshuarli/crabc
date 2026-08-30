/*
 * A exits with one source-shaped sole mapped-medium route. B's exact
 * `realloc` cannot reuse A's torn-down Theap, so the selected native shadow
 * must privately allocate and record a normal B client, copy the bounded
 * prefix, then terminally free A's exact client through the typed route.
 *
 * This is a selected-shadow lifecycle fixture, not a general cross-thread
 * realloc claim. Its synchronized A/B handoff also proves that a rejected
 * replacement preserves the original C client and its contents.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned char *shared_medium;
static size_t replacement_size;

static void *owner_worker(void *opaque)
{
    (void)opaque;
    shared_medium = malloc(64 * 1024);
    if (shared_medium == NULL)
        return (void *)(uintptr_t)1;
    shared_medium[0] = 0x61;
    shared_medium[4095] = 0x62;
    shared_medium[64 * 1024 - 1] = 0x63;
    return NULL;
}

static void *release_worker(void *opaque)
{
    unsigned char *replacement;

    (void)opaque;
    if (shared_medium == NULL)
        return (void *)(uintptr_t)1;
    errno = 0;
    replacement = realloc(shared_medium, SIZE_MAX);
    if (replacement != NULL)
        return (void *)(uintptr_t)2;
    if (errno != ENOMEM)
        return (void *)(uintptr_t)3;
    if (shared_medium[0] != 0x61
            || shared_medium[4095] != 0x62
            || shared_medium[64 * 1024 - 1] != 0x63)
        return (void *)(uintptr_t)4;
    replacement = realloc(shared_medium, replacement_size);
    if (replacement == NULL)
        return (void *)(uintptr_t)5;
    if (replacement == shared_medium)
        return (void *)(uintptr_t)6;
    if (replacement_size == 0) {
        if (replacement[0] != 0)
            return (void *)(uintptr_t)7;
    } else {
        if (replacement[0] != 0x61)
            return (void *)(uintptr_t)8;
        if (replacement_size >= 4096 && replacement[4095] != 0x62)
            return (void *)(uintptr_t)9;
        if (replacement_size >= 64 * 1024
                && replacement[64 * 1024 - 1] != 0x63)
            return (void *)(uintptr_t)10;
    }
    free(replacement);
    shared_medium = NULL;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)5;
    unsigned char *after;

    static const size_t replacement_sizes[] = {
        4096,
        128 * 1024,
        0,
    };

    for (unsigned int round = 0; round < 3; ++round) {
        replacement_size = replacement_sizes[round];
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

    puts("native mimalloc owner exit realloc ok");
    return 0;
}
