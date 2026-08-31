/*
 * One live pthread owns the source allocation while the initial thread uses
 * the standard realloc ABI. A failed request must preserve A's exact client
 * and contents; a successful cross-thread request returns B's replacement
 * with the requested prefix intact. B must never use the stale source after
 * that success, and A remains live until B has released the replacement. No
 * aligned-realloc extension is used or implied here.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static pthread_cond_t replacement_released = PTHREAD_COND_INITIALIZER;
static unsigned char *foreign_allocation;
static int owner_ready;
static int replacement_was_released;

static void *owner_worker(void *opaque)
{
    unsigned char *allocation;
    unsigned char *probe;
    size_t index;

    (void)opaque;
    allocation = malloc(513);
    if (allocation == NULL)
        return (void *)(uintptr_t)1;
    for (index = 0; index < 513; ++index)
        allocation[index] = (unsigned char)(index * 37U + 11U);

    if (pthread_mutex_lock(&lock) != 0)
        return (void *)(uintptr_t)2;
    foreign_allocation = allocation;
    owner_ready = 1;
    if (pthread_cond_signal(&ready) != 0) {
        (void)pthread_mutex_unlock(&lock);
        return (void *)(uintptr_t)3;
    }
    while (!replacement_was_released) {
        if (pthread_cond_wait(&replacement_released, &lock) != 0) {
            (void)pthread_mutex_unlock(&lock);
            return (void *)(uintptr_t)4;
        }
    }
    if (pthread_mutex_unlock(&lock) != 0)
        return (void *)(uintptr_t)5;

    /* B's successful realloc consumed `allocation`. A later ordinary local
     * operation gives A's normal source collection/finish path a chance to
     * observe the remote free without touching that stale client. */
    probe = malloc(37);
    if (probe == NULL)
        return (void *)(uintptr_t)6;
    probe[0] = 0x4a;
    probe[36] = 0x4b;
    if (probe[0] != 0x4a || probe[36] != 0x4b)
        return (void *)(uintptr_t)7;
    free(probe);
    return NULL;
}

static int prefix_is_preserved(const unsigned char *allocation)
{
    size_t index;

    for (index = 0; index < 513; ++index) {
        if (allocation[index] != (unsigned char)(index * 37U + 11U))
            return 0;
    }
    return 1;
}

int main(void)
{
    pthread_t owner;
    unsigned char *source;
    unsigned char *replacement;
    void *owner_result = (void *)(uintptr_t)6;

    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 1;
    if (pthread_mutex_lock(&lock) != 0)
        return 2;
    while (!owner_ready) {
        if (pthread_cond_wait(&ready, &lock) != 0) {
            (void)pthread_mutex_unlock(&lock);
            return 3;
        }
    }
    source = foreign_allocation;
    if (pthread_mutex_unlock(&lock) != 0)
        return 4;

    if (source == NULL || !prefix_is_preserved(source))
        return 5;
    errno = 0;
    replacement = realloc(source, SIZE_MAX);
    if (replacement != NULL || errno != ENOMEM
            || !prefix_is_preserved(source))
        return 6;

    errno = EAGAIN;
    replacement = realloc(source, 8192);
    if (replacement == NULL || !prefix_is_preserved(replacement))
        return 7;
    if (errno != EAGAIN)
        return 8;
    replacement[8191] = 0x7d;
    if (replacement[8191] != 0x7d)
        return 9;

    /* `source` is invalid after the successful realloc. B releases only the
     * returned replacement while A remains live for the source-side finish. */
    free(replacement);

    if (pthread_mutex_lock(&lock) != 0)
        return 10;
    replacement_was_released = 1;
    if (pthread_cond_signal(&replacement_released) != 0) {
        (void)pthread_mutex_unlock(&lock);
        return 11;
    }
    if (pthread_mutex_unlock(&lock) != 0)
        return 12;
    if (pthread_join(owner, &owner_result) != 0 || owner_result != NULL)
        return 13;

    puts("native mimalloc shadow foreign realloc ok");
    return 0;
}
