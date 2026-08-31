/*
 * One live pthread owns the source allocation while the initial thread uses
 * the standard realloc ABI. The native shadow must reject this foreign
 * request with ENOMEM, preserving A's exact client and contents. The initial
 * thread then consumes that original client through generic pointer-first
 * free while A remains live and synchronized. No aligned-realloc extension
 * is used or implied here.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static pthread_cond_t source_freed = PTHREAD_COND_INITIALIZER;
static unsigned char *foreign_allocation;
static int owner_ready;
static int source_was_freed;

static void *owner_worker(void *opaque)
{
    unsigned char *allocation;
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
    while (!source_was_freed) {
        if (pthread_cond_wait(&source_freed, &lock) != 0) {
            (void)pthread_mutex_unlock(&lock);
            return (void *)(uintptr_t)4;
        }
    }
    if (pthread_mutex_unlock(&lock) != 0)
        return (void *)(uintptr_t)5;
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
    unsigned char *foreign_reallocation;
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
    foreign_reallocation = realloc(source, SIZE_MAX);
    if (foreign_reallocation != NULL || errno != ENOMEM
            || !prefix_is_preserved(source))
        return 6;

    errno = EAGAIN;
    foreign_reallocation = realloc(source, 8192);
    if (foreign_reallocation != NULL || errno != ENOMEM
            || !prefix_is_preserved(source))
        return 7;

    /* A is still waiting on `source_freed`, so this is a live-owner generic
     * pointer-first free rather than a detached-owner cleanup path. */
    free(source);

    if (pthread_mutex_lock(&lock) != 0)
        return 8;
    source_was_freed = 1;
    if (pthread_cond_signal(&source_freed) != 0) {
        (void)pthread_mutex_unlock(&lock);
        return 9;
    }
    if (pthread_mutex_unlock(&lock) != 0)
        return 10;
    if (pthread_join(owner, &owner_result) != 0 || owner_result != NULL)
        return 11;

    puts("native mimalloc shadow rejects live foreign realloc ok");
    return 0;
}
