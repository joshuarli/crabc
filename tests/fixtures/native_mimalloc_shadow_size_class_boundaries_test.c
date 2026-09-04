/*
 * This public-C witness derives its six requests from pinned mimalloc v3.5.0,
 * `include/mimalloc/types.h:463-504`, `src/init.c:MI_PAGE_QUEUES_EMPTY`, and
 * `src/page-queue.c:mi_good_size`.  The frozen Linux/AArch64 release profile
 * has 16-byte natural allocation alignment, 10,240-byte small objects,
 * 86,698-byte medium objects, and 524,288-byte large objects.  The source
 * queue table makes 10,240 / 10,241 the small-to-medium transition, 81,920 /
 * 81,921 the medium-to-large transition, and 524,288 / 524,289 the
 * large-to-singleton transition after `mi_good_size` rounding.
 *
 * One owner creates the complete boundary image and remains live while the
 * initial thread is the sole serialized releaser.  This is deliberately not
 * a queue-race, reuse-order, general lifecycle, or promotion claim: it
 * proves only public `malloc` natural alignment plus non-null
 * write/read/free behavior at the source-derived class transitions.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum {
    NATIVE_MIMALLOC_NATURAL_ALIGNMENT = 16,
    NATIVE_MIMALLOC_SMALL_FINAL_REQUEST = 10 * 1024,
    NATIVE_MIMALLOC_MEDIUM_FIRST_REQUEST = NATIVE_MIMALLOC_SMALL_FINAL_REQUEST + 1,
    NATIVE_MIMALLOC_MEDIUM_FINAL_REQUEST = 80 * 1024,
    NATIVE_MIMALLOC_LARGE_FIRST_REQUEST = NATIVE_MIMALLOC_MEDIUM_FINAL_REQUEST + 1,
    NATIVE_MIMALLOC_LARGE_FINAL_REQUEST = 512 * 1024,
    NATIVE_MIMALLOC_SINGLETON_FIRST_REQUEST = NATIVE_MIMALLOC_LARGE_FINAL_REQUEST + 1,
    NATIVE_MIMALLOC_SIZE_CASE_COUNT = 6,
};

struct size_case {
    size_t request;
    unsigned char tag;
};

struct size_class_handoff {
    pthread_mutex_t lock;
    pthread_cond_t owner_ready;
    pthread_cond_t released;
    volatile unsigned char *blocks[NATIVE_MIMALLOC_SIZE_CASE_COUNT];
    int owner_is_ready;
    int owner_failed;
    int release_complete;
};

static const struct size_case size_cases[NATIVE_MIMALLOC_SIZE_CASE_COUNT] = {
    { NATIVE_MIMALLOC_SMALL_FINAL_REQUEST, 0x11 },
    { NATIVE_MIMALLOC_MEDIUM_FIRST_REQUEST, 0x22 },
    { NATIVE_MIMALLOC_MEDIUM_FINAL_REQUEST, 0x33 },
    { NATIVE_MIMALLOC_LARGE_FIRST_REQUEST, 0x44 },
    { NATIVE_MIMALLOC_LARGE_FINAL_REQUEST, 0x55 },
    { NATIVE_MIMALLOC_SINGLETON_FIRST_REQUEST, 0x66 },
};

static struct size_class_handoff handoff = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    { NULL, NULL, NULL, NULL, NULL, NULL },
    0,
    0,
    0,
};

static void write_owner_pattern(volatile unsigned char *block, const struct size_case *test)
{
    block[0] = test->tag;
    block[test->request / 2] = (unsigned char)(test->tag + 1);
    block[test->request - 1] = (unsigned char)(test->tag + 2);
}

static int owner_pattern_matches(const volatile unsigned char *block,
        const struct size_case *test)
{
    return block[0] == test->tag
        && block[test->request / 2] == (unsigned char)(test->tag + 1)
        && block[test->request - 1] == (unsigned char)(test->tag + 2);
}

static int releaser_pattern_round_trips(volatile unsigned char *block,
        const struct size_case *test)
{
    unsigned char first = (unsigned char)(test->tag + 3);
    unsigned char middle = (unsigned char)(test->tag + 4);
    unsigned char last = (unsigned char)(test->tag + 5);

    if (!owner_pattern_matches(block, test))
        return 0;
    if (((uintptr_t)block % NATIVE_MIMALLOC_NATURAL_ALIGNMENT) != 0)
        return 0;
    block[0] = first;
    block[test->request / 2] = middle;
    block[test->request - 1] = last;
    return block[0] == first
        && block[test->request / 2] == middle
        && block[test->request - 1] == last;
}

static void *owner_worker(void *opaque)
{
    size_t index;

    (void)opaque;
    for (index = 0; index < NATIVE_MIMALLOC_SIZE_CASE_COUNT; index++) {
        volatile unsigned char *block = malloc(size_cases[index].request);

        if (block == NULL)
            goto allocation_failed;
        write_owner_pattern(block, &size_cases[index]);
        handoff.blocks[index] = block;
    }

    if (pthread_mutex_lock(&handoff.lock) != 0)
        return (void *)(uintptr_t)1;
    handoff.owner_is_ready = 1;
    if (pthread_cond_signal(&handoff.owner_ready) != 0) {
        (void)pthread_mutex_unlock(&handoff.lock);
        return (void *)(uintptr_t)2;
    }
    while (!handoff.release_complete) {
        if (pthread_cond_wait(&handoff.released, &handoff.lock) != 0) {
            (void)pthread_mutex_unlock(&handoff.lock);
            return (void *)(uintptr_t)3;
        }
    }
    if (pthread_mutex_unlock(&handoff.lock) != 0)
        return (void *)(uintptr_t)4;
    return NULL;

allocation_failed:
    while (index != 0) {
        index--;
        free((void *)handoff.blocks[index]);
        handoff.blocks[index] = NULL;
    }
    if (pthread_mutex_lock(&handoff.lock) != 0)
        return (void *)(uintptr_t)5;
    handoff.owner_failed = 1;
    handoff.owner_is_ready = 1;
    if (pthread_cond_signal(&handoff.owner_ready) != 0) {
        (void)pthread_mutex_unlock(&handoff.lock);
        return (void *)(uintptr_t)5;
    }
    if (pthread_mutex_unlock(&handoff.lock) != 0)
        return (void *)(uintptr_t)5;
    return (void *)(uintptr_t)5;
}

int main(void)
{
    pthread_t owner;
    void *owner_result = (void *)(uintptr_t)6;
    size_t index;

    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 1;
    if (pthread_mutex_lock(&handoff.lock) != 0)
        return 2;
    while (!handoff.owner_is_ready) {
        if (pthread_cond_wait(&handoff.owner_ready, &handoff.lock) != 0) {
            (void)pthread_mutex_unlock(&handoff.lock);
            return 3;
        }
    }
    if (handoff.owner_failed) {
        if (pthread_mutex_unlock(&handoff.lock) != 0)
            return 4;
        if (pthread_join(owner, &owner_result) != 0 || owner_result != (void *)(uintptr_t)5)
            return 5;
        return 6;
    }
    for (index = 0; index < NATIVE_MIMALLOC_SIZE_CASE_COUNT; index++) {
        volatile unsigned char *block = handoff.blocks[index];

        if (block == NULL || !releaser_pattern_round_trips(block, &size_cases[index])) {
            (void)pthread_mutex_unlock(&handoff.lock);
            return 7;
        }
        free((void *)block);
        handoff.blocks[index] = NULL;
    }
    handoff.release_complete = 1;
    if (pthread_cond_signal(&handoff.released) != 0) {
        (void)pthread_mutex_unlock(&handoff.lock);
        return 8;
    }
    if (pthread_mutex_unlock(&handoff.lock) != 0)
        return 9;
    if (pthread_join(owner, &owner_result) != 0 || owner_result != NULL)
        return 10;

    puts("native mimalloc shadow size class boundaries ok");
    return 0;
}
