/*
 * A native-shadow worker keeps more ordinary C allocations live than the
 * historical mixed-owner-exit fixture requires.  They remain entirely local:
 * no address crosses a worker boundary and the worker frees every block before
 * its normal page-owner destructor runs.  Repeating the worker proves that a
 * completed all-free drain returns its admission and any private ledger
 * storage before ticket zero serves the next main-thread allocation.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum {
    LOCAL_BLOCK_COUNT = 64,
    WORKER_EPOCHS = 8,
};

static void *local_allocation_worker(void *opaque)
{
    unsigned char *blocks[LOCAL_BLOCK_COUNT];
    size_t index;

    (void)opaque;
    for (index = 0; index < LOCAL_BLOCK_COUNT; index++) {
        size_t size = 37 + (index % 17);

        blocks[index] = malloc(size);
        if (blocks[index] == NULL) {
            while (index != 0) {
                index--;
                free(blocks[index]);
            }
            return (void *)(uintptr_t)1;
        }
        blocks[index][0] = (unsigned char)(0x20 + index);
        blocks[index][size - 1] = (unsigned char)(0x80 + index);
    }

    while (index != 0) {
        size_t size;

        index--;
        size = 37 + (index % 17);
        if (blocks[index][0] != (unsigned char)(0x20 + index)
                || blocks[index][size - 1] != (unsigned char)(0x80 + index))
            return (void *)(uintptr_t)2;
        free(blocks[index]);
    }
    return NULL;
}

int main(void)
{
    size_t epoch;

    for (epoch = 0; epoch < WORKER_EPOCHS; epoch++) {
        pthread_t worker;
        void *result = (void *)(uintptr_t)3;
        unsigned char *after;

        if (pthread_create(&worker, NULL, local_allocation_worker, NULL) != 0)
            return 1;
        if (pthread_join(worker, &result) != 0 || result != NULL)
            return 2;

        after = malloc(53);
        if (after == NULL)
            return 3;
        after[0] = 0x51;
        after[52] = 0x52;
        if (after[0] != 0x51 || after[52] != 0x52)
            return 4;
        free(after);
    }

    puts("native mimalloc many local allocations ok");
    return 0;
}
