/*
 * The initial persistent owner retains this ordinary allocation while a later
 * pthread needs its own local allocation. No pointer or engine crosses the
 * thread boundary: the worker receives an independently owned native
 * operation while the initial owner remains current for its exact live client.
 */
#include <pthread.h>
#include <stdint.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>

static void *local_worker(void *opaque)
{
    unsigned char *local;

    (void)opaque;
    local = malloc(37);
    if (local == NULL)
        return (void *)(uintptr_t)1;
    local[0] = 0x41;
    local[36] = 0x42;
    if (local[0] != 0x41 || local[36] != 0x42)
        return (void *)(uintptr_t)2;
    free(local);
    return NULL;
}

int main(void)
{
    pthread_t worker;
    void *result = (void *)(uintptr_t)3;
    unsigned char *initial;
    unsigned char *after;

    initial = malloc(79);
    if (initial == NULL)
        return 1;
    initial[0] = 0x31;
    initial[78] = 0x32;

    if (pthread_create(&worker, NULL, local_worker, NULL) != 0)
        return 2;
    if (pthread_join(worker, &result) != 0 || result != NULL)
        return 3;

    if (initial[0] != 0x31 || initial[78] != 0x32)
        return 4;
    if (malloc_usable_size(initial) < 79)
        return 5;

    /* Both query and replacement remain with the same initial-thread owner;
     * neither operation reassembles or parks a parent engine. */
    initial = realloc(initial, 151);
    if (initial == NULL)
        return 6;
    if (initial[0] != 0x31 || initial[78] != 0x32)
        return 7;
    initial[150] = 0x33;
    if (malloc_usable_size(initial) < 151 || initial[150] != 0x33)
        return 8;
    free(initial);

    after = malloc(53);
    if (after == NULL)
        return 9;
    after[0] = 0x51;
    after[52] = 0x52;
    if (after[0] != 0x51 || after[52] != 0x52)
        return 10;
    free(after);

    puts("native mimalloc initial live local worker ok");
    return 0;
}
