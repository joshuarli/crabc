/*
 * The initial thread owns this allocation, while a later pthread performs
 * its exact free.  The main thread then allocates again so the initial owner
 * must collect the source remote head before its next ordinary operation.
 * This is an owner-domain regression, not a separate page-shape route.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct remote_clients {
    unsigned char *normal;
    unsigned char *aligned;
};

static void *free_initial_clients(void *opaque)
{
    struct remote_clients *clients = opaque;

    if (clients->normal == NULL || clients->normal[0] != 0x31
        || clients->normal[78] != 0x32)
        return (void *)(uintptr_t)1;
    if (clients->aligned == NULL || clients->aligned[0] != 0x51
        || clients->aligned[78] != 0x52)
        return (void *)(uintptr_t)2;
    free(clients->normal);
    free(clients->aligned);
    return NULL;
}

int main(void)
{
    pthread_t worker;
    void *result = (void *)(uintptr_t)3;
    struct remote_clients clients;
    unsigned char *after;
    unsigned char *aligned_after;

    clients.normal = malloc(79);
    if (clients.normal == NULL)
        return 1;
    clients.normal[0] = 0x31;
    clients.normal[78] = 0x32;
    clients.aligned = aligned_alloc(64, 79);
    if (clients.aligned == NULL || (uintptr_t)clients.aligned % 64 != 0)
        return 2;
    clients.aligned[0] = 0x51;
    clients.aligned[78] = 0x52;

    if (pthread_create(&worker, NULL, free_initial_clients, &clients) != 0)
        return 3;
    if (pthread_join(worker, &result) != 0 || result != NULL)
        return 4;

    after = malloc(97);
    if (after == NULL)
        return 5;
    after[0] = 0x41;
    after[96] = 0x42;
    if (after[0] != 0x41 || after[96] != 0x42)
        return 6;
    aligned_after = aligned_alloc(64, 79);
    if (aligned_after == NULL || (uintptr_t)aligned_after % 64 != 0)
        return 7;
    aligned_after[0] = 0x61;
    aligned_after[78] = 0x62;
    if (aligned_after[0] != 0x61 || aligned_after[78] != 0x62)
        return 8;
    free(after);
    free(aligned_after);

    puts("native mimalloc initial remote free ok");
    return 0;
}
