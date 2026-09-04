/*
 * Two independently attached A workers each park one live native allocation
 * before either address crosses to a fresh B worker. Every B receives only
 * its exact C pointer, validates the source-recorded usable extent, and frees
 * it while the other A remains parked. The runtime must locate the matching
 * private A ledger without a process-wide client table, then return both A
 * sessions to normal collection and ticket-zero reactivation.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>

struct two_live_owner_state {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_cond_t published;
    unsigned char *remote[2];
    int owners_ready;
    int remote_published;
};

static struct two_live_owner_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    { NULL, NULL },
    0,
    0,
};

static size_t remote_request(unsigned int index)
{
    return index == 0 ? 37 : 53;
}

static size_t local_request(unsigned int index)
{
    return index == 0 ? 73 : 89;
}

static unsigned char remote_first_byte(unsigned int index)
{
    return index == 0 ? 0x41 : 0x51;
}

static unsigned char remote_last_byte(unsigned int index)
{
    return index == 0 ? 0x42 : 0x52;
}

static unsigned char local_first_byte(unsigned int index)
{
    return index == 0 ? 0x43 : 0x53;
}

static unsigned char local_last_byte(unsigned int index)
{
    return index == 0 ? 0x44 : 0x54;
}

static void *owner_worker(void *opaque)
{
    unsigned int index = (unsigned int)(uintptr_t)opaque;
    size_t remote_size;
    size_t local_size;
    unsigned char *remote;
    unsigned char *local;
    unsigned char *probe;

    if (index > 1)
        return (void *)(uintptr_t)1;
    /* The source scheduler admits one setup transition at a time. A1 first
     * parks its complete source owner; A2 then independently allocates and
     * parks. The test still has both live registry entries ACTIVE before a B
     * thread receives either exact C address. */
    if (index == 1) {
        if (pthread_mutex_lock(&state.lock) != 0)
            return (void *)(uintptr_t)2;
        while (state.owners_ready != 1) {
            if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
                (void)pthread_mutex_unlock(&state.lock);
                return (void *)(uintptr_t)3;
            }
        }
        if (pthread_mutex_unlock(&state.lock) != 0)
            return (void *)(uintptr_t)4;
    }
    remote_size = remote_request(index);
    local_size = local_request(index);
    remote = malloc(remote_size);
    local = malloc(local_size);
    if (remote == NULL || local == NULL)
        return (void *)(uintptr_t)5;
    remote[0] = remote_first_byte(index);
    remote[remote_size - 1] = remote_last_byte(index);
    local[0] = local_first_byte(index);
    local[local_size - 1] = local_last_byte(index);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)6;
    state.remote[index] = remote;
    state.owners_ready += 1;
    if (pthread_cond_broadcast(&state.ready) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)7;
    }
    while (state.remote_published != 2) {
        if (pthread_cond_wait(&state.published, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)8;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)9;

    /* Both exact B publications have restored the A engines to PARKED. A
     * resumes normally and its source collector decides when to reuse each
     * remote head; no C-visible reuse order is prescribed. */
    probe = malloc(remote_size);
    if (probe == NULL)
        return (void *)(uintptr_t)10;
    probe[0] = remote_first_byte(index);
    probe[remote_size - 1] = remote_last_byte(index);
    if (probe[0] != remote_first_byte(index)
        || probe[remote_size - 1] != remote_last_byte(index)
        || local[0] != local_first_byte(index)
        || local[local_size - 1] != local_last_byte(index))
        return (void *)(uintptr_t)11;
    free(probe);
    free(local);
    return NULL;
}

static void *releaser_worker(void *opaque)
{
    unsigned int index = (unsigned int)(uintptr_t)opaque;
    size_t request;
    unsigned char *remote;

    if (index > 1)
        return (void *)(uintptr_t)1;
    request = remote_request(index);
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)2;
    while (state.owners_ready != 2) {
        if (pthread_cond_wait(&state.ready, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)3;
        }
    }
    remote = state.remote[index];
    if (remote == NULL || remote[0] != remote_first_byte(index)
        || remote[request - 1] != remote_last_byte(index)) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)4;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)5;

    if (malloc_usable_size(remote) < request)
        return (void *)(uintptr_t)6;
    free(remote);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)7;
    state.remote_published += 1;
    if (pthread_cond_broadcast(&state.published) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)8;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)9;
    return NULL;
}

int main(void)
{
    pthread_t owners[2];
    pthread_t releasers[2];
    void *result = (void *)(uintptr_t)10;
    unsigned char *after;

    if (pthread_create(&owners[0], NULL, owner_worker, (void *)(uintptr_t)0) != 0)
        return 1;
    if (pthread_create(&owners[1], NULL, owner_worker, (void *)(uintptr_t)1) != 0)
        return 2;
    if (pthread_create(&releasers[0], NULL, releaser_worker, (void *)(uintptr_t)0) != 0)
        return 3;
    if (pthread_create(&releasers[1], NULL, releaser_worker, (void *)(uintptr_t)1) != 0)
        return 4;
    if (pthread_join(releasers[0], &result) != 0 || result != NULL)
        return 5;
    result = (void *)(uintptr_t)11;
    if (pthread_join(releasers[1], &result) != 0 || result != NULL)
        return 6;
    result = (void *)(uintptr_t)12;
    if (pthread_join(owners[0], &result) != 0 || result != NULL)
        return 7;
    result = (void *)(uintptr_t)13;
    if (pthread_join(owners[1], &result) != 0 || result != NULL)
        return 8;

    after = malloc(53);
    if (after == NULL)
        return 9;
    after[0] = 0x61;
    after[52] = 0x62;
    if (after[0] != 0x61 || after[52] != 0x62)
        return 10;
    free(after);

    puts("native mimalloc two live remote owners ok");
    return 0;
}
