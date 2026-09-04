/*
 * Two attached workers cross their first native C allocation together. Each
 * must wait through the peer's short scheduler handoff, establish its own
 * parked session, and complete ordinary local allocation/reallocation/free
 * without turning serialized setup into a spurious allocation failure.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct concurrent_session_start_state {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned int waiting;
    int release;
};

static struct concurrent_session_start_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    0,
    0,
};

static void *worker(void *opaque)
{
    unsigned char *small;
    unsigned char *large;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)1;
    state.waiting += 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)2;
    }
    while (!state.release) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)3;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)4;

    small = calloc(100, sizeof(*small));
    if (small == NULL)
        return (void *)(uintptr_t)5;
    small[0] = 0x41;
    small[99] = 0x42;

    /* The upstream stress worker grows this same source-shaped pointer table
     * on its first local allocation. */
    large = realloc(NULL, 100000 * sizeof(void *));
    if (large == NULL) {
        free(small);
        return (void *)(uintptr_t)6;
    }
    large[0] = 0x51;
    large[100000 * sizeof(void *) - 1] = 0x52;
    if (small[0] != 0x41 || small[99] != 0x42 || large[0] != 0x51
            || large[100000 * sizeof(void *) - 1] != 0x52) {
        free(large);
        free(small);
        return (void *)(uintptr_t)7;
    }
    free(large);
    free(small);
    return NULL;
}

int main(void)
{
    pthread_t first;
    pthread_t second;
    void *result = (void *)(uintptr_t)1;

    if (pthread_create(&first, NULL, worker, NULL) != 0)
        return 1;
    if (pthread_create(&second, NULL, worker, NULL) != 0)
        return 2;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 3;
    while (state.waiting != 2) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return 4;
        }
    }
    state.release = 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return 5;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 6;
    if (pthread_join(first, &result) != 0 || result != NULL)
        return 7;
    result = (void *)(uintptr_t)8;
    if (pthread_join(second, &result) != 0 || result != NULL)
        return 8;

    puts("native mimalloc concurrent session start ok");
    return 0;
}
