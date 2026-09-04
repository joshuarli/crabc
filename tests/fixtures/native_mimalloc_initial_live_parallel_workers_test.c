/*
 * The initial persistent owner keeps one native client live while two later
 * workers each retain a private local client. The workers are released one at
 * a time: the test observes worker-local lifecycle progress, not parent-side
 * parking, concurrent PageMap mutation, or a pointer handoff. The initial
 * client remains with its direct owner throughout both all-free finishes.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum { WORKER_COUNT = 2 };

struct initial_live_parallel_state {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int parked[WORKER_COUNT];
    int release[WORKER_COUNT];
    int finished[WORKER_COUNT];
};

static struct initial_live_parallel_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    { 0, 0 },
    { 0, 0 },
    { 0, 0 },
};

static size_t worker_request(unsigned int index)
{
    return index == 0 ? 37 : 53;
}

static unsigned char worker_first_byte(unsigned int index)
{
    return index == 0 ? 0x41 : 0x51;
}

static unsigned char worker_last_byte(unsigned int index)
{
    return index == 0 ? 0x42 : 0x52;
}

static void *local_worker(void *opaque)
{
    unsigned int index = (unsigned int)(uintptr_t)opaque;
    unsigned char *local;
    size_t request;

    if (index >= WORKER_COUNT)
        return (void *)(uintptr_t)1;
    request = worker_request(index);
    local = malloc(request);
    if (local == NULL)
        return (void *)(uintptr_t)2;
    local[0] = worker_first_byte(index);
    local[request - 1] = worker_last_byte(index);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)3;
    state.parked[index] = 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)4;
    }
    while (!state.release[index]) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)5;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)6;

    if (local[0] != worker_first_byte(index)
            || local[request - 1] != worker_last_byte(index))
        return (void *)(uintptr_t)7;
    free(local);

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)8;
    state.finished[index] = 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)9;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)10;
    return NULL;
}

int main(void)
{
    pthread_t first_worker;
    pthread_t second_worker;
    void *result = (void *)(uintptr_t)11;
    unsigned char *initial;
    unsigned char *after;

    initial = malloc(79);
    if (initial == NULL)
        return 1;
    initial[0] = 0x31;
    initial[78] = 0x32;

    /* Wait until the first worker holds its own local client before the
     * initial thread creates the second child. This fixes the fixture's
     * worker ordering without changing the initial owner's lifecycle. */
    if (pthread_create(&first_worker, NULL, local_worker, (void *)(uintptr_t)0) != 0)
        return 2;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 3;
    while (!state.parked[0]) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return 4;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 5;

    if (pthread_create(&second_worker, NULL, local_worker, (void *)(uintptr_t)1) != 0)
        return 6;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 7;
    while (!state.parked[0] || !state.parked[1]) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return 8;
        }
    }
    state.release[0] = 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return 9;
    }
    while (!state.finished[0]) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return 10;
        }
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 11;

    /* Join the first thread before releasing the second. Its no-page
     * destructor finish settles only its own local lifecycle, keeping this a
     * serial worker-ordering witness. */
    if (pthread_join(first_worker, &result) != 0 || result != NULL)
        return 12;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 13;
    state.release[1] = 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return 14;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 15;
    result = (void *)(uintptr_t)16;
    if (pthread_join(second_worker, &result) != 0 || result != NULL)
        return 17;

    if (initial[0] != 0x31 || initial[78] != 0x32)
        return 18;
    free(initial);

    after = malloc(67);
    if (after == NULL)
        return 19;
    after[0] = 0x61;
    after[66] = 0x62;
    if (after[0] != 0x61 || after[66] != 0x62)
        return 20;
    free(after);

    puts("native mimalloc initial live parallel workers ok");
    return 0;
}
