/*
 * A owns the source image while B and C establish independent local C
 * allocations and remain parked.  Only after `pthread_join` has published
 * A's completed owner exit do main, B, and C cross one real pthread barrier.
 * B validly reallocates A's direct-small and medium clients through B's
 * persistent owner while C reads usable sizes and frees A's disjoint
 * non-direct-small, regular-large, arena-singleton, and OS-aligned singleton
 * clients.
 *
 * This is deliberately not the fresh-worker concurrent-free fixture.  Both
 * consumers survive A's exit with independent local sessions already live,
 * and their simultaneous post-exit operations must retain ordinary C ABI
 * behavior.  A native `Retained` realloc becomes NULL/ENOMEM here, while a
 * retained free aborts; either outcome is a differential failure rather than
 * an accepted scheduler fallback.
 */
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum {
    SURVIVOR_COUNT = 2,
    DIRECT_SMALL_REQUEST = 37,
    NON_DIRECT_SMALL_REQUEST = 1025,
    MEDIUM_REQUEST = 64 * 1024,
    LARGE_REQUEST = 128 * 1024,
    ARENA_SINGLETON_REQUEST = 1024 * 1024,
    OS_ALIGNED_REQUEST = 7,
    SMALL_REPLACEMENT_REQUEST = 4096,
    MEDIUM_REPLACEMENT_REQUEST = 128 * 1024,
};

struct owner_exit_blocks {
    unsigned char *small;
    unsigned char *non_direct_small;
    unsigned char *medium;
    unsigned char *large;
    unsigned char *arena_singleton;
    unsigned char *os_aligned;
};

struct post_exit_concurrent_realloc_state {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned int survivors_ready;
    unsigned int survivors_at_start;
    int owner_allocated;
    int owner_exited;
    int failed;
};

static struct owner_exit_blocks shared_blocks;
static struct post_exit_concurrent_realloc_state state = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    0,
    0,
    0,
    0,
    0,
};
static pthread_barrier_t post_exit_start;

static void mark_failed(void)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return;
    state.failed = 1;
    (void)pthread_cond_broadcast(&state.changed);
    (void)pthread_mutex_unlock(&state.lock);
}

static int wait_for_owner_allocation(void)
{
    if (pthread_mutex_lock(&state.lock) != 0) {
        mark_failed();
        return 0;
    }
    while (!state.owner_allocated && !state.failed) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            mark_failed();
            return 0;
        }
    }
    if (state.failed || pthread_mutex_unlock(&state.lock) != 0)
        return 0;
    return 1;
}

/* The local allocation is complete before this worker acknowledges A's
 * source image. A consequently cannot leave its owner lifecycle until both
 * B and C are independently attached. */
static int wait_for_owner_exit_and_start(void)
{
    int barrier_result;

    if (pthread_mutex_lock(&state.lock) != 0) {
        mark_failed();
        return 0;
    }
    state.survivors_ready += 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        mark_failed();
        return 0;
    }
    while (!state.owner_exited && !state.failed) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            mark_failed();
            return 0;
        }
    }
    if (state.failed) {
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    }
    state.survivors_at_start += 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        mark_failed();
        return 0;
    }
    if (pthread_mutex_unlock(&state.lock) != 0) {
        mark_failed();
        return 0;
    }

    barrier_result = pthread_barrier_wait(&post_exit_start);
    if (barrier_result != 0 && barrier_result != PTHREAD_BARRIER_SERIAL_THREAD) {
        mark_failed();
        return 0;
    }
    return 1;
}

static void *owner_worker(void *opaque)
{
    (void)opaque;
    /* The allocation order and exact class mix match the selected ordinary
     * owner-exit image: direct-small, non-direct-small, medium, regular
     * large, arena singleton, and an OS-aligned singleton. */
    shared_blocks.small = malloc(DIRECT_SMALL_REQUEST);
    shared_blocks.non_direct_small = malloc(NON_DIRECT_SMALL_REQUEST);
    shared_blocks.medium = malloc(MEDIUM_REQUEST);
    shared_blocks.large = malloc(LARGE_REQUEST);
    shared_blocks.arena_singleton = malloc(ARENA_SINGLETON_REQUEST);
    shared_blocks.os_aligned = aligned_alloc(128 * 1024, OS_ALIGNED_REQUEST);
    if (shared_blocks.small == NULL || shared_blocks.non_direct_small == NULL
            || shared_blocks.medium == NULL || shared_blocks.large == NULL
            || shared_blocks.arena_singleton == NULL
            || shared_blocks.os_aligned == NULL) {
        mark_failed();
        return (void *)(uintptr_t)1;
    }
    if ((uintptr_t)shared_blocks.os_aligned % (128 * 1024) != 0) {
        mark_failed();
        return (void *)(uintptr_t)2;
    }

    shared_blocks.small[0] = 0x41;
    shared_blocks.small[DIRECT_SMALL_REQUEST - 1] = 0x42;
    shared_blocks.non_direct_small[0] = 0x43;
    shared_blocks.non_direct_small[NON_DIRECT_SMALL_REQUEST - 1] = 0x44;
    shared_blocks.medium[0] = 0x45;
    shared_blocks.medium[4095] = 0x46;
    shared_blocks.medium[MEDIUM_REQUEST - 1] = 0x47;
    shared_blocks.large[0] = 0x48;
    shared_blocks.large[LARGE_REQUEST - 1] = 0x49;
    shared_blocks.arena_singleton[0] = 0x4a;
    shared_blocks.arena_singleton[ARENA_SINGLETON_REQUEST - 1] = 0x4b;
    shared_blocks.os_aligned[0] = 0x4c;
    shared_blocks.os_aligned[OS_ALIGNED_REQUEST - 1] = 0x4d;

    if (pthread_mutex_lock(&state.lock) != 0) {
        mark_failed();
        return (void *)(uintptr_t)3;
    }
    state.owner_allocated = 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        mark_failed();
        return (void *)(uintptr_t)4;
    }
    while (state.survivors_ready != SURVIVOR_COUNT && !state.failed) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            mark_failed();
            return (void *)(uintptr_t)5;
        }
    }
    if (state.failed) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)6;
    }
    if (pthread_mutex_unlock(&state.lock) != 0) {
        mark_failed();
        return (void *)(uintptr_t)7;
    }
    return NULL;
}

static void *realloc_survivor(void *opaque)
{
    unsigned char *local;
    unsigned char *small;
    unsigned char *medium;
    unsigned char *replacement;

    (void)opaque;
    if (!wait_for_owner_allocation())
        return (void *)(uintptr_t)1;

    local = malloc(73);
    if (local == NULL) {
        mark_failed();
        return (void *)(uintptr_t)2;
    }
    local[0] = 0x71;
    local[72] = 0x72;
    if (local[0] != 0x71 || local[72] != 0x72
            || malloc_usable_size(local) < 73) {
        free(local);
        mark_failed();
        return (void *)(uintptr_t)3;
    }

    if (!wait_for_owner_exit_and_start()) {
        free(local);
        return (void *)(uintptr_t)4;
    }

    small = shared_blocks.small;
    medium = shared_blocks.medium;
    if (small == NULL || medium == NULL || small[0] != 0x41
            || small[DIRECT_SMALL_REQUEST - 1] != 0x42
            || medium[0] != 0x45 || medium[4095] != 0x46
            || medium[MEDIUM_REQUEST - 1] != 0x47
            || malloc_usable_size(small) < DIRECT_SMALL_REQUEST
            || malloc_usable_size(medium) < MEDIUM_REQUEST) {
        free(local);
        return (void *)(uintptr_t)5;
    }

    /* This is a valid post-exit foreign source. A successful result may be
     * in place or a B-owned replacement; in either case the old alias is no
     * longer C-accessible after `realloc` returns. */
    replacement = realloc(small, SMALL_REPLACEMENT_REQUEST);
    if (replacement == NULL) {
        free(local);
        return (void *)(uintptr_t)6;
    }
    shared_blocks.small = NULL;
    if (replacement[0] != 0x41
            || replacement[DIRECT_SMALL_REQUEST - 1] != 0x42
            || malloc_usable_size(replacement) < SMALL_REPLACEMENT_REQUEST) {
        free(replacement);
        free(local);
        return (void *)(uintptr_t)7;
    }
    replacement[SMALL_REPLACEMENT_REQUEST - 1] = 0x51;
    if (replacement[SMALL_REPLACEMENT_REQUEST - 1] != 0x51) {
        free(replacement);
        free(local);
        return (void *)(uintptr_t)8;
    }
    free(replacement);

    replacement = realloc(medium, MEDIUM_REPLACEMENT_REQUEST);
    if (replacement == NULL) {
        free(local);
        return (void *)(uintptr_t)9;
    }
    shared_blocks.medium = NULL;
    if (replacement[0] != 0x45 || replacement[4095] != 0x46
            || replacement[MEDIUM_REQUEST - 1] != 0x47
            || malloc_usable_size(replacement) < MEDIUM_REPLACEMENT_REQUEST) {
        free(replacement);
        free(local);
        return (void *)(uintptr_t)10;
    }
    replacement[MEDIUM_REPLACEMENT_REQUEST - 1] = 0x52;
    if (replacement[MEDIUM_REPLACEMENT_REQUEST - 1] != 0x52) {
        free(replacement);
        free(local);
        return (void *)(uintptr_t)11;
    }
    free(replacement);

    if (local[0] != 0x71 || local[72] != 0x72) {
        free(local);
        return (void *)(uintptr_t)12;
    }
    free(local);
    return NULL;
}

static void *query_and_free_survivor(void *opaque)
{
    unsigned char *local;
    unsigned char *non_direct_small;
    unsigned char *large;
    unsigned char *arena_singleton;
    unsigned char *os_aligned;

    (void)opaque;
    if (!wait_for_owner_allocation())
        return (void *)(uintptr_t)1;

    local = malloc(79);
    if (local == NULL) {
        mark_failed();
        return (void *)(uintptr_t)2;
    }
    local[0] = 0x73;
    local[78] = 0x74;
    if (local[0] != 0x73 || local[78] != 0x74
            || malloc_usable_size(local) < 79) {
        free(local);
        mark_failed();
        return (void *)(uintptr_t)3;
    }

    if (!wait_for_owner_exit_and_start()) {
        free(local);
        return (void *)(uintptr_t)4;
    }

    non_direct_small = shared_blocks.non_direct_small;
    large = shared_blocks.large;
    arena_singleton = shared_blocks.arena_singleton;
    os_aligned = shared_blocks.os_aligned;
    if (non_direct_small == NULL || large == NULL || arena_singleton == NULL
            || os_aligned == NULL || non_direct_small[0] != 0x43
            || non_direct_small[NON_DIRECT_SMALL_REQUEST - 1] != 0x44
            || large[0] != 0x48 || large[LARGE_REQUEST - 1] != 0x49
            || arena_singleton[0] != 0x4a
            || arena_singleton[ARENA_SINGLETON_REQUEST - 1] != 0x4b
            || os_aligned[0] != 0x4c
            || os_aligned[OS_ALIGNED_REQUEST - 1] != 0x4d
            || malloc_usable_size(non_direct_small) < NON_DIRECT_SMALL_REQUEST
            || malloc_usable_size(large) < LARGE_REQUEST
            || malloc_usable_size(arena_singleton) < ARENA_SINGLETON_REQUEST
            || malloc_usable_size(os_aligned) < OS_ALIGNED_REQUEST) {
        free(local);
        return (void *)(uintptr_t)5;
    }

    /* Withdraw every C alias before the source-consuming frees. The other
     * survivor owns only `small` and `medium`, so these calls are disjoint
     * from its valid concurrent replacements. */
    shared_blocks.non_direct_small = NULL;
    shared_blocks.large = NULL;
    shared_blocks.arena_singleton = NULL;
    shared_blocks.os_aligned = NULL;
    free(os_aligned);
    free(arena_singleton);
    free(large);
    free(non_direct_small);

    if (local[0] != 0x73 || local[78] != 0x74) {
        free(local);
        return (void *)(uintptr_t)6;
    }
    free(local);
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t realloc_worker;
    pthread_t free_worker;
    void *result = (void *)(uintptr_t)1;
    unsigned char *after;
    int barrier_result;

    if (pthread_barrier_init(&post_exit_start, NULL, SURVIVOR_COUNT + 1) != 0)
        return 1;
    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 2;
    if (pthread_create(&realloc_worker, NULL, realloc_survivor, NULL) != 0)
        return 3;
    if (pthread_create(&free_worker, NULL, query_and_free_survivor, NULL) != 0)
        return 4;

    /* A cannot return until both B and C have local allocations. Joining A
     * is the only publication step that allows the workers to leave their
     * owner-exit gate. */
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 5;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 6;
    if (state.failed) {
        (void)pthread_mutex_unlock(&state.lock);
        return 7;
    }
    state.owner_exited = 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return 8;
    }
    while (state.survivors_at_start != SURVIVOR_COUNT && !state.failed) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return 9;
        }
    }
    if (state.failed || pthread_mutex_unlock(&state.lock) != 0)
        return 10;

    /* This releases the two distinct post-exit source operations together,
     * after A's exit and without turning either B or C into a fresh worker. */
    barrier_result = pthread_barrier_wait(&post_exit_start);
    if (barrier_result != 0 && barrier_result != PTHREAD_BARRIER_SERIAL_THREAD)
        return 11;

    result = (void *)(uintptr_t)12;
    if (pthread_join(realloc_worker, &result) != 0 || result != NULL)
        return 12;
    result = (void *)(uintptr_t)13;
    if (pthread_join(free_worker, &result) != 0 || result != NULL)
        return 13;
    if (shared_blocks.small != NULL || shared_blocks.non_direct_small != NULL
            || shared_blocks.medium != NULL || shared_blocks.large != NULL
            || shared_blocks.arena_singleton != NULL
            || shared_blocks.os_aligned != NULL)
        return 14;
    if (pthread_barrier_destroy(&post_exit_start) != 0)
        return 15;

    /* Both independent normal finishes have run after the final post-exit
     * source operation. A later ordinary allocation must therefore remain
     * usable rather than inheriting a retained owner or terminal route. */
    after = malloc(53);
    if (after == NULL)
        return 16;
    after[0] = 0x81;
    after[52] = 0x82;
    if (after[0] != 0x81 || after[52] != 0x82)
        return 17;
    free(after);

    puts("native mimalloc post exit concurrent realloc ok");
    return 0;
}
