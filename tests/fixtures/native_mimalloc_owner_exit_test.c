/*
 * A worker A leaves ordinary C allocations live, then a fresh joined worker B
 * returns them after A's allocator owner has crossed thread exit.  The
 * fixture intentionally uses distinct regular-page classes so the selected
 * native backend must enter its aggregate post-exit lifecycle rather than
 * treating this as an all-free worker finish.
 */
#include <pthread.h>
#include <stdint.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>

struct owner_exit_blocks {
    unsigned char *small;
    unsigned char *non_direct_small;
    unsigned char *medium;
    unsigned char *large;
    unsigned char *arena_singleton;
    unsigned char *os_aligned;
    unsigned char *sole_medium;
};

static struct owner_exit_blocks shared_blocks;
static pthread_key_t owner_exit_destructor_key;
static unsigned int owner_exit_destructor_calls;
static int owner_exit_destructor_failed;
static int owner_exit_via_pthread_exit;
static pthread_mutex_t owner_exit_cancel_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t owner_exit_cancel_cond = PTHREAD_COND_INITIALIZER;
static int owner_exit_cancel_mode;
static int owner_exit_cancel_ready;
static unsigned int owner_exit_cancel_cleanup_calls;
static int owner_exit_cancel_cleanup_failed;

/* This destructor runs while A still owns its parked native session.  It is
 * deliberately part of the aggregate owner-exit fixture: the runtime must
 * complete user destructor work before it turns A's remaining live clients
 * into the opaque post-exit route. */
static void owner_exit_destructor(void *value)
{
    unsigned char *temporary;

    if (value == NULL) {
        owner_exit_destructor_failed = 1;
        return;
    }
    temporary = malloc(73);
    if (temporary == NULL) {
        owner_exit_destructor_failed = 1;
        return;
    }
    temporary[0] = 0x31;
    temporary[72] = 0x32;
    if (temporary[0] != 0x31 || temporary[72] != 0x32
            || malloc_usable_size(temporary) < 73)
        owner_exit_destructor_failed = 1;
    free(temporary);
    /* Deferred cancellation must run cleanup handlers before TSD
     * destructors. The native allocator has to remain a live A-side owner
     * through both phases, before it creates the opaque post-exit route. */
    if (owner_exit_cancel_mode && owner_exit_cancel_cleanup_calls != 1)
        owner_exit_destructor_failed = 1;
    owner_exit_destructor_calls += 1;
}

static void owner_exit_cancel_cleanup(void *opaque)
{
    unsigned char *temporary;

    (void)opaque;
    temporary = malloc(79);
    if (temporary == NULL) {
        owner_exit_cancel_cleanup_failed = 1;
        return;
    }
    temporary[0] = 0x61;
    temporary[78] = 0x62;
    if (temporary[0] != 0x61 || temporary[78] != 0x62
            || malloc_usable_size(temporary) < 79)
        owner_exit_cancel_cleanup_failed = 1;
    free(temporary);
    owner_exit_cancel_cleanup_calls += 1;
}

static void owner_exit_cancel_unlock(void *opaque)
{
    (void)pthread_mutex_unlock((pthread_mutex_t *)opaque);
}

static void *owner_worker(void *opaque)
{
    (void)opaque;
    shared_blocks.small = malloc(37);
    /* 1025 is just above the pinned 1024-byte direct-cache boundary. */
    shared_blocks.non_direct_small = malloc(1025);
    shared_blocks.medium = malloc(64 * 1024);
    /* This is larger than the pinned medium maximum but remains a regular
     * large page. The unaligned 1 MiB request then crosses the source arena
     * singleton boundary without taking the OS-aligned singleton path. */
    shared_blocks.large = malloc(128 * 1024);
    shared_blocks.arena_singleton = malloc(1024 * 1024);
    /* This exact alignment follows the existing general aggregate's
     * OS-singleton source branch. It is intentionally part of the ordinary
     * mixed A exit rather than a separate C route: B must release the
     * static-main OS-abandoned-list member before A's admission can finish. */
    shared_blocks.os_aligned = aligned_alloc(128 * 1024, 7);
    if (shared_blocks.small == NULL || shared_blocks.non_direct_small == NULL
            || shared_blocks.medium == NULL || shared_blocks.large == NULL
            || shared_blocks.arena_singleton == NULL
            || shared_blocks.os_aligned == NULL)
        return (void *)(uintptr_t)1;
    if ((uintptr_t)shared_blocks.os_aligned % (128 * 1024) != 0)
        return (void *)(uintptr_t)2;
    shared_blocks.small[0] = 0x41;
    shared_blocks.small[36] = 0x42;
    shared_blocks.non_direct_small[0] = 0x43;
    shared_blocks.non_direct_small[1024] = 0x44;
    shared_blocks.medium[0] = 0x43;
    shared_blocks.medium[64 * 1024 - 1] = 0x44;
    shared_blocks.large[0] = 0x45;
    shared_blocks.large[128 * 1024 - 1] = 0x46;
    shared_blocks.arena_singleton[0] = 0x47;
    shared_blocks.arena_singleton[1024 * 1024 - 1] = 0x48;
    shared_blocks.os_aligned[0] = 0x49;
    shared_blocks.os_aligned[6] = 0x4a;
    if (pthread_setspecific(owner_exit_destructor_key,
            (void *)(uintptr_t)1) != 0)
        return (void *)(uintptr_t)3;
    if (owner_exit_cancel_mode) {
        /* Main cannot request cancellation until this wait has released the
         * mutex, which means both cleanup handlers are installed. The
         * allocation cleanup runs first, then unlocks the mutex, and the
         * TSD destructor must still allocate/free before the native owner
         * crosses its typed post-exit route. */
        if (pthread_mutex_lock(&owner_exit_cancel_mutex) != 0)
            return (void *)(uintptr_t)4;
        owner_exit_cancel_ready = 1;
        if (pthread_cond_signal(&owner_exit_cancel_cond) != 0) {
            (void)pthread_mutex_unlock(&owner_exit_cancel_mutex);
            return (void *)(uintptr_t)5;
        }
        pthread_cleanup_push(owner_exit_cancel_unlock,
                &owner_exit_cancel_mutex);
        pthread_cleanup_push(owner_exit_cancel_cleanup, NULL);
        while (owner_exit_cancel_ready)
            (void)pthread_cond_wait(&owner_exit_cancel_cond,
                    &owner_exit_cancel_mutex);
        pthread_cleanup_pop(0);
        pthread_cleanup_pop(1);
    }
    if (owner_exit_via_pthread_exit)
        pthread_exit(NULL);
    return NULL;
}

static void *release_worker(void *opaque)
{
    (void)opaque;
    if (shared_blocks.small == NULL || shared_blocks.non_direct_small == NULL
            || shared_blocks.medium == NULL || shared_blocks.large == NULL
            || shared_blocks.arena_singleton == NULL
            || shared_blocks.os_aligned == NULL)
        return (void *)(uintptr_t)1;
    if (shared_blocks.small[0] != 0x41 || shared_blocks.small[36] != 0x42
            || shared_blocks.non_direct_small[0] != 0x43
            || shared_blocks.non_direct_small[1024] != 0x44
            || shared_blocks.medium[0] != 0x43
            || shared_blocks.medium[64 * 1024 - 1] != 0x44
            || shared_blocks.large[0] != 0x45
            || shared_blocks.large[128 * 1024 - 1] != 0x46
            || shared_blocks.arena_singleton[0] != 0x47
            || shared_blocks.arena_singleton[1024 * 1024 - 1] != 0x48
            || shared_blocks.os_aligned[0] != 0x49
            || shared_blocks.os_aligned[6] != 0x4a)
        return (void *)(uintptr_t)2;
    /* The fresh B may inspect only its exact C inputs. The selected native
     * route answers from A's private recorded extents without giving B a
     * page, ledger, or route capability before the later frees. */
    if (malloc_usable_size(shared_blocks.small) < 37
            || malloc_usable_size(shared_blocks.non_direct_small) < 1025
            || malloc_usable_size(shared_blocks.medium) < 64 * 1024
            || malloc_usable_size(shared_blocks.large) < 128 * 1024
            || malloc_usable_size(shared_blocks.arena_singleton) < 1024 * 1024
            || malloc_usable_size(shared_blocks.os_aligned) < 7)
        return (void *)(uintptr_t)3;

    free(shared_blocks.os_aligned);
    free(shared_blocks.arena_singleton);
    free(shared_blocks.large);
    free(shared_blocks.medium);
    free(shared_blocks.non_direct_small);
    free(shared_blocks.small);
    shared_blocks.os_aligned = NULL;
    shared_blocks.arena_singleton = NULL;
    shared_blocks.large = NULL;
    shared_blocks.medium = NULL;
    shared_blocks.non_direct_small = NULL;
    shared_blocks.small = NULL;
    return NULL;
}

/* The sole mapped-regular source result requires a live medium client and an
 * immediate local free head in the same page. It is not a second C-specific
 * route: B still presents only the surviving C address to the typed native
 * post-exit capability. */
static void *sole_owner_worker(void *opaque)
{
    unsigned char *returned_medium;

    (void)opaque;
    returned_medium = malloc(64 * 1024);
    shared_blocks.sole_medium = malloc(64 * 1024);
    if (returned_medium == NULL || shared_blocks.sole_medium == NULL)
        return (void *)(uintptr_t)1;
    returned_medium[0] = 0x51;
    shared_blocks.sole_medium[0] = 0x52;
    shared_blocks.sole_medium[64 * 1024 - 1] = 0x53;
    free(returned_medium);
    return NULL;
}

static void *sole_release_worker(void *opaque)
{
    (void)opaque;
    if (shared_blocks.sole_medium == NULL)
        return (void *)(uintptr_t)1;
    if (shared_blocks.sole_medium[0] != 0x52
            || shared_blocks.sole_medium[64 * 1024 - 1] != 0x53)
        return (void *)(uintptr_t)2;
    if (malloc_usable_size(shared_blocks.sole_medium) < 64 * 1024)
        return (void *)(uintptr_t)3;

    free(shared_blocks.sole_medium);
    shared_blocks.sole_medium = NULL;
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)3;
    unsigned char *after;

    if (pthread_key_create(&owner_exit_destructor_key,
            owner_exit_destructor) != 0)
        return 1;
    for (unsigned int round = 0; round < 3; ++round) {
        owner_exit_destructor_calls = 0;
        owner_exit_destructor_failed = 0;
        owner_exit_cancel_mode = 0;
        /* Exercise both thread-entry return and direct pthread_exit. Both
         * must run user destructors before A's aggregate leaves its Theap. */
        owner_exit_via_pthread_exit = (round & 1) != 0;
        if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
            return 2;
        if (pthread_join(owner, &result) != 0 || result != NULL)
            return 3;
        if (owner_exit_destructor_calls != 1 || owner_exit_destructor_failed)
            return 4;
        if (pthread_create(&releaser, NULL, release_worker, NULL) != 0)
            return 5;
        result = (void *)(uintptr_t)6;
        if (pthread_join(releaser, &result) != 0 || result != NULL)
            return 7;
    }

    /* Cancellation is the third thread-exit entrance. It must execute the
     * cleanup allocation, TSD allocation, typed A-side aggregate teardown,
     * and B's terminal releases in that order. `PTHREAD_CANCELED` proves the
     * cancellation path did not accidentally return through the normal owner
     * exit branch. */
    owner_exit_destructor_calls = 0;
    owner_exit_destructor_failed = 0;
    owner_exit_cancel_cleanup_calls = 0;
    owner_exit_cancel_cleanup_failed = 0;
    owner_exit_cancel_mode = 1;
    owner_exit_cancel_ready = 0;
    owner_exit_via_pthread_exit = 0;
    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 16;
    if (pthread_mutex_lock(&owner_exit_cancel_mutex) != 0)
        return 17;
    while (!owner_exit_cancel_ready) {
        if (pthread_cond_wait(&owner_exit_cancel_cond,
                &owner_exit_cancel_mutex) != 0) {
            (void)pthread_mutex_unlock(&owner_exit_cancel_mutex);
            return 18;
        }
    }
    if (pthread_mutex_unlock(&owner_exit_cancel_mutex) != 0)
        return 19;
    if (pthread_cancel(owner) != 0)
        return 20;
    result = NULL;
    if (pthread_join(owner, &result) != 0 || result != PTHREAD_CANCELED)
        return 21;
    if (owner_exit_cancel_cleanup_calls != 1 || owner_exit_cancel_cleanup_failed
            || owner_exit_destructor_calls != 1 || owner_exit_destructor_failed)
        return 22;
    if (pthread_create(&releaser, NULL, release_worker, NULL) != 0)
        return 23;
    result = (void *)(uintptr_t)24;
    if (pthread_join(releaser, &result) != 0 || result != NULL)
        return 25;
    owner_exit_cancel_mode = 0;
    if (pthread_key_delete(owner_exit_destructor_key) != 0)
        return 8;

    for (unsigned int round = 0; round < 3; ++round) {
        if (pthread_create(&owner, NULL, sole_owner_worker, NULL) != 0)
            return 9;
        if (pthread_join(owner, &result) != 0 || result != NULL)
            return 10;
        if (pthread_create(&releaser, NULL, sole_release_worker, NULL) != 0)
            return 11;
        result = (void *)(uintptr_t)12;
        if (pthread_join(releaser, &result) != 0 || result != NULL)
            return 13;
    }

    /* B's final post-exit free and its normal runtime finish must restore
     * ticket zero before the initial thread can allocate again. */
    after = malloc(53);
    if (after == NULL)
        return 14;
    after[0] = 0x45;
    after[52] = 0x46;
    if (after[0] != 0x45 || after[52] != 0x46)
        return 15;
    free(after);

    puts("native mimalloc owner exit ok");
    return 0;
}
