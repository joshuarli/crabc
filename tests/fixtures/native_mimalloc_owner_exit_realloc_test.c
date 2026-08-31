/*
 * A exits with one source-shaped sole mapped-medium route. B's exact
 * `realloc` observes A's PageMap source facts but cannot enter A's torn-down
 * Theap or use B's engine as a replacement route. It must fail while leaving
 * A's client intact, after which generic pointer-first `free` releases it.
 *
 * This is a selected-shadow lifecycle fixture, not a general cross-thread
 * realloc claim. Its synchronized A/B handoff proves that the rejected
 * detached reallocation preserves A's original C client and contents, while
 * an independently allocated B-local client still supports replacement.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned char *shared_medium;
static size_t replacement_size;
static pthread_key_t terminal_proof_destructor_key;
static unsigned char *terminal_proof_replacement;
static pthread_mutex_t terminal_proof_cancel_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t terminal_proof_cancel_cond = PTHREAD_COND_INITIALIZER;
enum terminal_proof_exit_kind {
    TERMINAL_PROOF_RETURN,
    TERMINAL_PROOF_PTHREAD_EXIT,
    TERMINAL_PROOF_CANCELLATION,
};
static enum terminal_proof_exit_kind terminal_proof_exit_kind;
static int terminal_proof_cancel_ready;
static unsigned int terminal_proof_cleanup_calls;
static int terminal_proof_cleanup_failed;
static unsigned int terminal_proof_destructor_calls;
static int terminal_proof_destructor_failed;

static int terminal_proof_replacement_is_valid(const unsigned char *replacement)
{
    if (replacement_size == 0)
        return replacement[0] == 0;
    if (replacement[0] != 0x61)
        return 0;
    if (replacement_size >= 4096 && replacement[4095] != 0x62)
        return 0;
    if (replacement_size >= 64 * 1024
            && replacement[64 * 1024 - 1] != 0x63)
        return 0;
    return 1;
}

/* `pthread_exit` and cancellation invoke this cleanup before their TSD
 * destructors. It covers the user-owned phase between B's terminal A free and
 * the native lifecycle finish: a completed A proof remains opaque and
 * unreleased while B independently resumes, uses, and re-parks its own
 * session. */
static void terminal_proof_cleanup(void *opaque)
{
    unsigned char *continued;

    (void)opaque;
    errno = 0;
    continued = malloc(73);
    if (continued == NULL) {
        terminal_proof_cleanup_failed = 1;
    } else {
        continued[0] = 0x73;
        continued[72] = 0x74;
        if (continued[0] != 0x73 || continued[72] != 0x74)
            terminal_proof_cleanup_failed = 1;
        free(continued);
    }
    terminal_proof_cleanup_calls += 1;
}

static void terminal_proof_cancel_unlock(void *opaque)
{
    (void)pthread_mutex_unlock((pthread_mutex_t *)opaque);
}

static int terminal_proof_cleanup_order_is_valid(void)
{
    unsigned int expected = terminal_proof_exit_kind == TERMINAL_PROOF_RETURN
        ? 0
        : 1;

    return terminal_proof_cleanup_calls == expected;
}

/* This destructor runs after B has terminally freed A's route client, but
 * before libc calls the native owner finish. It proves that B may continue
 * its own local session at the exact pthread TSD ordering point; A's opaque
 * completion remains pending until that later native finish. */
static void terminal_proof_destructor(void *value)
{
    unsigned char *replacement = terminal_proof_replacement;
    unsigned char *resized;

    if (value == NULL || replacement == NULL
            || !terminal_proof_cleanup_order_is_valid()) {
        terminal_proof_destructor_failed = 1;
    } else {
        errno = 0;
        resized = realloc(replacement, 256 * 1024);
        if (resized == NULL) {
            terminal_proof_destructor_failed = 1;
        } else {
            if (!terminal_proof_replacement_is_valid(resized))
                terminal_proof_destructor_failed = 1;
            free(resized);
        }
    }
    terminal_proof_replacement = NULL;
    terminal_proof_destructor_calls += 1;
}

static void *owner_worker(void *opaque)
{
    (void)opaque;
    shared_medium = malloc(64 * 1024);
    if (shared_medium == NULL)
        return (void *)(uintptr_t)1;
    shared_medium[0] = 0x61;
    shared_medium[4095] = 0x62;
    shared_medium[64 * 1024 - 1] = 0x63;
    return NULL;
}

static void *release_worker(void *opaque)
{
    unsigned char *replacement;
    unsigned char *continued;
    unsigned char *local;

    (void)opaque;
    if (shared_medium == NULL)
        return (void *)(uintptr_t)1;
    errno = 0;
    replacement = realloc(shared_medium, SIZE_MAX);
    if (replacement != NULL)
        return (void *)(uintptr_t)2;
    if (errno != ENOMEM)
        return (void *)(uintptr_t)3;
    if (shared_medium[0] != 0x61
            || shared_medium[4095] != 0x62
            || shared_medium[64 * 1024 - 1] != 0x63)
        return (void *)(uintptr_t)4;

    errno = 0;
    replacement = realloc(shared_medium, replacement_size);
    if (replacement != NULL)
        return (void *)(uintptr_t)5;
    if (errno != ENOMEM)
        return (void *)(uintptr_t)6;
    if (shared_medium[0] != 0x61
            || shared_medium[4095] != 0x62
            || shared_medium[64 * 1024 - 1] != 0x63)
        return (void *)(uintptr_t)7;
    free(shared_medium);
    shared_medium = NULL;

    replacement = malloc(64 * 1024);
    if (replacement == NULL)
        return (void *)(uintptr_t)8;
    replacement[0] = 0x61;
    replacement[4095] = 0x62;
    replacement[64 * 1024 - 1] = 0x63;
    replacement = realloc(replacement, replacement_size);
    if (replacement == NULL)
        return (void *)(uintptr_t)9;
    if (!terminal_proof_replacement_is_valid(replacement)) {
        free(replacement);
        return (void *)(uintptr_t)10;
    }
    /* Generic pointer-first free has terminally released A's client. B now
     * exercises only its own ordinary local replacement before its source
     * finish settles the opaque A completion. */
    errno = 0;
    continued = realloc(replacement, 128 * 1024);
    if (continued == NULL)
        return (void *)(uintptr_t)11;
    if (!terminal_proof_replacement_is_valid(continued)) {
        free(continued);
        return (void *)(uintptr_t)12;
    }
    replacement = continued;
    local = malloc(73);
    if (local == NULL) {
        free(replacement);
        return (void *)(uintptr_t)13;
    }
    local[0] = 0x71;
    local[72] = 0x72;
    if (local[0] != 0x71 || local[72] != 0x72) {
        free(local);
        free(replacement);
        return (void *)(uintptr_t)14;
    }
    free(local);
    terminal_proof_replacement = replacement;
    if (pthread_setspecific(terminal_proof_destructor_key, (void *)(uintptr_t)1) != 0) {
        terminal_proof_replacement = NULL;
        free(replacement);
        return (void *)(uintptr_t)15;
    }
    if (terminal_proof_exit_kind == TERMINAL_PROOF_CANCELLATION) {
        /* Main cannot request deferred cancellation until both cleanup
         * handlers are installed and B
         * already holds A's terminal proof. The allocation cleanup must run
         * first, then unlock, then the TSD destructor continues B's local
         * `realloc` before the native finish can release A's admission. */
        if (pthread_mutex_lock(&terminal_proof_cancel_mutex) != 0)
            return (void *)(uintptr_t)16;
        terminal_proof_cancel_ready = 1;
        if (pthread_cond_signal(&terminal_proof_cancel_cond) != 0) {
            (void)pthread_mutex_unlock(&terminal_proof_cancel_mutex);
            return (void *)(uintptr_t)17;
        }
        pthread_cleanup_push(terminal_proof_cancel_unlock,
                &terminal_proof_cancel_mutex);
        pthread_cleanup_push(terminal_proof_cleanup, NULL);
        while (terminal_proof_cancel_ready)
            (void)pthread_cond_wait(&terminal_proof_cancel_cond,
                    &terminal_proof_cancel_mutex);
        pthread_cleanup_pop(0);
        pthread_cleanup_pop(1);
        return NULL;
    }
    if (terminal_proof_exit_kind == TERMINAL_PROOF_PTHREAD_EXIT) {
        pthread_cleanup_push(terminal_proof_cleanup, NULL);
        pthread_exit(NULL);
        pthread_cleanup_pop(0);
    }
    return NULL;
}

int main(void)
{
    pthread_t owner;
    pthread_t releaser;
    void *result = (void *)(uintptr_t)5;
    unsigned char *after;

    static const struct {
        size_t replacement_size;
        enum terminal_proof_exit_kind exit_kind;
    } cases[] = {
        { 4096, TERMINAL_PROOF_RETURN },
        { 128 * 1024, TERMINAL_PROOF_PTHREAD_EXIT },
        { 0, TERMINAL_PROOF_PTHREAD_EXIT },
        { 4096, TERMINAL_PROOF_CANCELLATION },
    };

    if (pthread_key_create(&terminal_proof_destructor_key,
            terminal_proof_destructor) != 0)
        return 1;
    for (unsigned int round = 0;
            round < sizeof(cases) / sizeof(cases[0]);
            ++round) {
        replacement_size = cases[round].replacement_size;
        terminal_proof_replacement = NULL;
        terminal_proof_exit_kind = cases[round].exit_kind;
        terminal_proof_cancel_ready = 0;
        terminal_proof_cleanup_calls = 0;
        terminal_proof_cleanup_failed = 0;
        terminal_proof_destructor_calls = 0;
        terminal_proof_destructor_failed = 0;
        if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
            return 1;
        if (pthread_join(owner, &result) != 0 || result != NULL)
            return 2;
        if (pthread_create(&releaser, NULL, release_worker, NULL) != 0)
            return 3;
        result = (void *)(uintptr_t)6;
        if (terminal_proof_exit_kind == TERMINAL_PROOF_CANCELLATION) {
            if (pthread_mutex_lock(&terminal_proof_cancel_mutex) != 0)
                return 4;
            while (!terminal_proof_cancel_ready) {
                if (pthread_cond_wait(&terminal_proof_cancel_cond,
                        &terminal_proof_cancel_mutex) != 0) {
                    (void)pthread_mutex_unlock(&terminal_proof_cancel_mutex);
                    return 5;
                }
            }
            if (pthread_mutex_unlock(&terminal_proof_cancel_mutex) != 0)
                return 6;
            if (pthread_cancel(releaser) != 0)
                return 7;
            result = NULL;
            if (pthread_join(releaser, &result) != 0 || result != PTHREAD_CANCELED)
                return 8;
        } else if (pthread_join(releaser, &result) != 0 || result != NULL) {
            return 9;
        }
        if (terminal_proof_destructor_calls != 1
                || terminal_proof_destructor_failed
                || !terminal_proof_cleanup_order_is_valid()
                || terminal_proof_cleanup_failed
                || terminal_proof_replacement != NULL)
            return 10;
    }

    if (pthread_key_delete(terminal_proof_destructor_key) != 0)
        return 11;
    after = malloc(53);
    if (after == NULL)
        return 12;
    after[0] = 0x63;
    after[52] = 0x64;
    if (after[0] != 0x63 || after[52] != 0x64)
        return 13;
    free(after);

    puts("native mimalloc owner exit realloc ok");
    return 0;
}
