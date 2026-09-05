/* Ordinary installed Linux/x86-64 directory consumer.
 *
 * The caller provides one prepared directory containing `alpha`, `beta`, and
 * `nested`. This consumer uses the installed product's public scandir/ftw/nftw
 * interfaces, C allocation boundary, and selected callback records without
 * adding pathname creation, general filesystem policy, or a dynamic runtime.
 * It also makes one pending selected-worker cancellation request while each
 * `nftw`/`ftw` callback is active. Pinned musl disables cancellation across
 * `do_nftw`, so the callback's `pthread_testcancel` returns, the traversal
 * releases its resources and restores the caller state, and a later explicit
 * test point delivers the pending request.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this consumer requires native Linux/x86-64 little-endian LP64"
#endif

#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>

enum {
    CANCELLATION_NFTW = 1,
    CANCELLATION_FTW = 2,
};

static int keep_visible(const struct dirent *entry)
{
    return !(entry->d_name[0] == '.' &&
        (entry->d_name[1] == '\0' ||
         (entry->d_name[1] == '.' && entry->d_name[2] == '\0')));
}

struct traversal_result {
    int entries;
    int directories;
    int files;
    int invalid;
};

static struct traversal_result traversal;

static int ftw_entries;
static int ftw_directories;
static int ftw_files;
static int ftw_invalid;

static int visit_ftw(const char *path, const struct stat *metadata, int kind)
{
    if (path == 0 || metadata == 0) {
        ftw_invalid = 1;
        return 1;
    }
    ++ftw_entries;
    if (kind == FTW_D)
        ++ftw_directories;
    else if (kind == FTW_F)
        ++ftw_files;
    else
        ftw_invalid = 1;
    return 0;
}

static int visit(const char *path, const struct stat *metadata, int kind,
    struct FTW *info)
{
    if (path == 0 || metadata == 0 || info == 0 || info->level < 0 ||
        info->base < 0) {
        traversal.invalid = 1;
        return 1;
    }
    ++traversal.entries;
    if (kind == FTW_D)
        ++traversal.directories;
    else if (kind == FTW_F)
        ++traversal.files;
    else
        traversal.invalid = 1;
    return 0;
}

struct cancellation_round {
    const char *path;
    int kind;
    volatile int callback_ready;
    volatile int release_callback;
    volatile int callback_testcancel_returned;
    volatile int traversal_returned;
    volatile int restored_enabled;
    volatile int callback_count;
    volatile int failure;
};

static struct cancellation_round *active_cancellation_round;

static void cancellation_pause(void)
{
    __asm__ volatile("" ::: "memory");
}

static void wait_for_nonzero(volatile int *value)
{
    while (__atomic_load_n(value, __ATOMIC_ACQUIRE) == 0)
        cancellation_pause();
}

static int observe_pending_cancellation(void)
{
    struct cancellation_round *round = active_cancellation_round;
    int previous_state = -1;
    int observed_state = -1;
    int count;

    if (round == 0) {
        return 1;
    }
    count = __atomic_add_fetch(&round->callback_count, 1, __ATOMIC_ACQ_REL);
    if (count != 1)
        return 0;
    __atomic_store_n(&round->callback_ready, 1, __ATOMIC_RELEASE);
    wait_for_nonzero(&round->release_callback);

    /* Pinned `nftw.c` has already disabled cancellation before this callback.
     * Repeating the disable operation reports that state without enabling a
     * pending request; the explicit test point must consequently return. */
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_state) != 0 ||
        previous_state != PTHREAD_CANCEL_DISABLE) {
        __atomic_store_n(&round->failure, 1, __ATOMIC_RELEASE);
        return 1;
    }
    pthread_testcancel();
    if (pthread_setcancelstate(previous_state, &observed_state) != 0 ||
        observed_state != PTHREAD_CANCEL_DISABLE) {
        __atomic_store_n(&round->failure, 2, __ATOMIC_RELEASE);
        return 1;
    }
    __atomic_store_n(&round->callback_testcancel_returned, 1, __ATOMIC_RELEASE);
    return 0;
}

static int visit_cancellation_nftw(const char *path,
    const struct stat *metadata, int kind, struct FTW *info)
{
    if (path == 0 || metadata == 0 || info == 0)
        return 1;
    return observe_pending_cancellation();
}

static int visit_cancellation_ftw(const char *path,
    const struct stat *metadata, int kind)
{
    if (path == 0 || metadata == 0)
        return 1;
    return observe_pending_cancellation();
}

static void *cancellation_worker(void *opaque)
{
    struct cancellation_round *round = opaque;
    int result;
    int previous_state = -1;

    if (round->kind == CANCELLATION_NFTW)
        result = nftw(round->path, visit_cancellation_nftw, 4, FTW_PHYS);
    else
        result = ftw(round->path, visit_cancellation_ftw, 4);
    if (result != 0 || __atomic_load_n(&round->failure, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&round->callback_count, __ATOMIC_ACQUIRE) != 4) {
        __atomic_store_n(&round->failure, 3, __ATOMIC_RELEASE);
        return 0;
    }
    __atomic_store_n(&round->traversal_returned, 1, __ATOMIC_RELEASE);

    /* `nftw` restored the worker's enabled state only after the walk closed
     * every directory/CWD resource. Record that restoration before this known
     * selected cancellation point deliberately consumes the pending request. */
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_state) != 0 ||
        previous_state != PTHREAD_CANCEL_ENABLE ||
        pthread_setcancelstate(previous_state, 0) != 0) {
        __atomic_store_n(&round->failure, 4, __ATOMIC_RELEASE);
        return 0;
    }
    __atomic_store_n(&round->restored_enabled, 1, __ATOMIC_RELEASE);
    pthread_testcancel();
    __atomic_store_n(&round->failure, 5, __ATOMIC_RELEASE);
    return 0;
}

static int run_cancellation_round(const char *path, int kind)
{
    struct cancellation_round round = {
        .path = path,
        .kind = kind,
        .callback_ready = 0,
        .release_callback = 0,
        .callback_testcancel_returned = 0,
        .traversal_returned = 0,
        .restored_enabled = 0,
        .callback_count = 0,
        .failure = 0,
    };
    pthread_t thread;
    void *result = 0;

    active_cancellation_round = &round;
    if (pthread_create(&thread, 0, cancellation_worker, &round) != 0) {
        active_cancellation_round = 0;
        return -1;
    }
    wait_for_nonzero(&round.callback_ready);
    if (pthread_cancel(thread) != 0) {
        active_cancellation_round = 0;
        return -1;
    }
    __atomic_store_n(&round.release_callback, 1, __ATOMIC_RELEASE);
    if (pthread_join(thread, &result) != 0 || result != PTHREAD_CANCELED ||
        __atomic_load_n(&round.callback_testcancel_returned, __ATOMIC_ACQUIRE) != 1 ||
        __atomic_load_n(&round.traversal_returned, __ATOMIC_ACQUIRE) != 1 ||
        __atomic_load_n(&round.restored_enabled, __ATOMIC_ACQUIRE) != 1 ||
        __atomic_load_n(&round.callback_count, __ATOMIC_ACQUIRE) != 4 ||
        __atomic_load_n(&round.failure, __ATOMIC_ACQUIRE) != 0) {
        active_cancellation_round = 0;
        return -1;
    }
    active_cancellation_round = 0;
    return 0;
}

int main(int argc, char **argv)
{
    struct dirent **entries = 0;
    int count;
    int index;

    if (argc != 2)
        return 64;
    errno = E2BIG;
    count = scandir(argv[1], &entries, keep_visible, alphasort);
    if (count != 3 || entries == 0 ||
        entries[0]->d_name[0] != 'a' || entries[1]->d_name[0] != 'b' ||
        entries[2]->d_name[0] != 'n' || errno != E2BIG)
        return 65;
    for (index = 0; index != count; ++index)
        free(entries[index]);
    free(entries);

    ftw_entries = 0;
    ftw_directories = 0;
    ftw_files = 0;
    ftw_invalid = 0;
    errno = EDOM;
    if (ftw(argv[1], visit_ftw, 4) != 0 || errno != EDOM ||
        ftw_entries != 4 || ftw_directories != 2 || ftw_files != 2 ||
        ftw_invalid)
        return 66;

    traversal.entries = 0;
    traversal.directories = 0;
    traversal.files = 0;
    traversal.invalid = 0;
    errno = EDOM;
    if (nftw(argv[1], visit, 4, FTW_PHYS) != 0 || errno != EDOM ||
        traversal.entries != 4 || traversal.directories != 2 ||
        traversal.files != 2 || traversal.invalid)
        return 67;
    if (run_cancellation_round(argv[1], CANCELLATION_NFTW) != 0)
        return 68;
    if (run_cancellation_round(argv[1], CANCELLATION_FTW) != 0)
        return 69;
    return 0;
}
