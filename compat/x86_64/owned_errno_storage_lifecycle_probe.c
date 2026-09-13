/* Installed native x86 errno/h_errno storage lifecycle workload.
 *
 * This source is compiled once through the supplied installed candidate headers.
 * The unchanged static object is linked with pinned musl and the supplied
 * static candidate product; the unchanged dynamic object is linked with both
 * shared providers.  It exercises no resolver configuration, DNS, or network
 * I/O.  The loaded DSO calls only the installed public accessors.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this workload requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#error "this workload requires the installed GNU errno/netdb/pthread profile"
#endif

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>

#ifdef CRABC_ERRNO_STORAGE_DYNAMIC_DSO
#include <dlfcn.h>
#endif

/* `netdb.h` deliberately spells h_errno through its public accessor.  This
 * link-visible object spelling proves the selected bootstrapped-main fallback
 * remains the accessor's exact main-thread storage; it is never used as a
 * worker status channel. */
extern int crabc_link_visible_h_errno __asm__("h_errno");

#ifdef CRABC_ERRNO_STORAGE_STATIC_ALIAS
/* Musl's archive-only allocator alias is deliberately absent from shared
 * dynsym.  This static-only declaration proves its same-address weak alias
 * behavior without turning it into a shared application import. */
extern int *___errno_location(void);
#endif

#define TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)
_Static_assert(TYPE_IS(__typeof__(__errno_location()), int *),
    "installed __errno_location result declaration");
_Static_assert(TYPE_IS(__typeof__(__h_errno_location()), int *),
    "installed __h_errno_location result declaration");
_Static_assert(TYPE_IS(__typeof__(&errno), int *),
    "installed errno macro expression");
_Static_assert(TYPE_IS(__typeof__(&h_errno), int *),
    "installed h_errno macro expression");
_Static_assert(_Alignof(int) == 4,
    "native x86 h_errno source alignment");

struct errno_storage_snapshot {
    int *errno_location;
    int errno_value;
    int *h_errno_location;
    int h_errno_value;
};

typedef int (*errno_storage_snapshot_fn)(struct errno_storage_snapshot *);

struct worker_state {
    _Atomic int ready;
    _Atomic int release;
    int *errno_location;
    int *h_errno_location;
    int errno_value;
    int h_errno_value;
    errno_storage_snapshot_fn dso_snapshot;
    int failure;
};

enum {
    MAIN_ERRNO = EACCES,
    MAIN_H_ERRNO = NO_RECOVERY,
    WORKER_ERRNO = E2BIG,
    WORKER_H_ERRNO = TRY_AGAIN,
};

static int snapshot_matches(const struct errno_storage_snapshot *snapshot,
    int *errno_location, int errno_value, int *h_errno_location, int h_errno_value)
{
    return snapshot->errno_location == errno_location &&
        snapshot->errno_value == errno_value &&
        snapshot->h_errno_location == h_errno_location &&
        snapshot->h_errno_value == h_errno_value;
}

static int locations_are_int_aligned(const int *errno_location, const int *h_errno_location)
{
    return (uintptr_t)errno_location % _Alignof(int) == 0 &&
        (uintptr_t)h_errno_location % _Alignof(int) == 0;
}

static void *storage_worker(void *opaque)
{
    struct worker_state *state = opaque;
    struct errno_storage_snapshot snapshot;

    state->errno_location = __errno_location();
    state->h_errno_location = __h_errno_location();
    if (!state->errno_location || !state->h_errno_location ||
        !locations_are_int_aligned(state->errno_location, state->h_errno_location) ||
        __errno_location() != state->errno_location ||
        __h_errno_location() != state->h_errno_location) {
        state->failure = 1;
        atomic_store_explicit(&state->ready, 1, memory_order_release);
        return 0;
    }
    if (*state->errno_location != 0 || *state->h_errno_location != 0) {
        state->failure = 2;
        atomic_store_explicit(&state->ready, 1, memory_order_release);
        return 0;
    }

    errno = WORKER_ERRNO;
    h_errno = WORKER_H_ERRNO;
    state->errno_value = errno;
    state->h_errno_value = h_errno;
    if (*state->errno_location != WORKER_ERRNO ||
        *state->h_errno_location != WORKER_H_ERRNO ||
        __errno_location() != state->errno_location ||
        __h_errno_location() != state->h_errno_location) {
        state->failure = 3;
        atomic_store_explicit(&state->ready, 1, memory_order_release);
        return 0;
    }
    if (state->dso_snapshot &&
        (state->dso_snapshot(&snapshot) != 0 ||
         !snapshot_matches(&snapshot, state->errno_location, WORKER_ERRNO,
             state->h_errno_location, WORKER_H_ERRNO))) {
        state->failure = 4;
        atomic_store_explicit(&state->ready, 1, memory_order_release);
        return 0;
    }

    atomic_store_explicit(&state->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->release, memory_order_acquire)) {
    }
    if (*state->errno_location != WORKER_ERRNO ||
        *state->h_errno_location != WORKER_H_ERRNO ||
        __errno_location() != state->errno_location ||
        __h_errno_location() != state->h_errno_location) {
        state->failure = 5;
    }
    return 0;
}

static int run_storage_lifecycle(errno_storage_snapshot_fn dso_snapshot)
{
    struct worker_state state = { 0 };
    struct errno_storage_snapshot snapshot;
    pthread_t worker;
    void *worker_result = 0;
    int *main_errno = __errno_location();
    int *main_h_errno = __h_errno_location();

    if (!main_errno || !main_h_errno ||
        !locations_are_int_aligned(main_errno, main_h_errno) ||
        main_h_errno != &crabc_link_visible_h_errno ||
        __errno_location() != main_errno || __h_errno_location() != main_h_errno)
        return 10;
#ifdef CRABC_ERRNO_STORAGE_STATIC_ALIAS
    if (___errno_location() != main_errno)
        return 11;
#endif
    errno = MAIN_ERRNO;
    h_errno = MAIN_H_ERRNO;
    if (*main_errno != MAIN_ERRNO || *main_h_errno != MAIN_H_ERRNO ||
        crabc_link_visible_h_errno != MAIN_H_ERRNO)
        return 12;
    if (dso_snapshot &&
        (dso_snapshot(&snapshot) != 0 ||
         !snapshot_matches(&snapshot, main_errno, MAIN_ERRNO, main_h_errno, MAIN_H_ERRNO)))
        return 13;

    state.dso_snapshot = dso_snapshot;
    if (pthread_create(&worker, 0, storage_worker, &state) != 0)
        return 14;
    while (!atomic_load_explicit(&state.ready, memory_order_acquire)) {
    }
    if (state.failure || !state.errno_location || !state.h_errno_location ||
        state.errno_location == main_errno || state.h_errno_location == main_h_errno ||
        state.errno_value != WORKER_ERRNO || state.h_errno_value != WORKER_H_ERRNO ||
        *main_errno != MAIN_ERRNO || *main_h_errno != MAIN_H_ERRNO)
        return 15;

    /* The selected owned pthread source returns a positive EBUSY result for a
     * live joinable worker.  Its documented error path must not publish that
     * result through the caller's errno location. */
    if (pthread_tryjoin_np(worker, 0) != EBUSY || errno != MAIN_ERRNO)
        return 16;

    atomic_store_explicit(&state.release, 1, memory_order_release);
    if (pthread_join(worker, &worker_result) != 0 || worker_result || state.failure)
        return 17;

    /* The worker's TLS mapping can now be released.  Do not read or
     * dereference state.errno_location/state.h_errno_location after this join. */
    if (*main_errno != MAIN_ERRNO || *main_h_errno != MAIN_H_ERRNO ||
        !locations_are_int_aligned(main_errno, main_h_errno) ||
        __errno_location() != main_errno || __h_errno_location() != main_h_errno)
        return 18;
    if (dso_snapshot &&
        (dso_snapshot(&snapshot) != 0 ||
         !snapshot_matches(&snapshot, main_errno, MAIN_ERRNO, main_h_errno, MAIN_H_ERRNO)))
        return 19;
    return 0;
}

int main(void)
{
#ifdef CRABC_ERRNO_STORAGE_DYNAMIC_DSO
    void *handle = dlopen("/usr/lib/liberrno-storage-lifecycle-probe.so", RTLD_NOW | RTLD_LOCAL);
    errno_storage_snapshot_fn dso_snapshot;
    int result;

    if (!handle)
        return 30;
    dso_snapshot = (errno_storage_snapshot_fn)dlsym(handle, "errno_storage_lifecycle_snapshot");
    if (!dso_snapshot) {
        (void)dlclose(handle);
        return 31;
    }
    result = run_storage_lifecycle(dso_snapshot);
    if (dlclose(handle) != 0)
        return 32;
#else
    int result = run_storage_lifecycle(0);
#endif
    if (result != 0)
        return result;
    if (write(1, "errno-storage-lifecycle: PASS\n", 30) != 30)
        return 40;
    return 0;
}
