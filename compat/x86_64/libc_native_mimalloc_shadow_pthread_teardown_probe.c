/* Selected static x86 native-mimalloc pthread teardown fixture.
 *
 * The pinned-musl arm establishes the ordinary C/POSIX worker observations.
 * The native-shadow arm is a real `-nostdlib -static` owned-runtime process:
 * its entry first proves that a worker created before `__libc_start_main`
 * receives EAGAIN without invoking user code, then starts libc normally.
 * Normal return, pthread_exit, and deferred pthread cancellation each make a
 * user TSD destructor allocate and free before the selected native owner is
 * finished. A final worker also reaches ordinary `atexit` only after the
 * bootstrapped thread called `pthread_exit`; that callback allocates and frees
 * after the final worker's normal-return or explicit-exit native finish. It
 * does not qualify main-thread or process shutdown, dynamic loader ownership,
 * cross-worker pointer transfer, allocator promotion, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define CRABC_TYPE_IS(actual, expected) \
    __builtin_types_compatible_p(actual, expected)

enum {
    CRABC_WAIT_LIMIT = 100000000u,
    CRABC_NORMAL_MARKER = 0x13579bdfu,
    CRABC_EXPLICIT_MARKER = 0x2468ace0u,
};

_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_create),
    int (*)(pthread_t *__restrict, const pthread_attr_t *__restrict,
        void *(*)(void *), void *__restrict)), "pthread_create declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_join),
    int (*)(pthread_t, void **)), "pthread_join declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_cancel),
    int (*)(pthread_t)), "pthread_cancel declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_testcancel),
    void (*)(void)), "pthread_testcancel declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_key_create),
    int (*)(pthread_key_t *, void (*)(void *))), "pthread_key_create declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&malloc), void *(*)(size_t)),
    "malloc declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&free), void (*)(void *)),
    "free declaration");
_Static_assert(PTHREAD_CANCELED == (void *)-1,
    "pthread cancellation result spelling");

struct teardown_round {
    volatile int ready;
    volatile int tsd_finished;
    volatile int failure;
    uintptr_t marker;
};

static pthread_key_t teardown_key;
static volatile int prestart_callback_count;
static void *final_worker_pre_teardown_allocation;

/* The runner writes only after `/proc` reports the bootstrapped task as a
 * zombie. Releasing a worker from an application flag before `pthread_exit`
 * has withdrawn the initial task would race the final-task decision. This
 * private test pipe adopts the existing last-thread evidence convention; it
 * does not select a public task-ID API or a dynamic runtime path. */
static volatile int final_worker_ready;

#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
extern size_t __crabc_x86_native_mimalloc_active_later_thread_count_test_audit(void);
#endif

#ifdef CRABC_NATIVE_INTERNAL_MALLOC_OVERRIDE
/* The replacement is intentionally strong. The candidate calls
 * pthread_atfork below, whose node allocation must remain on libc's direct
 * native internal seam and must therefore neither call this spelling nor
 * return its null refusal to the atfork registration. */
static volatile unsigned int replacement_malloc_calls;

void *malloc(size_t size)
{
    (void)size;
    __atomic_fetch_add(&replacement_malloc_calls, 1, __ATOMIC_RELEASE);
    return 0;
}
#endif

static void spin_pause(void)
{
    __asm__ volatile("pause" ::: "memory");
}

static int wait_for_nonzero(const volatile int *value)
{
    unsigned int spin;

    for (spin = 0; spin != CRABC_WAIT_LIMIT; ++spin) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) != 0)
            return 0;
        spin_pause();
    }
    return -1;
}

static void record_failure(struct teardown_round *round, int value)
{
    __atomic_store_n(&round->failure, value, __ATOMIC_RELEASE);
}

/* This runs while libc still owns the attached worker's native TLS owner.
 * If the native finish moved before selected TSD destructors, its allocation
 * would fail (or fail-stop) and the candidate process could not pass. */
static void native_allocation_tsd_destructor(void *opaque)
{
    struct teardown_round *round = opaque;
    void *allocation;

    if (pthread_getspecific(teardown_key) != 0) {
        record_failure(round, 101);
        return;
    }
    allocation = malloc(97);
    if (allocation == 0) {
        record_failure(round, 102);
        return;
    }
    ((volatile unsigned char *)allocation)[0] = 0x5a;
    free(allocation);
    __atomic_store_n(&round->tsd_finished, 1, __ATOMIC_RELEASE);
}

static int prepare_worker_teardown(struct teardown_round *round)
{
    void *allocation = malloc(10241);

    if (allocation == 0)
        return 1;
    ((volatile unsigned char *)allocation)[0] = 0xa5;
    free(allocation);
    if (pthread_setspecific(teardown_key, round) != 0)
        return 2;
    return 0;
}

static void *normal_return_worker(void *opaque)
{
    struct teardown_round *round = opaque;

    if (prepare_worker_teardown(round) != 0) {
        record_failure(round, 1);
        return 0;
    }
    return (void *)round->marker;
}

static void *explicit_exit_worker(void *opaque)
{
    struct teardown_round *round = opaque;

    if (prepare_worker_teardown(round) != 0) {
        record_failure(round, 2);
        return 0;
    }
    pthread_exit((void *)round->marker);
}

static void *deferred_cancel_worker(void *opaque)
{
    struct teardown_round *round = opaque;

    if (prepare_worker_teardown(round) != 0) {
        record_failure(round, 3);
        return 0;
    }
    __atomic_store_n(&round->ready, 1, __ATOMIC_RELEASE);
    for (;;)
        pthread_testcancel();
}

/* Pinned `_mi_thread_done` runs before its final-thread decision. A later
 * ordinary-exit callback may call malloc: the source sees the now-empty
 * default Theap and lazily creates a new one for this still-running final
 * task. This callback makes that post-finish allocation observable.  It also
 * frees a live block allocated by the same worker before `_mi_thread_done`.
 * Source collection abandons that old page, so its PageMap record must no
 * longer classify the reused Linux/TLS identity as the new owner. */
static void final_worker_atexit_allocation(void)
{
    void *allocation = malloc(257);
    void *pre_teardown_allocation = final_worker_pre_teardown_allocation;

    if (allocation == 0)
        _Exit(51);
    ((volatile unsigned char *)allocation)[0] = 0x3c;
    free(allocation);
    if (pre_teardown_allocation == 0)
        _Exit(53);
    free(pre_teardown_allocation);
    final_worker_pre_teardown_allocation = 0;
}

static void *final_worker_after_initial_pthread_exit(void *opaque)
{
    char release;
    void *allocation;

    (void)opaque;
    allocation = malloc(193);
    if (allocation == 0)
        _Exit(54);
    ((volatile unsigned char *)allocation)[0] = 0xc3;
    final_worker_pre_teardown_allocation = allocation;
    __atomic_store_n(&final_worker_ready, 1, __ATOMIC_RELEASE);
    if (read(STDIN_FILENO, &release, 1) != 1)
        _Exit(52);
    if (release == 'E')
        pthread_exit(0);
    if (release != 'R')
        _Exit(52);
    return 0;
}

static int run_return_round(
    void *(*worker)(void *), uintptr_t marker, int failure_base)
{
    pthread_t thread;
    void *result = 0;
    struct teardown_round round = {
        .ready = 0,
        .tsd_finished = 0,
        .failure = 0,
        .marker = marker,
    };

    if (pthread_create(&thread, 0, worker, &round) != 0)
        return failure_base + 1;
    if (pthread_join(thread, &result) != 0)
        return failure_base + 2;
    if (result != (void *)marker)
        return failure_base + 3;
    if (__atomic_load_n(&round.failure, __ATOMIC_ACQUIRE) != 0)
        return failure_base + 4;
    if (__atomic_load_n(&round.tsd_finished, __ATOMIC_ACQUIRE) != 1)
        return failure_base + 5;
    return 0;
}

static int run_deferred_cancellation_round(void)
{
    pthread_t thread;
    void *result = 0;
    struct teardown_round round = {
        .ready = 0,
        .tsd_finished = 0,
        .failure = 0,
        .marker = 0,
    };

    if (pthread_create(&thread, 0, deferred_cancel_worker, &round) != 0)
        return 31;
    if (wait_for_nonzero(&round.ready) != 0)
        return 32;
    if (pthread_cancel(thread) != 0)
        return 33;
    if (pthread_join(thread, &result) != 0)
        return 34;
    if (result != PTHREAD_CANCELED)
        return 35;
    if (__atomic_load_n(&round.failure, __ATOMIC_ACQUIRE) != 0)
        return 36;
    if (__atomic_load_n(&round.tsd_finished, __ATOMIC_ACQUIRE) != 1)
        return 37;
    return 0;
}

static void *prestart_callback(void *opaque)
{
    (void)opaque;
    __atomic_fetch_add(&prestart_callback_count, 1, __ATOMIC_RELEASE);
    return 0;
}

/* Called by the candidate-only entry shim after libc's static TLS bootstrap
 * but before __libc_start_main installs the native process owner. Inactive is
 * the one recoverable attach result: the parent must return EAGAIN only after
 * the child has stopped, without exposing a callback or pthread handle. */
int crabc_x86_64_native_mimalloc_shadow_prestart_rejection(void)
{
    pthread_t thread;
    int result;

    __atomic_store_n(&prestart_callback_count, 0, __ATOMIC_RELEASE);
    result = pthread_create(&thread, 0, prestart_callback, 0);
    if (result != EAGAIN)
        return 1;
    return __atomic_load_n(&prestart_callback_count, __ATOMIC_ACQUIRE) == 0
        ? 0 : 2;
}

int main(void)
{
    int result;

#ifdef CRABC_NATIVE_INTERNAL_MALLOC_OVERRIDE
    if (pthread_atfork(0, 0, 0) != 0)
        return 41;
    return __atomic_load_n(&replacement_malloc_calls, __ATOMIC_ACQUIRE) == 0
        ? 0 : 42;
#else
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    const size_t baseline_later_thread_count =
        __crabc_x86_native_mimalloc_active_later_thread_count_test_audit();

    /* The rejected pre-start worker never installed an admission; ordinary
     * startup must therefore begin these three attached rounds at zero. */
    if (baseline_later_thread_count != 0)
        return 9;
#endif
    if (pthread_key_create(&teardown_key, native_allocation_tsd_destructor) != 0)
        return 10;
    result = run_return_round(normal_return_worker, CRABC_NORMAL_MARKER, 10);
    if (result != 0)
        return result;
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 18;
#endif
    result = run_return_round(explicit_exit_worker, CRABC_EXPLICIT_MARKER, 20);
    if (result != 0)
        return result;
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 28;
#endif
    result = run_deferred_cancellation_round();
    if (result != 0)
        return result;
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 38;
#endif
    if (pthread_key_delete(teardown_key) != 0)
        return 40;

    /* Main pthread_exit must leave this worker as the final ordinary-exit
     * owner. Its native worker finish therefore precedes this callback.
     * The task-ID handshake above prevents the worker returning too early. */
    {
        pthread_t final_worker;

        __atomic_store_n(&final_worker_ready, 0, __ATOMIC_RELEASE);
        if (atexit(final_worker_atexit_allocation) != 0)
            return 41;
        if (pthread_create(&final_worker, 0,
                final_worker_after_initial_pthread_exit, 0) != 0)
            return 42;
        if (wait_for_nonzero(&final_worker_ready) != 0)
            return 43;
    }
    pthread_exit(0);
#endif
}
