/* Static crabc-libc x86-64 deferred pthread-cancellation fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * against a `-nostdlib -static` candidate linked solely through the selected
 * crabc archive.  It selects one deliberately bounded route: a default
 * joinable pointer-returning worker keeps one request pending through DISABLE
 * and MASKED states, where explicit pthread_testcancel calls return.  After
 * ENABLE it reaches the sole selected cancellation point.  That exit runs
 * cleanup handlers LIFO with cancellation disabled, then the selected TSD
 * destructor, publishes PTHREAD_CANCELED, and uses the existing clear-tid
 * join seam.
 *
 * The candidate deliberately rejects PTHREAD_CANCEL_ASYNCHRONOUS with
 * ENOTSUP and no output mutation.  The reference arm records musl's distinct
 * successful async-then-deferred round with no pending request; this is an
 * intentional, directly checked candidate boundary.  Neither arm selects a
 * signal, syscall interruption, implicit or blocking cancellation point,
 * detached/main/foreign/C11 thread cancellation, or general pthread
 * cancellation semantics.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>

#define CRABC_TYPE_IS(actual, expected) \
    __builtin_types_compatible_p(actual, expected)

enum {
    CRABC_WAIT_LIMIT = 100000000u,
    CRABC_SENTINEL = 0x4a5b6c7d,
};

_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_create),
    int (*)(pthread_t *__restrict, const pthread_attr_t *__restrict,
        void *(*)(void *), void *__restrict)), "pthread_create declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_join),
    int (*)(pthread_t, void **)), "pthread_join declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_cancel),
    int (*)(pthread_t)), "pthread_cancel declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_setcancelstate),
    int (*)(int, int *)), "pthread_setcancelstate declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_setcanceltype),
    int (*)(int, int *)), "pthread_setcanceltype declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_testcancel),
    void (*)(void)), "pthread_testcancel declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_key_create),
    int (*)(pthread_key_t *, void (*)(void *))), "pthread_key_create declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_setspecific),
    int (*)(pthread_key_t, const void *)), "pthread_setspecific declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_getspecific),
    void *(*)(pthread_key_t)), "pthread_getspecific declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_key_delete),
    int (*)(pthread_key_t)), "pthread_key_delete declaration");
_Static_assert(PTHREAD_CANCEL_ENABLE == 0 && PTHREAD_CANCEL_DISABLE == 1 &&
    PTHREAD_CANCEL_MASKED == 2, "cancellation state values");
_Static_assert(PTHREAD_CANCEL_DEFERRED == 0 && PTHREAD_CANCEL_ASYNCHRONOUS == 1,
    "cancellation type values");
_Static_assert(PTHREAD_CANCELED == (void *)-1,
    "cancellation join result");

enum cancellation_phase {
    CANCELLATION_PHASE_INITIAL = 0,
    CANCELLATION_PHASE_DISABLED_READY = 1,
    CANCELLATION_PHASE_DISABLED_TESTCANCEL_RETURNED = 2,
    CANCELLATION_PHASE_MASKED_TESTCANCEL_RETURNED = 3,
    CANCELLATION_PHASE_FAILURE = -1,
};

enum cancellation_order {
    CANCELLATION_ORDER_INNER_ENTERED = 1,
    CANCELLATION_ORDER_INNER_RETURNED = 2,
    CANCELLATION_ORDER_OUTER = 3,
    CANCELLATION_ORDER_TSD = 4,
};

struct cancellation_round {
    volatile int phase;
    volatile int release_after_cancel;
    volatile int allow_enable;
    volatile int worker_failure;
    volatile unsigned int order_count;
    int order[4];
    int deferred_previous_type;
    int disabled_previous_state;
    int masked_previous_state;
    int enabled_previous_state;
    int async_probe_result;
    int async_probe_old_type;
    int invalid_state_old;
    int invalid_type_old;
};

static pthread_key_t cancellation_tsd_key;

static void spin_pause(void)
{
    __asm__ volatile("pause" ::: "memory");
}

static void cancellation_failure(struct cancellation_round *round, int failure)
{
    __atomic_store_n(&round->worker_failure, failure, __ATOMIC_RELAXED);
    __atomic_store_n(&round->phase, CANCELLATION_PHASE_FAILURE,
        __ATOMIC_RELEASE);
}

static int wait_for_phase(const struct cancellation_round *round, int expected)
{
    unsigned int spin;

    for (spin = 0; spin != CRABC_WAIT_LIMIT; ++spin) {
        const int phase = __atomic_load_n(&round->phase, __ATOMIC_ACQUIRE);

        if (phase == expected)
            return 0;
        if (phase == CANCELLATION_PHASE_FAILURE)
            return -1;
        spin_pause();
    }
    return -1;
}

static int wait_for_flag(const volatile int *flag)
{
    unsigned int spin;

    for (spin = 0; spin != CRABC_WAIT_LIMIT; ++spin) {
        if (__atomic_load_n(flag, __ATOMIC_ACQUIRE) != 0)
            return 0;
        spin_pause();
    }
    return -1;
}

static void record_cancellation_order(struct cancellation_round *round, int value)
{
    const unsigned int index = __atomic_fetch_add(&round->order_count, 1,
        __ATOMIC_RELAXED);

    if (index >= sizeof(round->order) / sizeof(round->order[0])) {
        cancellation_failure(round, 60);
        return;
    }
    round->order[index] = value;
}

static void cancellation_cleanup_inner(void *opaque)
{
    struct cancellation_round *round = opaque;

    record_cancellation_order(round, CANCELLATION_ORDER_INNER_ENTERED);
    if (errno != EACCES)
        cancellation_failure(round, 61);
    /* This must return: exit_selected_worker disables cancellation before it
     * starts cleanup, matching musl's __pthread_exit transition. */
    pthread_testcancel();
    if (errno != EACCES)
        cancellation_failure(round, 62);
    record_cancellation_order(round, CANCELLATION_ORDER_INNER_RETURNED);
}

static void cancellation_cleanup_outer(void *opaque)
{
    struct cancellation_round *round = opaque;

    if (errno != EACCES)
        cancellation_failure(round, 63);
    record_cancellation_order(round, CANCELLATION_ORDER_OUTER);
}

static void cancellation_tsd_destructor(void *opaque)
{
    struct cancellation_round *round = opaque;

    if (pthread_getspecific(cancellation_tsd_key) != 0 || errno != EACCES)
        cancellation_failure(round, 64);
    record_cancellation_order(round, CANCELLATION_ORDER_TSD);
}

static int check_cancellation_type_contract(struct cancellation_round *round)
{
    int old_type = CRABC_SENTINEL;

    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,
            &round->deferred_previous_type) != 0 ||
        round->deferred_previous_type != PTHREAD_CANCEL_DEFERRED)
        return 1;
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, 0) != 0)
        return 2;
    round->invalid_type_old = CRABC_SENTINEL;
    if (pthread_setcanceltype(-1, &round->invalid_type_old) != EINVAL ||
        round->invalid_type_old != CRABC_SENTINEL)
        return 3;

    round->async_probe_old_type = CRABC_SENTINEL;
    round->async_probe_result = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,
        &round->async_probe_old_type);
#ifdef CRABC_PTHREAD_CANCEL_DEFERRED_FREESTANDING
    if (round->async_probe_result != ENOTSUP ||
        round->async_probe_old_type != CRABC_SENTINEL)
        return 4;
#else
    if (round->async_probe_result != 0 ||
        round->async_probe_old_type != PTHREAD_CANCEL_DEFERRED)
        return 5;
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old_type) != 0 ||
        old_type != PTHREAD_CANCEL_ASYNCHRONOUS)
        return 6;
#endif
    return errno == EACCES ? 0 : 7;
}

static void *deferred_cancellation_worker(void *opaque)
{
    struct cancellation_round *round = opaque;

    if (errno != 0) {
        cancellation_failure(round, 10);
        return 0;
    }
    errno = EACCES;
    if (check_cancellation_type_contract(round) != 0) {
        cancellation_failure(round, 11);
        return 0;
    }

    round->invalid_state_old = CRABC_SENTINEL;
    if (pthread_setcancelstate(-1, &round->invalid_state_old) != EINVAL ||
        round->invalid_state_old != CRABC_SENTINEL) {
        cancellation_failure(round, 12);
        return 0;
    }
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
            &round->disabled_previous_state) != 0 ||
        round->disabled_previous_state != PTHREAD_CANCEL_ENABLE ||
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, 0) != 0) {
        cancellation_failure(round, 13);
        return 0;
    }
    if (pthread_setspecific(cancellation_tsd_key, round) != 0 || errno != EACCES) {
        cancellation_failure(round, 14);
        return 0;
    }

    pthread_cleanup_push(cancellation_cleanup_outer, round);
    pthread_cleanup_push(cancellation_cleanup_inner, round);

    __atomic_store_n(&round->phase, CANCELLATION_PHASE_DISABLED_READY,
        __ATOMIC_RELEASE);
    if (wait_for_flag(&round->release_after_cancel) != 0) {
        cancellation_failure(round, 15);
    } else {
        /* A queued request must remain harmless at this disabled explicit
         * point. The parent holds the later enable transition separately. */
        pthread_testcancel();
        if (errno != EACCES) {
            cancellation_failure(round, 16);
        } else {
            __atomic_store_n(&round->phase,
                CANCELLATION_PHASE_DISABLED_TESTCANCEL_RETURNED,
                __ATOMIC_RELEASE);
            if (pthread_setcancelstate(PTHREAD_CANCEL_MASKED,
                    &round->masked_previous_state) != 0 ||
                round->masked_previous_state != PTHREAD_CANCEL_DISABLE ||
                pthread_setcancelstate(PTHREAD_CANCEL_MASKED, 0) != 0) {
                cancellation_failure(round, 17);
            } else {
                pthread_testcancel();
                if (errno != EACCES) {
                    cancellation_failure(round, 18);
                } else {
                    __atomic_store_n(&round->phase,
                        CANCELLATION_PHASE_MASKED_TESTCANCEL_RETURNED,
                        __ATOMIC_RELEASE);
                    if (wait_for_flag(&round->allow_enable) != 0) {
                        cancellation_failure(round, 19);
                    } else if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,
                                   &round->enabled_previous_state) != 0 ||
                               round->enabled_previous_state != PTHREAD_CANCEL_MASKED ||
                               errno != EACCES) {
                        cancellation_failure(round, 20);
                    } else {
                        /* This is the single selected delivery point. */
                        pthread_testcancel();
                        cancellation_failure(round, 21);
                    }
                }
            }
        }
    }

    /* These lexical pops are unreachable only for the successful enabled
     * cancellation delivery above. They keep the public cleanup macros paired
     * for compiler and ordinary-error-path correctness. */
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return 0;
}

int crabc_x86_64_pthread_cancel_deferred_probe(void)
{
    pthread_t worker;
    void *worker_result = 0;
    int *main_errno_location = __errno_location();
    struct cancellation_round round = {
        .phase = CANCELLATION_PHASE_INITIAL,
        .release_after_cancel = 0,
        .allow_enable = 0,
        .worker_failure = 0,
        .order_count = 0,
        .order = {0, 0, 0, 0},
        .deferred_previous_type = -1,
        .disabled_previous_state = -1,
        .masked_previous_state = -1,
        .enabled_previous_state = -1,
        .async_probe_result = -1,
        .async_probe_old_type = -1,
        .invalid_state_old = -1,
        .invalid_type_old = -1,
    };

    if (main_errno_location == 0 || errno != 0)
        return 100;
    if (pthread_key_create(&cancellation_tsd_key, cancellation_tsd_destructor) != 0)
        return 101;
    errno = EACCES;

    if (pthread_create(&worker, 0, deferred_cancellation_worker, &round) != 0)
        return 102;
    if (wait_for_phase(&round, CANCELLATION_PHASE_DISABLED_READY) != 0)
        return 103;
    if (pthread_cancel(worker) != 0)
        return 104;
    if (errno != EACCES || __errno_location() != main_errno_location)
        return 105;

    __atomic_store_n(&round.release_after_cancel, 1, __ATOMIC_RELEASE);
    if (wait_for_phase(&round, CANCELLATION_PHASE_MASKED_TESTCANCEL_RETURNED) != 0)
        return 106;
    if (__atomic_load_n(&round.worker_failure, __ATOMIC_RELAXED) != 0)
        return 107;
    if (errno != EACCES || __errno_location() != main_errno_location)
        return 108;

    __atomic_store_n(&round.allow_enable, 1, __ATOMIC_RELEASE);
    if (pthread_join(worker, &worker_result) != 0)
        return 109;
    if (worker_result != PTHREAD_CANCELED)
        return 110;
    if (__atomic_load_n(&round.phase, __ATOMIC_ACQUIRE) !=
            CANCELLATION_PHASE_MASKED_TESTCANCEL_RETURNED ||
        __atomic_load_n(&round.worker_failure, __ATOMIC_RELAXED) != 0)
        return 111;
    if (round.deferred_previous_type != PTHREAD_CANCEL_DEFERRED ||
        round.disabled_previous_state != PTHREAD_CANCEL_ENABLE ||
        round.masked_previous_state != PTHREAD_CANCEL_DISABLE ||
        round.enabled_previous_state != PTHREAD_CANCEL_MASKED ||
        round.invalid_state_old != CRABC_SENTINEL ||
        round.invalid_type_old != CRABC_SENTINEL)
        return 112;
#ifdef CRABC_PTHREAD_CANCEL_DEFERRED_FREESTANDING
    if (round.async_probe_result != ENOTSUP ||
        round.async_probe_old_type != CRABC_SENTINEL)
        return 113;
#else
    if (round.async_probe_result != 0 ||
        round.async_probe_old_type != PTHREAD_CANCEL_DEFERRED)
        return 114;
#endif
    if (__atomic_load_n(&round.order_count, __ATOMIC_RELAXED) != 4 ||
        round.order[0] != CANCELLATION_ORDER_INNER_ENTERED ||
        round.order[1] != CANCELLATION_ORDER_INNER_RETURNED ||
        round.order[2] != CANCELLATION_ORDER_OUTER ||
        round.order[3] != CANCELLATION_ORDER_TSD)
        return 115;
    if (pthread_key_delete(cancellation_tsd_key) != 0)
        return 116;
    if (errno != EACCES || __errno_location() != main_errno_location)
        return 117;
    return 0;
}

#ifndef CRABC_PTHREAD_CANCEL_DEFERRED_FREESTANDING
int main(void)
{
    return crabc_x86_64_pthread_cancel_deferred_probe();
}
#endif
