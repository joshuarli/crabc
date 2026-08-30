/* Static crabc-libc x86-64 pthread-key/C11-TSS lifecycle fixture.
 *
 * The exact same project-header body first runs against pinned musl 1.2.6,
 * then through a `-nostdlib -static` candidate linked only with the selected
 * crabc archive. It specifies only a bounded TSD lifecycle: 128-key capacity,
 * current main/selected-worker values, selected worker isolation, deletion
 * clearing, and normal/pthread_exit/thrd-return/thrd_exit four-pass
 * clear-before-rearm destructors. It is not cancellation, main-process-exit
 * destruction, foreign-thread TSD, fork/atfork, dynamic TLS, loader TLS, a
 * full pthread/C11 runtime, family completion, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <threads.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

_Static_assert(sizeof(pthread_key_t) == 4 && _Alignof(pthread_key_t) == 4,
    "musl x86-64 pthread_key_t ABI");
_Static_assert(CRABC_TYPE_IS(pthread_key_t, tss_t),
    "musl C tss_t has pthread_key_t identity");
_Static_assert(PTHREAD_KEYS_MAX == 128 && PTHREAD_DESTRUCTOR_ITERATIONS == 4,
    "musl selected pthread TSD limits");
_Static_assert(TSS_DTOR_ITERATIONS == PTHREAD_DESTRUCTOR_ITERATIONS,
    "musl C11/POSIX destructor iteration identity");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_key_create),
    int (*)(pthread_key_t *, void (*)(void *))), "pthread_key_create declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_key_delete),
    int (*)(pthread_key_t)), "pthread_key_delete declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_getspecific),
    void *(*)(pthread_key_t)), "pthread_getspecific declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_setspecific),
    int (*)(pthread_key_t, const void *)), "pthread_setspecific declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&tss_create),
    int (*)(tss_t *, tss_dtor_t)), "tss_create declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&tss_delete), void (*)(tss_t)),
    "tss_delete declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&tss_get), void *(*)(tss_t)),
    "tss_get declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&tss_set), int (*)(tss_t, void *)),
    "tss_set declaration");

enum {
    MAIN_VALUE = 0x101,
    WORKER_VALUE = 0x202,
    PTHREAD_RETURN_VALUE = 0x303,
    PTHREAD_EXIT_VALUE = 0x404,
    C11_RETURN_VALUE = -0x505,
    C11_EXIT_VALUE = 0x606,
};

static pthread_key_t plain_key;
static pthread_key_t pthread_dtor_key;
static tss_t c11_dtor_key;
static volatile int pthread_dtor_calls;
static volatile int pthread_dtor_failure;
static volatile int c11_dtor_calls;
static volatile int c11_dtor_failure;
static pthread_key_t deletion_key;
static pthread_key_t deletion_fillers[PTHREAD_KEYS_MAX - 1];
static pthread_key_t replacement_key;
static volatile int deletion_ready;
static volatile int deletion_release;
static volatile int deleted_key_dtor_calls;
static volatile int replacement_key_dtor_calls;
static volatile int deletion_dtor_failure;

static void reset_pthread_dtor_observation(void)
{
    __atomic_store_n(&pthread_dtor_calls, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&pthread_dtor_failure, 0, __ATOMIC_RELAXED);
}

static void reset_c11_dtor_observation(void)
{
    __atomic_store_n(&c11_dtor_calls, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&c11_dtor_failure, 0, __ATOMIC_RELAXED);
}

static void pthread_rearming_destructor(void *value)
{
    const int call = __atomic_fetch_add(&pthread_dtor_calls, 1, __ATOMIC_RELAXED);

    if ((uintptr_t)value != (uintptr_t)(call + 1) ||
        pthread_getspecific(pthread_dtor_key) != 0 || errno != EACCES)
        __atomic_store_n(&pthread_dtor_failure, 1, __ATOMIC_RELAXED);
    /* Rearm even on pass four: the selected implementation must clear before
     * callback, release its private lock, and stop exactly at the fixed cap. */
    if (pthread_setspecific(pthread_dtor_key,
        (void *)(uintptr_t)(call + 2)) != 0)
        __atomic_store_n(&pthread_dtor_failure, 2, __ATOMIC_RELAXED);
}

static void c11_rearming_destructor(void *value)
{
    const int call = __atomic_fetch_add(&c11_dtor_calls, 1, __ATOMIC_RELAXED);

    if ((uintptr_t)value != (uintptr_t)(call + 1) ||
        tss_get(c11_dtor_key) != 0 || errno != EACCES)
        __atomic_store_n(&c11_dtor_failure, 1, __ATOMIC_RELAXED);
    if (tss_set(c11_dtor_key,
        (void *)(uintptr_t)(call + 2)) != thrd_success)
        __atomic_store_n(&c11_dtor_failure, 2, __ATOMIC_RELAXED);
}

static void deleted_key_destructor(void *value)
{
    (void)value;
    __atomic_fetch_add(&deleted_key_dtor_calls, 1, __ATOMIC_RELAXED);
}

static void replacement_key_destructor(void *value)
{
    if ((uintptr_t)value != WORKER_VALUE ||
        pthread_getspecific(replacement_key) != 0 || errno != EACCES)
        __atomic_store_n(&deletion_dtor_failure, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&replacement_key_dtor_calls, 1, __ATOMIC_RELAXED);
}

static void *pthread_return_worker(void *opaque)
{
    (void)opaque;
    if (errno != 0)
        return (void *)(uintptr_t)6;
    errno = EACCES;
    if (pthread_getspecific(plain_key) != 0)
        return (void *)(uintptr_t)1;
    if (pthread_setspecific(plain_key, (void *)(uintptr_t)WORKER_VALUE) != 0)
        return (void *)(uintptr_t)2;
    if ((uintptr_t)pthread_getspecific(plain_key) != WORKER_VALUE)
        return (void *)(uintptr_t)3;
    if (pthread_setspecific(pthread_dtor_key, (void *)(uintptr_t)1) != 0)
        return (void *)(uintptr_t)4;
    if (errno != EACCES)
        return (void *)(uintptr_t)5;
    return (void *)(uintptr_t)PTHREAD_RETURN_VALUE;
}

static void *pthread_exit_worker(void *opaque)
{
    (void)opaque;
    if (errno != 0)
        return (void *)(uintptr_t)2;
    errno = EACCES;
    if (pthread_setspecific(pthread_dtor_key, (void *)(uintptr_t)1) != 0)
        return (void *)(uintptr_t)1;
    pthread_exit((void *)(uintptr_t)PTHREAD_EXIT_VALUE);
}

static int c11_return_worker(void *opaque)
{
    (void)opaque;
    if (errno != 0)
        return 4;
    errno = EACCES;
    if (tss_get(c11_dtor_key) != 0)
        return 1;
    if (tss_set(c11_dtor_key, (void *)(uintptr_t)1) != thrd_success)
        return 2;
    if (errno != EACCES)
        return 3;
    return C11_RETURN_VALUE;
}

static int c11_exit_worker(void *opaque)
{
    (void)opaque;
    if (errno != 0)
        return 2;
    errno = EACCES;
    if (tss_set(c11_dtor_key, (void *)(uintptr_t)1) != thrd_success)
        return 1;
    thrd_exit(C11_EXIT_VALUE);
}

static void *deletion_worker(void *opaque)
{
    (void)opaque;
    if (errno != 0)
        return (void *)(uintptr_t)5;
    errno = EACCES;
    if (pthread_setspecific(deletion_key, (void *)(uintptr_t)WORKER_VALUE) != 0)
        return (void *)(uintptr_t)1;
    __atomic_store_n(&deletion_ready, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&deletion_release, __ATOMIC_ACQUIRE) == 0)
        ;
    if (pthread_getspecific(replacement_key) != 0)
        return (void *)(uintptr_t)2;
    if (pthread_setspecific(replacement_key,
        (void *)(uintptr_t)WORKER_VALUE) != 0)
        return (void *)(uintptr_t)3;
    if (errno != EACCES)
        return (void *)(uintptr_t)4;
    return 0;
}

static int run_pthread_return_round(void)
{
    pthread_t worker;
    void *result = 0;

    errno = E2BIG;
    reset_pthread_dtor_observation();
    if (pthread_create(&worker, 0, pthread_return_worker, 0) != 0)
        return 1;
    if (pthread_join(worker, &result) != 0)
        return 2;
    if ((uintptr_t)result != PTHREAD_RETURN_VALUE ||
        __atomic_load_n(&pthread_dtor_calls, __ATOMIC_RELAXED) !=
            PTHREAD_DESTRUCTOR_ITERATIONS ||
        __atomic_load_n(&pthread_dtor_failure, __ATOMIC_RELAXED) != 0)
        return 3;
    if ((uintptr_t)pthread_getspecific(plain_key) != MAIN_VALUE)
        return 4;
    if (errno != E2BIG)
        return 5;
    return 0;
}

static int run_pthread_exit_round(void)
{
    pthread_t worker;
    void *result = 0;

    errno = E2BIG;
    reset_pthread_dtor_observation();
    if (pthread_create(&worker, 0, pthread_exit_worker, 0) != 0)
        return 1;
    if (pthread_join(worker, &result) != 0)
        return 2;
    if ((uintptr_t)result != PTHREAD_EXIT_VALUE ||
        __atomic_load_n(&pthread_dtor_calls, __ATOMIC_RELAXED) !=
            PTHREAD_DESTRUCTOR_ITERATIONS ||
        __atomic_load_n(&pthread_dtor_failure, __ATOMIC_RELAXED) != 0)
        return 3;
    if (errno != E2BIG)
        return 4;
    return 0;
}

static int run_c11_return_round(void)
{
    thrd_t worker;
    int result = 0;

    errno = E2BIG;
    reset_c11_dtor_observation();
    if (thrd_create(&worker, c11_return_worker, 0) != thrd_success)
        return 1;
    if (thrd_join(worker, &result) != thrd_success)
        return 2;
    if (result != C11_RETURN_VALUE ||
        __atomic_load_n(&c11_dtor_calls, __ATOMIC_RELAXED) !=
            TSS_DTOR_ITERATIONS ||
        __atomic_load_n(&c11_dtor_failure, __ATOMIC_RELAXED) != 0)
        return 3;
    if (errno != E2BIG)
        return 4;
    return 0;
}

static int run_c11_exit_round(void)
{
    thrd_t worker;
    int result = 0;

    errno = E2BIG;
    reset_c11_dtor_observation();
    if (thrd_create(&worker, c11_exit_worker, 0) != thrd_success)
        return 1;
    if (thrd_join(worker, &result) != thrd_success)
        return 2;
    if (result != C11_EXIT_VALUE ||
        __atomic_load_n(&c11_dtor_calls, __ATOMIC_RELAXED) !=
            TSS_DTOR_ITERATIONS ||
        __atomic_load_n(&c11_dtor_failure, __ATOMIC_RELAXED) != 0)
        return 3;
    if (errno != E2BIG)
        return 4;
    return 0;
}

static int run_deletion_round(void)
{
    pthread_t worker;
    void *result = (void *)(uintptr_t)9;
    pthread_key_t created;
    unsigned int filler_count = 0;
    unsigned int index;
    int replacement_found = 0;

    errno = E2BIG;
    __atomic_store_n(&deletion_ready, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&deletion_release, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&deleted_key_dtor_calls, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&replacement_key_dtor_calls, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&deletion_dtor_failure, 0, __ATOMIC_RELAXED);
    if (pthread_key_create(&deletion_key, deleted_key_destructor) != 0)
        return 1;
    if (pthread_create(&worker, 0, deletion_worker, 0) != 0)
        return 2;
    while (__atomic_load_n(&deletion_ready, __ATOMIC_ACQUIRE) == 0)
        ;
    if (pthread_key_delete(deletion_key) != 0)
        return 3;
    /* Pinned musl owns exactly the fixed key table. Refill it, then select the
     * public numeric handle that reuses the deleted slot without depending on
     * allocator order. The worker uses only that newly valid key. */
    for (index = 0; index != PTHREAD_KEYS_MAX; ++index) {
        if (pthread_key_create(&created, replacement_key_destructor) != 0)
            return 4;
        if (created == deletion_key) {
            replacement_key = created;
            replacement_found = 1;
        } else {
            deletion_fillers[filler_count++] = created;
        }
    }
    if (!replacement_found || filler_count != PTHREAD_KEYS_MAX - 1)
        return 5;
    if (pthread_key_create(&created, 0) != EAGAIN)
        return 6;
    __atomic_store_n(&deletion_release, 1, __ATOMIC_RELEASE);
    if (pthread_join(worker, &result) != 0)
        return 7;
    if (result != 0)
        return 8;
    if (__atomic_load_n(&deleted_key_dtor_calls, __ATOMIC_RELAXED) != 0 ||
        __atomic_load_n(&replacement_key_dtor_calls, __ATOMIC_RELAXED) != 1 ||
        __atomic_load_n(&deletion_dtor_failure, __ATOMIC_RELAXED) != 0)
        return 9;
    if (pthread_key_delete(replacement_key) != 0)
        return 10;
    for (index = 0; index != filler_count; ++index) {
        if (pthread_key_delete(deletion_fillers[index]) != 0)
            return 11;
    }
    if (errno != E2BIG)
        return 12;
    return 0;
}

static int run_capacity_round(void)
{
    pthread_key_t pthread_keys[PTHREAD_KEYS_MAX];
    tss_t c11_keys[PTHREAD_KEYS_MAX];
    tss_t c11_reused;
    pthread_key_t pthread_reused;
    unsigned int index;

    errno = E2BIG;
    for (index = 0; index != PTHREAD_KEYS_MAX; ++index) {
        if (pthread_key_create(&pthread_keys[index], 0) != 0)
            return 1;
    }
    if (tss_create(&c11_reused, 0) != thrd_error)
        return 2;
    if (pthread_key_delete(pthread_keys[0]) != 0)
        return 3;
    if (tss_create(&c11_reused, 0) != thrd_success)
        return 4;
    tss_delete(c11_reused);
    for (index = 1; index != PTHREAD_KEYS_MAX; ++index) {
        if (pthread_key_delete(pthread_keys[index]) != 0)
            return 5;
    }

    for (index = 0; index != PTHREAD_KEYS_MAX; ++index) {
        if (tss_create(&c11_keys[index], 0) != thrd_success)
            return 6;
    }
    if (pthread_key_create(&pthread_reused, 0) != EAGAIN)
        return 7;
    tss_delete(c11_keys[0]);
    if (pthread_key_create(&pthread_reused, 0) != 0)
        return 8;
    if (pthread_key_delete(pthread_reused) != 0)
        return 9;
    for (index = 1; index != PTHREAD_KEYS_MAX; ++index)
        tss_delete(c11_keys[index]);
    if (errno != E2BIG)
        return 10;
    return 0;
}

static int run_pthread_c11_tsd(void)
{
    int status;

    errno = E2BIG;
    if (pthread_key_create(&plain_key, 0) != 0)
        return 1;
    if (pthread_setspecific(plain_key, (void *)(uintptr_t)MAIN_VALUE) != 0 ||
        (uintptr_t)pthread_getspecific(plain_key) != MAIN_VALUE)
        return 2;
    if (pthread_key_create(&pthread_dtor_key, pthread_rearming_destructor) != 0)
        return 3;
    if (tss_create(&c11_dtor_key, c11_rearming_destructor) != thrd_success)
        return 4;
    if ((status = run_pthread_return_round()) != 0)
        return 16 + status;
    if ((status = run_pthread_exit_round()) != 0)
        return 32 + status;
    if ((status = run_c11_return_round()) != 0)
        return 48 + status;
    if ((status = run_c11_exit_round()) != 0)
        return 64 + status;
    if (pthread_key_delete(pthread_dtor_key) != 0)
        return 80;
    tss_delete(c11_dtor_key);
    if (pthread_key_delete(plain_key) != 0)
        return 81;
    if ((status = run_deletion_round()) != 0)
        return 96 + status;
    if ((status = run_capacity_round()) != 0)
        return 112 + status;
    if (errno != E2BIG)
        return 127;
    return 0;
}

#if defined(CRABC_PTHREAD_C11_TSD_FREESTANDING)
int crabc_x86_64_pthread_c11_tsd_probe(void)
{
    return run_pthread_c11_tsd();
}
#else
int main(void)
{
    return run_pthread_c11_tsd();
}
#endif
