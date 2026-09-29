/* Static crabc-libc x86-64 pthread/TLS aggregate fixture.
 *
 * This is a composition proof, not another leaf smoke test.  One bounded
 * selected-worker round composes the already selected Static Initial TLS v1,
 * pthread create/join, normal mutex/condition, rwlock, once, and TSD paths:
 * two workers acquire the shared read lock, publish admission through the
 * private condition, wait for the parent release, return distinct values,
 * and run their clear-before-callback TSD destructors before join publishes
 * the results.  The parent verifies writer exclusion while both readers are
 * held, then completes the condition-mediated lifecycle. A later handoff
 * deletes and reuses a key while its first worker is alive, then observes
 * ordered passes of that one replacement key's destructor on normal return
 * and explicit pthread_exit.
 *
 * It deliberately does not select cancellation, attributes, timed/shared
 * synchronization, C11 adapters, detached or foreign threads, dynamic TLS,
 * CRT/loader integration, or general pthread support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>

_Static_assert(sizeof(pthread_mutex_t) == 40 && _Alignof(pthread_mutex_t) == 8,
    "musl x86-64 pthread_mutex_t ABI");
_Static_assert(sizeof(pthread_cond_t) == 48 && _Alignof(pthread_cond_t) == 8,
    "musl x86-64 pthread_cond_t ABI");
_Static_assert(sizeof(pthread_rwlock_t) == 56 && _Alignof(pthread_rwlock_t) == 8,
    "musl x86-64 pthread_rwlock_t ABI");
_Static_assert(sizeof(pthread_once_t) == 4 && _Alignof(pthread_once_t) == 4,
    "musl x86-64 pthread_once_t ABI");
_Static_assert(sizeof(pthread_key_t) == 4 && _Alignof(pthread_key_t) == 4,
    "musl x86-64 pthread_key_t ABI");

enum {
    FIRST_MARKER = 0x11223344,
    SECOND_MARKER = 0x55667788,
    ONCE_PAYLOAD = 0x31415926,
    FIRST_LIFECYCLE_VALUE = 0x100,
    SECOND_LIFECYCLE_VALUE = 0x200,
};

struct raw_timespec {
    long seconds;
    long nanoseconds;
};

static int wait_for_count(const volatile int *count, int expected)
{
    struct raw_timespec deadline;
    struct raw_timespec now;
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(228L), "D"(1L), "S"(&deadline) : "rcx", "r11", "memory");
    if (result != 0)
        return -1;
    ++deadline.seconds;
    for (;;) {
        if (__atomic_load_n(count, __ATOMIC_ACQUIRE) == expected)
            return 0;
        __asm__ volatile("syscall" : "=a"(result)
            : "a"(228L), "D"(1L), "S"(&now) : "rcx", "r11", "memory");
        if (result != 0 || now.seconds > deadline.seconds ||
            (now.seconds == deadline.seconds && now.nanoseconds >= deadline.nanoseconds))
            return -1;
    }
}

struct aggregate_state {
    pthread_mutex_t gate;
    pthread_cond_t condition;
    pthread_rwlock_t lock;
    pthread_once_t once;
    pthread_key_t key;
    volatile int ready_readers;
    volatile int release_readers;
    volatile int once_calls;
    volatile int once_payload;
    volatile int destructor_calls;
    volatile uintptr_t destructor_sum;
    volatile int destructor_failure;
};

struct worker {
    struct aggregate_state *state;
    uintptr_t marker;
    int initial_errno;
    int final_errno;
    int status;
};

static struct aggregate_state state = {
    .gate = PTHREAD_MUTEX_INITIALIZER,
    .condition = PTHREAD_COND_INITIALIZER,
    .lock = PTHREAD_RWLOCK_INITIALIZER,
    .once = PTHREAD_ONCE_INIT,
};

struct lifecycle_worker {
    uintptr_t marker;
    int wait_for_reuse;
    int status;
};

static pthread_key_t deleted_key;
static pthread_key_t replacement_key;
static volatile int lifecycle_ready;
static volatile int lifecycle_release;
static volatile int deleted_destructor_calls;
static volatile int replacement_calls[2];
static volatile int lifecycle_failure;

static void emit_lifecycle_event(char worker, int pass)
{
    char event[3] = { worker, (char)('0' + pass), '\n' };
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(1L), "D"(1L), "S"(event), "d"(sizeof(event))
        : "rcx", "r11", "memory");
    if (result != (long)sizeof(event))
        __atomic_store_n(&lifecycle_failure, 1, __ATOMIC_RELAXED);
}

static void deleted_destructor(void *value)
{
    (void)value;
    __atomic_fetch_add(&deleted_destructor_calls, 1, __ATOMIC_RELAXED);
}

static void replacement_destructor(void *value)
{
    uintptr_t marker = (uintptr_t)value;
    int index = (marker & ~(uintptr_t)1) == FIRST_LIFECYCLE_VALUE ? 0 : 1;
    int pass = __atomic_fetch_add(&replacement_calls[index], 1, __ATOMIC_RELAXED);

    if ((marker & ~(uintptr_t)1) !=
            (index == 0 ? FIRST_LIFECYCLE_VALUE : SECOND_LIFECYCLE_VALUE) ||
        (marker & 1) != (uintptr_t)pass || pass > 1 ||
        pthread_getspecific(replacement_key) != 0 || errno != EACCES)
        __atomic_store_n(&lifecycle_failure, 2, __ATOMIC_RELAXED);
    emit_lifecycle_event(index == 0 ? 'A' : 'B', pass);
    if (pass == 0 && pthread_setspecific(replacement_key,
            (void *)(marker + 1)) != 0)
        __atomic_store_n(&lifecycle_failure, 3, __ATOMIC_RELAXED);
}

static void *lifecycle_worker_main(void *opaque)
{
    struct lifecycle_worker *worker = opaque;

    worker->status = 0;
    if (errno != 0)
        worker->status = 1;
    errno = EACCES;
    if (worker->status == 0 && worker->wait_for_reuse) {
        if (pthread_setspecific(deleted_key, (void *)worker->marker) != 0)
            worker->status = 2;
        __atomic_store_n(&lifecycle_ready, 1, __ATOMIC_RELEASE);
        while (__atomic_load_n(&lifecycle_release, __ATOMIC_ACQUIRE) == 0)
            ;
    }
    if (worker->status == 0 && pthread_getspecific(replacement_key) != 0)
        worker->status = 3;
    if (worker->status == 0 &&
        pthread_setspecific(replacement_key, (void *)(worker->marker + 2)) != 0)
        worker->status = 4;
    if (worker->status == 0 &&
        pthread_getspecific(replacement_key) != (void *)(worker->marker + 2))
        worker->status = 5;
    if (worker->status == 0 &&
        pthread_setspecific(replacement_key, (void *)worker->marker) != 0)
        worker->status = 6;
    if (worker->status == 0 && errno != EACCES)
        worker->status = 7;
    if (worker->wait_for_reuse == 0)
        pthread_exit((void *)(worker->status == 0 ? worker->marker :
            (uintptr_t)worker->status));
    return (void *)(worker->status == 0 ? worker->marker :
        (uintptr_t)worker->status);
}

static int run_key_lifecycle(void)
{
    struct lifecycle_worker first = {
        .marker = FIRST_LIFECYCLE_VALUE, .wait_for_reuse = 1,
    };
    struct lifecycle_worker second = { .marker = SECOND_LIFECYCLE_VALUE };
    pthread_t thread;
    void *result = 0;

    if (pthread_key_create(&deleted_key, deleted_destructor) != 0)
        return 1;
    if (pthread_create(&thread, 0, lifecycle_worker_main, &first) != 0)
        return 2;
    if (wait_for_count(&lifecycle_ready, 1) != 0)
        return 3;
    if (pthread_key_delete(deleted_key) != 0 ||
        pthread_key_create(&replacement_key, replacement_destructor) != 0)
        return 4;
    if (replacement_key != deleted_key)
        return 5;
    __atomic_store_n(&lifecycle_release, 1, __ATOMIC_RELEASE);
    if (pthread_join(thread, &result) != 0 ||
        result != (void *)FIRST_LIFECYCLE_VALUE || first.status != 0)
        return 6;
    if (__atomic_load_n(&replacement_calls[0], __ATOMIC_RELAXED) != 2 ||
        __atomic_load_n(&replacement_calls[1], __ATOMIC_RELAXED) != 0 ||
        __atomic_load_n(&deleted_destructor_calls, __ATOMIC_RELAXED) != 0 ||
        __atomic_load_n(&lifecycle_failure, __ATOMIC_RELAXED) != 0)
        return 7;
    if (pthread_create(&thread, 0, lifecycle_worker_main, &second) != 0)
        return 8;
    if (pthread_join(thread, &result) != 0 ||
        result != (void *)SECOND_LIFECYCLE_VALUE || second.status != 0)
        return 9;
    if (__atomic_load_n(&replacement_calls[1], __ATOMIC_RELAXED) != 2 ||
        __atomic_load_n(&deleted_destructor_calls, __ATOMIC_RELAXED) != 0 ||
        __atomic_load_n(&lifecycle_failure, __ATOMIC_RELAXED) != 0)
        return 10;
    if (pthread_getspecific(replacement_key) != 0 ||
        pthread_key_delete(replacement_key) != 0 || errno != E2BIG)
        return 11;
    return 0;
}

static void aggregate_once(void)
{
    __atomic_fetch_add(&state.once_calls, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&state.once_payload, ONCE_PAYLOAD, __ATOMIC_RELAXED);
}

static void aggregate_destructor(void *value)
{
    if (pthread_getspecific(state.key) != 0 || errno != EACCES)
        __atomic_store_n(&state.destructor_failure, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&state.destructor_calls, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&state.destructor_sum, (uintptr_t)value,
        __ATOMIC_RELAXED);
}

static void *aggregate_worker(void *opaque)
{
    struct worker *worker = opaque;
    struct aggregate_state *shared = worker->state;

    worker->status = 0;
    worker->initial_errno = errno;
    errno = EACCES;
    if (worker->initial_errno != 0 || pthread_once(&shared->once, aggregate_once) != 0)
        worker->status = 1;
    if (worker->status == 0 &&
        __atomic_load_n(&shared->once_payload, __ATOMIC_RELAXED) != ONCE_PAYLOAD)
        worker->status = 2;
    if (worker->status == 0 &&
        pthread_setspecific(shared->key, (void *)worker->marker) != 0)
        worker->status = 3;
    if (worker->status == 0 &&
        pthread_rwlock_rdlock(&shared->lock) != 0)
        worker->status = 4;
    if (worker->status == 0 && pthread_mutex_lock(&shared->gate) != 0)
        worker->status = 5;
    if (worker->status == 0) {
        __atomic_fetch_add(&shared->ready_readers, 1, __ATOMIC_RELEASE);
        if (pthread_cond_signal(&shared->condition) != 0)
            worker->status = 6;
        while (worker->status == 0 &&
            __atomic_load_n(&shared->release_readers, __ATOMIC_ACQUIRE) == 0) {
            if (pthread_cond_wait(&shared->condition, &shared->gate) != 0)
                worker->status = 7;
        }
        if (pthread_mutex_unlock(&shared->gate) != 0 && worker->status == 0)
            worker->status = 8;
    }
    if (worker->status == 0 && pthread_rwlock_unlock(&shared->lock) != 0)
        worker->status = 9;
    worker->final_errno = errno;
    return worker->status == 0 ? (void *)worker->marker : (void *)(uintptr_t)worker->status;
}

int crabc_x86_64_pthread_tls_aggregate_probe(void)
{
    struct worker first = { .state = &state, .marker = FIRST_MARKER };
    struct worker second = { .state = &state, .marker = SECOND_MARKER };
    pthread_t first_thread;
    pthread_t second_thread;
    void *first_result = 0;
    void *second_result = 0;
    int lifecycle_status;

    errno = E2BIG;
    if (pthread_key_create(&state.key, aggregate_destructor) != 0)
        return 1;
    if (pthread_create(&first_thread, 0, aggregate_worker, &first) != 0)
        return 2;
    if (pthread_create(&second_thread, 0, aggregate_worker, &second) != 0)
        return 3;
    if (wait_for_count(&state.ready_readers, 2) != 0)
        return 4;
    if (pthread_mutex_lock(&state.gate) != 0)
        return 5;
    if (pthread_rwlock_trywrlock(&state.lock) != EBUSY)
        return 6;
    __atomic_store_n(&state.release_readers, 1, __ATOMIC_RELEASE);
    if (pthread_cond_broadcast(&state.condition) != 0)
        return 7;
    if (pthread_mutex_unlock(&state.gate) != 0)
        return 8;
    if (pthread_join(first_thread, &first_result) != 0 ||
        pthread_join(second_thread, &second_result) != 0)
        return 9;
    if (pthread_rwlock_wrlock(&state.lock) != 0)
        return 10;
    if (__atomic_load_n(&state.once_calls, __ATOMIC_RELAXED) != 1 ||
        __atomic_load_n(&state.once_payload, __ATOMIC_RELAXED) != ONCE_PAYLOAD)
        return 11;
    if (pthread_rwlock_unlock(&state.lock) != 0)
        return 12;
    if (first_result != (void *)FIRST_MARKER || second_result != (void *)SECOND_MARKER ||
        first.status != 0 || second.status != 0 || first.initial_errno != 0 ||
        second.initial_errno != 0 || first.final_errno != EACCES ||
        second.final_errno != EACCES)
        return 13;
    if (__atomic_load_n(&state.destructor_calls, __ATOMIC_RELAXED) != 2 ||
        __atomic_load_n(&state.destructor_sum, __ATOMIC_RELAXED) !=
            (uintptr_t)(FIRST_MARKER + SECOND_MARKER) ||
        __atomic_load_n(&state.destructor_failure, __ATOMIC_RELAXED) != 0)
        return 14;
    if (pthread_getspecific(state.key) != 0 || pthread_key_delete(state.key) != 0)
        return 15;
    if (pthread_once(&state.once, aggregate_once) != 0 ||
        __atomic_load_n(&state.once_calls, __ATOMIC_RELAXED) != 1)
        return 16;
    lifecycle_status = run_key_lifecycle();
    if (lifecycle_status != 0)
        return 20 + lifecycle_status;
    if (pthread_rwlock_destroy(&state.lock) != 0 ||
        pthread_cond_destroy(&state.condition) != 0 ||
        pthread_mutex_destroy(&state.gate) != 0 || errno != E2BIG)
        return 17;
    return 0;
}

#ifndef CRABC_PTHREAD_TLS_AGGREGATE_FREESTANDING
int main(void)
{
    return crabc_x86_64_pthread_tls_aggregate_probe();
}
#endif
