/*
 * Exercise pthread/C11 ownership and publication through ordinary C calls.
 *
 * The program avoids time-based scheduling assumptions. Every transition uses
 * a barrier, mutex/condition handoff, or the selected synchronization primitive
 * being observed. The result line is intentionally fixed for byte comparison
 * with the separately linked pinned-musl object.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKERS 4
#define BARRIER_PHASES 3
#define TLS_INITIAL 0x3d51
#define ONCE_PUBLICATION 0x7e29

struct worker {
    int id;
    uintptr_t initialized_address;
    uintptr_t zero_address;
    int initialized_value;
    int zero_value;
};

static _Thread_local int initialized_tls = TLS_INITIAL;
static _Thread_local int zero_tls;
_Alignas(256) static _Thread_local unsigned char aligned_tls[17] = {0x51};

static once_flag once = ONCE_FLAG_INIT;
static tss_t tsd_key;
static pthread_barrier_t barrier;
static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_spinlock_t spin;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_changed = PTHREAD_COND_INITIALIZER;
static struct worker workers[WORKERS];
static atomic_int once_calls;
static atomic_int once_value;
static atomic_int barrier_serial[BARRIER_PHASES];
static atomic_int tsd_calls[WORKERS];
static atomic_int tsd_phase[WORKERS];
static atomic_int rw_reader_observed;
static int readers_ready;
static int release_readers;
static int rw_writer_published;
static int spin_holder_ready;
static int release_spin;
static int spin_try_busy;
static int rw_publication;
static int spin_publication;
static int once_initializer_live;
static int once_waiter_approaches;
static int release_once_initializer;
static int once_publication_ready;
static int once_returns;
static int once_returned_while_live;

static void fail(const char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    _Exit(1);
}

#define REQUIRE(condition, message) do { if (!(condition)) fail(message); } while (0)

static void once_initializer(void)
{
    REQUIRE(atomic_fetch_add_explicit(&once_calls, 1, memory_order_seq_cst) == 0,
            "call_once executed more than once");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "call_once initializer gate lock failed");
    once_initializer_live = 1;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "call_once initializer announcement failed");
    while (!release_once_initializer)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "call_once initializer release wait failed");
    atomic_store_explicit(&once_value, ONCE_PUBLICATION, memory_order_seq_cst);
    once_publication_ready = 1;
    once_initializer_live = 0;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "call_once publication announcement failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "call_once initializer gate unlock failed");
}

static void tsd_destructor(void *value)
{
    struct worker *worker = value;
    REQUIRE(worker >= workers && worker < workers + WORKERS, "TSD value differs");
    int phase = atomic_fetch_add_explicit(&tsd_phase[worker->id], 1, memory_order_seq_cst) + 1;
    atomic_fetch_add_explicit(&tsd_calls[worker->id], 1, memory_order_seq_cst);
    if (phase == 1)
        REQUIRE(tss_set(tsd_key, worker) == thrd_success, "TSD destructor rearm failed");
    else
        REQUIRE(phase == 2, "TSD destructor repeated unexpectedly");
}

static void barrier_phases(void)
{
    for (int phase = 0; phase < BARRIER_PHASES; ++phase) {
        int result = pthread_barrier_wait(&barrier);
        REQUIRE(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "barrier result differs");
        if (result == PTHREAD_BARRIER_SERIAL_THREAD)
            atomic_fetch_add_explicit(&barrier_serial[phase], 1, memory_order_seq_cst);
    }
}

static void reader_phase(void)
{
    REQUIRE(pthread_rwlock_rdlock(&rwlock) == 0, "reader lock failed");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "reader gate lock failed");
    ++readers_ready;
    if (readers_ready == 2)
        REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "reader gate broadcast failed");
    while (!release_readers)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "reader gate wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "reader gate unlock failed");
    REQUIRE(pthread_rwlock_unlock(&rwlock) == 0, "reader unlock failed");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "reader publication gate lock failed");
    while (!rw_writer_published)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "reader publication gate wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "reader publication gate unlock failed");
    REQUIRE(pthread_rwlock_rdlock(&rwlock) == 0, "reader publication lock failed");
    REQUIRE(rw_publication == 0x51a7, "reader did not observe rwlock writer publication");
    atomic_fetch_add_explicit(&rw_reader_observed, 1, memory_order_seq_cst);
    REQUIRE(pthread_rwlock_unlock(&rwlock) == 0, "reader publication unlock failed");
}

static void spin_holder_phase(void)
{
    REQUIRE(pthread_spin_lock(&spin) == 0, "spin holder lock failed");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "spin holder gate lock failed");
    spin_holder_ready = 1;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "spin holder announcement failed");
    while (!release_spin)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "spin holder gate wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "spin holder gate unlock failed");
    ++spin_publication;
    REQUIRE(pthread_spin_unlock(&spin) == 0, "spin holder unlock failed");
}

static void spin_contender_phase(void)
{
    REQUIRE(pthread_mutex_lock(&gate) == 0, "spin contender gate lock failed");
    while (!spin_holder_ready)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "spin contender gate wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "spin contender gate unlock failed");
    REQUIRE(pthread_spin_trylock(&spin) == EBUSY, "spin contention was not observed");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "spin contender release lock failed");
    spin_try_busy = 1;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "spin contender acknowledgement failed");
    while (!release_spin)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "spin contender release wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "spin contender release unlock failed");
    REQUIRE(pthread_spin_lock(&spin) == 0, "spin contender lock failed");
    ++spin_publication;
    REQUIRE(pthread_spin_unlock(&spin) == 0, "spin contender unlock failed");
}

static void once_phase(const struct worker *worker)
{
    if (worker->id != 0) {
        REQUIRE(pthread_mutex_lock(&gate) == 0, "call_once waiter gate lock failed");
        while (!once_initializer_live)
            REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "call_once waiter approach wait failed");
        ++once_waiter_approaches;
        REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "call_once waiter approach announcement failed");
        REQUIRE(pthread_mutex_unlock(&gate) == 0, "call_once waiter gate unlock failed");
    }
    call_once(&once, once_initializer);
    REQUIRE(pthread_mutex_lock(&gate) == 0, "call_once return gate lock failed");
    if (once_initializer_live)
        once_returned_while_live = 1;
    REQUIRE(once_publication_ready, "call_once returned before publication");
    ++once_returns;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "call_once return announcement failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "call_once return gate unlock failed");
    REQUIRE(atomic_load_explicit(&once_value, memory_order_seq_cst) == ONCE_PUBLICATION,
            "call_once publication differs");
}

static int worker_main(void *opaque)
{
    struct worker *worker = opaque;
    REQUIRE(initialized_tls == TLS_INITIAL && zero_tls == 0, "worker initial TLS differs");
    worker->initialized_address = (uintptr_t)&initialized_tls;
    worker->zero_address = (uintptr_t)&zero_tls;
    initialized_tls += worker->id + 1;
    zero_tls = worker->id + 1;
    worker->initialized_value = initialized_tls;
    worker->zero_value = zero_tls;

    barrier_phases();
    once_phase(worker);
    REQUIRE(tss_set(tsd_key, worker) == thrd_success, "initial TSD set failed");

    if (worker->id < 2)
        reader_phase();
    else if (worker->id == 2)
        spin_holder_phase();
    else
        spin_contender_phase();
    return 100 + worker->id;
}


static pthread_once_t canceled_once = PTHREAD_ONCE_INIT;
static pthread_key_t lifecycle_key;
static atomic_int canceled_once_calls;
static atomic_int canceled_once_publication;
static atomic_int cancel_cleanup;
static atomic_int cancel_destructors;
static int cancel_initializer_ready;
static int cancel_waiter_ready;
static int fork_worker_ready;
static int fork_worker_release;
static int fork_callback_sequence;
static pthread_key_t fork_key;
static int fork_key_live;

static void cancel_unlock(void *unused)
{
    (void)unused;
    atomic_store(&cancel_cleanup, 1);
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "canceled initializer cleanup unlock failed");
}

static void lifecycle_destructor(void *value)
{
    REQUIRE(value == &cancel_cleanup, "canceled initializer TSD value differs");
    REQUIRE(atomic_load(&cancel_cleanup) == 1, "TSD ran before cancellation cleanup");
    REQUIRE(pthread_getspecific(lifecycle_key) == NULL, "TSD value was not cleared before destructor");
    int iteration = atomic_fetch_add(&cancel_destructors, 1) + 1;
    if (iteration < PTHREAD_DESTRUCTOR_ITERATIONS)
        REQUIRE(pthread_setspecific(lifecycle_key, value) == 0, "canceled initializer TSD rearm failed");
    else
        REQUIRE(iteration == PTHREAD_DESTRUCTOR_ITERATIONS, "TSD exceeded destructor iteration bound");
}

static void cancel_once_initializer(void)
{
    int attempt = atomic_fetch_add(&canceled_once_calls, 1);
    REQUIRE(attempt == 0 || attempt == 1, "canceled once retried too often");
    if (attempt == 0) {
        REQUIRE(pthread_setspecific(lifecycle_key, &cancel_cleanup) == 0, "canceled initializer TSD set failed");
        REQUIRE(pthread_mutex_lock(&gate) == 0, "canceled initializer gate lock failed");
        pthread_cleanup_push(cancel_unlock, NULL);
        cancel_initializer_ready = 1;
        REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "canceled initializer announcement failed");
        for (;;)
            REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "canceled initializer wait failed");
        pthread_cleanup_pop(1);
    }
    REQUIRE(initialized_tls == TLS_INITIAL && zero_tls == 0, "retry worker initial TLS differs");
    atomic_store(&canceled_once_publication, 0x2391);
}

static void *cancel_once_worker(void *argument)
{
    if (argument) {
        REQUIRE(pthread_mutex_lock(&gate) == 0, "canceled once waiter gate lock failed");
        cancel_waiter_ready = 1;
        REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "canceled once waiter announcement failed");
        REQUIRE(pthread_mutex_unlock(&gate) == 0, "canceled once waiter gate unlock failed");
    }
    REQUIRE(pthread_once(&canceled_once, cancel_once_initializer) == 0, "canceled once call failed");
    REQUIRE(atomic_load(&canceled_once_publication) == 0x2391, "canceled once retry publication differs");
    return argument;
}

static void canceled_once_phase(void)
{
    pthread_t initializer, waiter;
    REQUIRE(pthread_key_create(&lifecycle_key, lifecycle_destructor) == 0, "lifecycle TSD create failed");
    REQUIRE(pthread_create(&initializer, NULL, cancel_once_worker, NULL) == 0, "cancel initializer create failed");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "main canceled once gate lock failed");
    while (!cancel_initializer_ready)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "main canceled initializer wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "main canceled initializer gate unlock failed");
    REQUIRE(pthread_create(&waiter, NULL, cancel_once_worker, &cancel_waiter_ready) == 0, "cancel waiter create failed");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "main canceled waiter gate lock failed");
    while (!cancel_waiter_ready)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "main canceled waiter wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "main canceled waiter gate unlock failed");
    REQUIRE(pthread_cancel(initializer) == 0, "once initializer cancel failed");
    void *result = NULL;
    REQUIRE(pthread_join(initializer, &result) == 0 && result == PTHREAD_CANCELED, "once canceled join differs");
    REQUIRE(atomic_load(&cancel_destructors) == PTHREAD_DESTRUCTOR_ITERATIONS, "canceled initializer TSD did not finish before join");
    REQUIRE(pthread_join(waiter, &result) == 0 && result == &cancel_waiter_ready, "once retry join differs");
    REQUIRE(pthread_once(&canceled_once, cancel_once_initializer) == 0, "completed canceled once reuse failed");
    REQUIRE(atomic_load(&canceled_once_calls) == 2, "canceled once completion reran initializer");
    REQUIRE(pthread_key_delete(lifecycle_key) == 0, "lifecycle TSD delete failed");
}

static void fork_prepare(void) { fork_callback_sequence = 1; }
static void fork_parent(void)
{
    REQUIRE(fork_callback_sequence == 1, "fork parent callback order differs");
    fork_callback_sequence = 2;
}
static void fork_child(void)
{
    REQUIRE(fork_callback_sequence == 1, "fork child callback order differs");
    fork_callback_sequence = 3;
}

static void *fork_worker(void *argument)
{
    (void)argument;
    REQUIRE(initialized_tls == TLS_INITIAL && zero_tls == 0, "fork worker initial TLS differs");
    REQUIRE(pthread_getspecific(fork_key) == NULL, "fork worker inherited main TSD");
    REQUIRE(pthread_setspecific(fork_key, &fork_worker_release) == 0, "fork worker TSD set failed");
    initialized_tls = 0x991;
    REQUIRE(pthread_mutex_lock(&gate) == 0, "fork worker gate lock failed");
    fork_worker_ready = 1;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "fork worker announcement failed");
    while (!fork_worker_release)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "fork worker release wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "fork worker gate unlock failed");
    REQUIRE(initialized_tls == 0x991, "parent worker TLS changed after fork");
    REQUIRE(pthread_getspecific(fork_key) == &fork_worker_release, "parent worker TSD changed after fork");
    return NULL;
}

struct churn_worker {
    int id;
    int destructor_calls;
};
static pthread_key_t churn_key;

static void churn_destructor(void *value)
{
    struct churn_worker *worker = value;
    REQUIRE(initialized_tls == TLS_INITIAL + worker->id + 1 && zero_tls == worker->id + 1,
            "churn destructor TLS differs");
    REQUIRE(pthread_getspecific(churn_key) == NULL, "churn destructor value was not cleared");
    ++worker->destructor_calls;
    if (worker->destructor_calls < PTHREAD_DESTRUCTOR_ITERATIONS)
        REQUIRE(pthread_setspecific(churn_key, worker) == 0, "churn TSD rearm failed");
}

static void *churn_main(void *argument)
{
    struct churn_worker *worker = argument;
    REQUIRE(initialized_tls == TLS_INITIAL && zero_tls == 0, "reused worker initial TLS differs");
    REQUIRE(pthread_getspecific(churn_key) == NULL, "reused worker retained TSD");
    if (fork_key_live)
        REQUIRE(pthread_getspecific(fork_key) == NULL, "child worker inherited main TSD");
    REQUIRE((uintptr_t)aligned_tls % 256 == 0 && aligned_tls[0] == 0x51 && aligned_tls[16] == 0,
            "reused worker aligned TLS differs");
    aligned_tls[0] = (unsigned char)worker->id;
    aligned_tls[16] = 0xa1;
    initialized_tls += worker->id + 1;
    zero_tls = worker->id + 1;
    REQUIRE(pthread_setspecific(churn_key, worker) == 0, "churn TSD set failed");
    unsigned char *allocation = malloc(4097);
    REQUIRE(allocation != NULL, "churn allocation failed");
    for (int index = 0; index < 4097; ++index) allocation[index] = (unsigned char)worker->id;
    for (int index = 0; index < 4097; ++index)
        REQUIRE(allocation[index] == (unsigned char)worker->id, "churn allocation ownership differs");
    free(allocation);
    if (worker->id & 1) pthread_exit(worker);
    return worker;
}

static void churn_phase(int rounds)
{
    REQUIRE(pthread_key_create(&churn_key, churn_destructor) == 0, "churn key create failed");
    for (int round = 0; round < rounds; ++round) {
        pthread_t threads[WORKERS];
        struct churn_worker state[WORKERS] = {0};
        for (int index = 0; index < WORKERS; ++index) {
            state[index].id = index;
            REQUIRE(pthread_create(&threads[index], NULL, churn_main, &state[index]) == 0, "churn worker create failed");
        }
        for (int index = 0; index < WORKERS; ++index) {
            void *result = NULL;
            REQUIRE(pthread_join(threads[index], &result) == 0 && result == &state[index], "churn join ownership differs");
            REQUIRE(state[index].destructor_calls == PTHREAD_DESTRUCTOR_ITERATIONS, "churn TSD teardown incomplete at join");
        }
        REQUIRE(initialized_tls == TLS_INITIAL && zero_tls == 0, "worker churn changed main TLS");
    }
    REQUIRE(pthread_key_delete(churn_key) == 0, "churn key delete failed");
}

/* Fork preserves the calling thread's TSD, while child-created workers receive
 * fresh thread state. The parent's waiting worker retains its own TLS and TSD. */
static void live_worker_fork_phase(void)
{
    pthread_t worker;
    REQUIRE(pthread_key_create(&fork_key, NULL) == 0, "fork TSD key create failed");
    fork_key_live = 1;
    REQUIRE(pthread_setspecific(fork_key, &fork_worker_ready) == 0, "fork main TSD set failed");
    REQUIRE(pthread_atfork(fork_prepare, fork_parent, fork_child) == 0, "atfork registration failed");
    REQUIRE(pthread_create(&worker, NULL, fork_worker, NULL) == 0, "fork worker create failed");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "main fork gate lock failed");
    while (!fork_worker_ready)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "main fork worker wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "main fork gate unlock failed");
    pid_t child = fork();
    REQUIRE(child >= 0, "live worker fork failed");
    if (child == 0) {
        REQUIRE(fork_callback_sequence == 3, "fork child callback missing");
        REQUIRE(initialized_tls == TLS_INITIAL && zero_tls == 0, "fork child main TLS differs");
        REQUIRE(pthread_getspecific(fork_key) == &fork_worker_ready, "fork child main TSD differs");
        REQUIRE(pthread_once(&canceled_once, cancel_once_initializer) == 0, "fork child completed once reuse failed");
        REQUIRE(atomic_load(&canceled_once_calls) == 2, "fork child completed once reran");
        churn_phase(4);
        _Exit(0);
    }
    REQUIRE(fork_callback_sequence == 2, "fork parent callback missing");
    int status = 0;
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "fork child lifecycle composition failed");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "main fork release gate lock failed");
    fork_worker_release = 1;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "main fork release announcement failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "main fork release gate unlock failed");
    REQUIRE(pthread_join(worker, NULL) == 0, "parent live worker join failed");
    REQUIRE(pthread_getspecific(fork_key) == &fork_worker_ready, "fork parent main TSD differs");
    REQUIRE(pthread_key_delete(fork_key) == 0, "fork TSD key delete failed");
    fork_key_live = 0;
}

int main(void)
{
    REQUIRE(tss_create(&tsd_key, tsd_destructor) == thrd_success, "TSD key create failed");
    REQUIRE(pthread_barrier_init(&barrier, NULL, WORKERS) == 0, "barrier init failed");
    REQUIRE(pthread_spin_init(&spin, PTHREAD_PROCESS_PRIVATE) == 0, "spin init failed");

    thrd_t threads[WORKERS];
    for (int index = 0; index < WORKERS; ++index) {
        workers[index].id = index;
        REQUIRE(thrd_create(&threads[index], worker_main, &workers[index]) == thrd_success,
                "C11 worker create failed");
    }

    REQUIRE(pthread_mutex_lock(&gate) == 0, "main call_once gate lock failed");
    while (!once_initializer_live || once_waiter_approaches != WORKERS - 1)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "main call_once approach wait failed");
    release_once_initializer = 1;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "main call_once release broadcast failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "main call_once gate unlock failed");

    REQUIRE(pthread_mutex_lock(&gate) == 0, "main reader gate lock failed");
    while (readers_ready != 2)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "main reader gate wait failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "main reader gate unlock failed");
    REQUIRE(pthread_rwlock_trywrlock(&rwlock) == EBUSY, "rwlock writer was not excluded by overlapping readers");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "main reader release lock failed");
    release_readers = 1;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "main reader release broadcast failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "main reader release unlock failed");
    REQUIRE(pthread_rwlock_wrlock(&rwlock) == 0, "rwlock writer lock failed");
    rw_publication = 0x51a7;
    REQUIRE(pthread_rwlock_unlock(&rwlock) == 0, "rwlock writer unlock failed");
    REQUIRE(pthread_mutex_lock(&gate) == 0, "main rwlock publication gate lock failed");
    rw_writer_published = 1;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "main rwlock publication broadcast failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "main rwlock publication gate unlock failed");

    REQUIRE(pthread_mutex_lock(&gate) == 0, "main spin gate lock failed");
    while (!spin_holder_ready || !spin_try_busy)
        REQUIRE(pthread_cond_wait(&gate_changed, &gate) == 0, "main spin gate wait failed");
    release_spin = 1;
    REQUIRE(pthread_cond_broadcast(&gate_changed) == 0, "main spin release broadcast failed");
    REQUIRE(pthread_mutex_unlock(&gate) == 0, "main spin gate unlock failed");

    for (int index = 0; index < WORKERS; ++index) {
        int result = 0;
        REQUIRE(thrd_join(threads[index], &result) == thrd_success && result == 100 + index,
                "C11 worker join result differs");
        REQUIRE(workers[index].initialized_value == TLS_INITIAL + index + 1
                && workers[index].zero_value == index + 1, "worker TLS publication differs");
        REQUIRE(atomic_load_explicit(&tsd_calls[index], memory_order_seq_cst) == 2
                && atomic_load_explicit(&tsd_phase[index], memory_order_seq_cst) == 2,
                "TSD destructor did not finish before joined completion");
        for (int other = 0; other < index; ++other)
            REQUIRE(workers[index].initialized_address != workers[other].initialized_address
                    && workers[index].zero_address != workers[other].zero_address,
                    "worker TLS storage was not distinct");
    }
    for (int phase = 0; phase < BARRIER_PHASES; ++phase)
        REQUIRE(atomic_load_explicit(&barrier_serial[phase], memory_order_seq_cst) == 1,
                "barrier phase has wrong serial return count");
    REQUIRE(atomic_load_explicit(&once_calls, memory_order_seq_cst) == 1,
            "call_once final count differs");
    REQUIRE(once_returns == WORKERS && !once_returned_while_live,
            "call_once waiter returned before initializer publication");
    REQUIRE(atomic_load_explicit(&rw_reader_observed, memory_order_seq_cst) == 2,
            "rwlock reader publication observations differ");
    REQUIRE(spin_publication == 2,
            "synchronization publication differs");

    REQUIRE(pthread_spin_destroy(&spin) == 0, "spin destroy failed");
    REQUIRE(pthread_barrier_destroy(&barrier) == 0, "barrier destroy failed");
    tss_delete(tsd_key);
    REQUIRE((uintptr_t)aligned_tls % 256 == 0 && aligned_tls[0] == 0x51 && aligned_tls[16] == 0,
            "main aligned TLS differs");
    canceled_once_phase();
    live_worker_fork_phase();
    churn_phase(32);
    REQUIRE(aligned_tls[0] == 0x51 && aligned_tls[16] == 0, "worker churn changed main aligned TLS");
    puts("pthread-family-composition-ok");
    return 0;
}
