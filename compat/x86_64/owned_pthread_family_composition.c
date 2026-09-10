/*
 * One installed-product pthread/TLS composition used by the x86 family receipt.
 *
 * The program avoids time-based scheduling assumptions. Every transition uses
 * a barrier, mutex/condition handoff, or the selected synchronization primitive
 * being observed. The result line is intentionally fixed for byte comparison
 * with the separately linked pinned-musl object.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>

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
    puts("pthread-family-composition-ok");
    return 0;
}
