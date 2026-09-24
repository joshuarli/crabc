#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

/* Each counter and its complement are published only through the spinlock.
 * Contending threads/processes must observe a complete preceding update. */
struct state {
    pthread_spinlock_t lock;
    unsigned count;
    unsigned complement;
};

static void require(int condition)
{
    if (!condition) _Exit(91);
}

static void initialize(struct state *state, int sharing)
{
    require(pthread_spin_init(&state->lock, sharing) == 0);
    state->count = 0;
    state->complement = ~0u;
    errno = E2BIG;
    require(pthread_spin_trylock(&state->lock) == 0);
    require(pthread_spin_trylock(&state->lock) == EBUSY);
    require(pthread_spin_unlock(&state->lock) == 0);
    require(errno == E2BIG);
}

static void *increment(void *argument)
{
    struct state *state = argument;
    for (unsigned i = 0; i < 20000; i++) {
        errno = EDOM;
        require(pthread_spin_lock(&state->lock) == 0);
        require(state->complement == ~state->count);
        state->count++;
        state->complement = ~state->count;
        require(pthread_spin_unlock(&state->lock) == 0);
        require(errno == EDOM);
    }
    return argument;
}

/* Reader/writer lock attributes, try and timed acquisition, and shared use
 * across fork. Every timed call below must stop at its deadline. */
struct shared_rwlock {
    pthread_rwlock_t lock;
    pthread_barrier_t barrier;
    int value;
};

static struct timespec realtime_after(long milliseconds)
{
    struct timespec deadline;
    require(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_nsec += milliseconds * 1000000L;
    deadline.tv_sec += deadline.tv_nsec / 1000000000L;
    deadline.tv_nsec %= 1000000000L;
    return deadline;
}

static pthread_rwlock_t private_rwlock;
static void *try_read(void *unused)
{
    (void)unused;
    return (void *)(long)pthread_rwlock_tryrdlock(&private_rwlock);
}

static void rwlock_case(void)
{
    pthread_rwlockattr_t attributes;
    int shared = -1;
    errno = E2BIG;
    require(pthread_rwlockattr_init(&attributes) == 0);
    require(pthread_rwlockattr_getpshared(&attributes, &shared) == 0 && shared == PTHREAD_PROCESS_PRIVATE);
    require(pthread_rwlockattr_setpshared(&attributes, 2) == EINVAL);
    require(pthread_rwlockattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED) == 0);
    require(pthread_rwlockattr_getpshared(&attributes, &shared) == 0 && shared == PTHREAD_PROCESS_SHARED);

    /* Private: readers share, a writer excludes readers and writers. */
    require(pthread_rwlock_init(&private_rwlock, NULL) == 0);
    require(pthread_rwlock_tryrdlock(&private_rwlock) == 0);
    require(pthread_rwlock_tryrdlock(&private_rwlock) == 0);
    require(pthread_rwlock_trywrlock(&private_rwlock) == EBUSY);
    struct timespec deadline = realtime_after(20);
    require(pthread_rwlock_timedwrlock(&private_rwlock, &deadline) == ETIMEDOUT);
    require(pthread_rwlock_unlock(&private_rwlock) == 0);
    require(pthread_rwlock_unlock(&private_rwlock) == 0);
    deadline = realtime_after(20);
    require(pthread_rwlock_timedwrlock(&private_rwlock, &deadline) == 0);
    pthread_t reader;
    void *reader_result;
    require(pthread_create(&reader, NULL, try_read, NULL) == 0);
    require(pthread_join(reader, &reader_result) == 0 && (long)reader_result == EBUSY);
    deadline = realtime_after(20);
    /* The writer's own read request is not diagnosed; it waits out the deadline. */
    require(pthread_rwlock_timedrdlock(&private_rwlock, &deadline) == ETIMEDOUT);
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = 1000000000L };
    require(pthread_rwlock_timedrdlock(&private_rwlock, &invalid) == EINVAL);
    require(pthread_rwlock_unlock(&private_rwlock) == 0);
    deadline = realtime_after(20);
    require(pthread_rwlock_timedrdlock(&private_rwlock, &deadline) == 0);
    require(pthread_rwlock_unlock(&private_rwlock) == 0);
    require(pthread_rwlock_destroy(&private_rwlock) == 0);

    /* Shared: a child writer holds the lock until the parent observes it. */
    struct shared_rwlock *state = mmap(NULL, sizeof *state, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    require(state != MAP_FAILED);
    pthread_barrierattr_t barrier_attributes;
    require(pthread_barrierattr_init(&barrier_attributes) == 0);
    require(pthread_barrierattr_getpshared(&barrier_attributes, &shared) == 0 && shared == PTHREAD_PROCESS_PRIVATE);
    require(pthread_barrierattr_setpshared(&barrier_attributes, 2) == EINVAL);
    require(pthread_barrierattr_setpshared(&barrier_attributes, PTHREAD_PROCESS_SHARED) == 0);
    require(pthread_barrierattr_getpshared(&barrier_attributes, &shared) == 0 && shared == PTHREAD_PROCESS_SHARED);
    require(pthread_barrier_init(&state->barrier, &barrier_attributes, 2) == 0);
    require(pthread_barrierattr_destroy(&barrier_attributes) == 0);
    require(pthread_rwlock_init(&state->lock, &attributes) == 0);
    require(pthread_rwlockattr_destroy(&attributes) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (!child) {
        require(pthread_rwlock_wrlock(&state->lock) == 0);
        state->value = 7;
        pthread_barrier_wait(&state->barrier);
        pthread_barrier_wait(&state->barrier);
        state->value = 8;
        require(pthread_rwlock_unlock(&state->lock) == 0);
        _Exit(0);
    }
    pthread_barrier_wait(&state->barrier);
    require(pthread_rwlock_tryrdlock(&state->lock) == EBUSY);
    deadline = realtime_after(20);
    require(pthread_rwlock_timedrdlock(&state->lock, &deadline) == ETIMEDOUT);
    pthread_barrier_wait(&state->barrier);
    require(pthread_rwlock_rdlock(&state->lock) == 0 && state->value == 8);
    require(pthread_rwlock_unlock(&state->lock) == 0);
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    require(pthread_rwlock_destroy(&state->lock) == 0 && pthread_barrier_destroy(&state->barrier) == 0);
    require(munmap(state, sizeof *state) == 0 && errno == E2BIG);
    puts("owned-pthread-rwlock-barrier-attributes-ok");
}

/* pthread_once runs its initializer once; a cancelled initializer resets the
 * control so the next caller runs it again, and waiters block meanwhile. */
static pthread_once_t once_control = PTHREAD_ONCE_INIT;
static atomic_int once_runs, once_entered, once_waiters_done;
static int cancel_first_initializer = 1;

static void once_initializer(void)
{
    atomic_fetch_add(&once_runs, 1);
    if (cancel_first_initializer) {
        cancel_first_initializer = 0;
        atomic_store(&once_entered, 1);
        for (;;) pause();
    }
}

static void *once_caller(void *unused)
{
    (void)unused;
    require(pthread_once(&once_control, once_initializer) == 0);
    return NULL;
}

static void *once_waiter(void *unused)
{
    (void)unused;
    require(pthread_once(&once_control, once_initializer) == 0);
    atomic_fetch_add(&once_waiters_done, 1);
    return NULL;
}

static void once_case(void)
{
    pthread_t first, waiter;
    void *result;
    require(pthread_create(&first, NULL, once_caller, NULL) == 0);
    while (!atomic_load(&once_entered)) sched_yield();
    require(pthread_create(&waiter, NULL, once_waiter, NULL) == 0);
    for (int i = 0; i < 1000; i++) sched_yield();
    require(atomic_load(&once_waiters_done) == 0);
    require(pthread_cancel(first) == 0);
    require(pthread_join(first, &result) == 0 && result == PTHREAD_CANCELED);
    require(pthread_join(waiter, &result) == 0 && atomic_load(&once_waiters_done) == 1);
    require(atomic_load(&once_runs) == 2);
    errno = E2BIG;
    require(pthread_once(&once_control, once_initializer) == 0 && errno == E2BIG);
    require(atomic_load(&once_runs) == 2);
    puts("owned-pthread-once-cancellation-ok");
}

/* C11 call_once runs its function exactly once among contending callers,
 * and every caller returns only after that call has completed. */
static once_flag c11_once = ONCE_FLAG_INIT;
static atomic_int c11_once_runs, c11_once_published;
static void c11_once_function(void)
{
    for (int i = 0; i < 1000; i++) sched_yield();
    atomic_fetch_add(&c11_once_runs, 1);
    atomic_store(&c11_once_published, 1);
}

static void *c11_once_caller(void *unused)
{
    (void)unused;
    call_once(&c11_once, c11_once_function);
    return (void *)(long)atomic_load(&c11_once_published);
}

static void call_once_case(void)
{
    pthread_t callers[4];
    void *result;
    for (int i = 0; i < 4; i++) require(pthread_create(&callers[i], NULL, c11_once_caller, NULL) == 0);
    for (int i = 0; i < 4; i++) require(pthread_join(callers[i], &result) == 0 && result == (void *)1);
    call_once(&c11_once, c11_once_function);
    require(atomic_load(&c11_once_runs) == 1);
    puts("owned-c11-call-once-ok");
}

int main(void)
{
    rwlock_case();
    once_case();
    call_once_case();
    struct state private;
    initialize(&private, PTHREAD_PROCESS_PRIVATE);
    pthread_t workers[4];
    for (unsigned i = 0; i < 4; i++)
        require(pthread_create(&workers[i], NULL, increment, &private) == 0);
    increment(&private);
    for (unsigned i = 0; i < 4; i++) {
        void *result = NULL;
        require(pthread_join(workers[i], &result) == 0 && result == &private);
    }
    require(private.count == 100000 && private.complement == ~private.count);
    require(pthread_spin_destroy(&private.lock) == 0);

    struct state *shared = mmap(NULL, sizeof *shared, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    require(shared != MAP_FAILED);
    initialize(shared, PTHREAD_PROCESS_SHARED);
    /* Force the child to observe a parent-owned lock before contention. */
    require(pthread_spin_lock(&shared->lock) == 0);
    int ready[2];
    require(pipe(ready) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (!child) {
        require(close(ready[0]) == 0);
        require(pthread_spin_trylock(&shared->lock) == EBUSY);
        require(write(ready[1], "r", 1) == 1);
        require(close(ready[1]) == 0);
        increment(shared);
        _Exit(0);
    }
    require(close(ready[1]) == 0);
    char byte;
    require(read(ready[0], &byte, 1) == 1 && byte == 'r');
    require(close(ready[0]) == 0);
    require(pthread_spin_unlock(&shared->lock) == 0);
    increment(shared);
    int status;
    require(waitpid(child, &status, 0) == child);
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    require(shared->count == 40000 && shared->complement == ~shared->count);
    require(pthread_spin_destroy(&shared->lock) == 0);
    require(munmap(shared, sizeof *shared) == 0);
    puts("owned-pthread-spin-ok");
    return 0;
}
