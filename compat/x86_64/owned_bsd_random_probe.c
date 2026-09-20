/*
 * Installed BSD random-family workload.
 *
 * This is deliberately a consumer of the published stdlib declarations, not
 * an implementation of the recurrence.  The runner compiles this one object
 * with the installed dynamic driver, links that unchanged object through
 * pinned musl and every owned product route, and raw-compares the
 * single-thread observations.  The two concurrent modes instead check
 * schedule-independent invariants in both implementations.
 */
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this workload requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef long (*random_signature)(void);
typedef void (*srandom_signature)(unsigned);
typedef char *(*initstate_signature)(unsigned, char *, size_t);
typedef char *(*setstate_signature)(char *);

_Static_assert(sizeof(unsigned) == 4, "BSD random seed word");
_Static_assert(sizeof(long) == 8, "BSD random return word");
_Static_assert(__builtin_types_compatible_p(__typeof__(&random), random_signature),
    "random declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&srandom), srandom_signature),
    "srandom declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&initstate), initstate_signature),
    "initstate declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setstate), setstate_signature),
    "setstate declaration");

enum { RANDOM_MAXIMUM = 0x7fffffffL };

union state_buffer {
    uint32_t words[68];
    unsigned char bytes[272];
};

static const size_t STATE_SIZES[] = { 8, 31, 32, 63, 64, 127, 128, 255, 256, 272 };

static int checked_random(long *out)
{
    long value = random();

    if (value < 0 || value > RANDOM_MAXIMUM)
        return 1;
    *out = value;
    return 0;
}

static void print_values(const char *label, const long *values, size_t count)
{
    size_t index;

    printf("%s=", label);
    for (index = 0; index < count; index++)
        printf("%s%ld", index == 0 ? "" : ",", values[index]);
    putchar('\n');
}

static int collect(unsigned seed, long *values, size_t count)
{
    size_t index;

    srandom(seed);
    for (index = 0; index < count; index++) {
        if (checked_random(&values[index]))
            return 1;
    }
    return 0;
}

static int run_core(void)
{
    static const unsigned seeds[] = { 0U, 1U, 0x80000000U, 0xffffffffU };
    long default_first;
    long recreated;
    long values[4];
    size_t index;

    errno = E2BIG;
    if (checked_random(&default_first) || errno != E2BIG)
        return 1;
    errno = EDEADLK;
    srandom(1U);
    if (errno != EDEADLK || checked_random(&recreated) || recreated != default_first)
        return 2;

    for (index = 0; index < sizeof(seeds) / sizeof(seeds[0]); index++) {
        char label[24];

        errno = E2BIG;
        if (collect(seeds[index], values, sizeof(values) / sizeof(values[0])) || errno != E2BIG)
            return 3;
        snprintf(label, sizeof(label), "seed-%08x", seeds[index]);
        print_values(label, values, sizeof(values) / sizeof(values[0]));
    }
    printf("core=default-reseed errno-preserved\n");
    return 0;
}

static int run_state(void)
{
    union state_buffer states[sizeof(STATE_SIZES) / sizeof(STATE_SIZES[0])];
    union state_buffer retained_a;
    union state_buffer retained_b;
    union state_buffer invalid;
    unsigned char invalid_before[8];
    long expected;
    long stream[128];
    char *initial_state = NULL;
    char *returned;
    char *active;
    unsigned char snapshot[sizeof(retained_a.bytes)];
    size_t index;
    int result = 0;

    /* musl returns null before taking its lock or inspecting state.  Preserve
     * both the exact errno sentinel and the next generator transition at every
     * invalid size, including zero. */
    memset(invalid.bytes, 0xa5, sizeof(invalid.bytes));
    memcpy(invalid_before, invalid.bytes, sizeof(invalid_before));
    for (index = 0; index < 8; index++) {
        srandom(0x13579bdfU);
        if (checked_random(&expected))
            return 1;
        srandom(0x13579bdfU);
        errno = E2BIG;
        if (initstate(7U, (char *)invalid.bytes, index) != NULL || errno != E2BIG ||
            memcmp(invalid.bytes, invalid_before, sizeof(invalid_before)) != 0)
            return 2;
        if (checked_random(&stream[0]) || stream[0] != expected)
            return 3;
    }

    for (index = 0; index < sizeof(STATE_SIZES) / sizeof(STATE_SIZES[0]); index++) {
        size_t draws = STATE_SIZES[index] < 32 ? 4 :
                       STATE_SIZES[index] < 64 ? 16 :
                       STATE_SIZES[index] < 128 ? 32 :
                       STATE_SIZES[index] < 256 ? 64 : 128;

        memset(states[index].bytes, 0, sizeof(states[index].bytes));
        errno = EDEADLK;
        returned = initstate((unsigned)(0x10203040U + index),
                             (char *)states[index].bytes, STATE_SIZES[index]);
        if (returned == NULL || errno != EDEADLK) {
            result = 4;
            goto restore;
        }
        if (index == 0)
            initial_state = returned;
        /* The additive classes cross their ring wraps more than twice: n=7
         * takes 16 draws, n=15 takes 32, n=31 takes 64, and n=63 takes 128.
         * The size 272 row also proves the final class above its threshold. */
        if (collect((unsigned)(0x10203040U + index), stream, draws)) {
            result = 5;
            goto restore;
        }
        printf("state-size-%zu=%zu ", index, STATE_SIZES[index]);
        print_values("stream", stream, draws);
    }

    /* initstate saves the old state before selecting and seeding the new
     * image; setstate does likewise.  Snapshot the inactive buffer after each
     * transition to make retained caller buffers observable. */
    memset(retained_a.bytes, 0, sizeof(retained_a.bytes));
    memset(retained_b.bytes, 0, sizeof(retained_b.bytes));
    active = initstate(0x2468ace0U, (char *)retained_a.bytes, 256);
    if (active == NULL) {
        result = 6;
        goto restore;
    }
    returned = initstate(0x89abcdefU, (char *)retained_b.bytes, 256);
    if (returned != (char *)retained_a.bytes) {
        result = 7;
        goto restore;
    }
    memcpy(snapshot, retained_a.bytes, sizeof(snapshot));
    if (checked_random(&stream[0]) || memcmp(snapshot, retained_a.bytes, sizeof(snapshot)) != 0) {
        result = 8;
        goto restore;
    }
    returned = setstate((char *)retained_a.bytes);
    if (returned != (char *)retained_b.bytes) {
        result = 9;
        goto restore;
    }
    memcpy(snapshot, retained_b.bytes, sizeof(snapshot));
    if (checked_random(&stream[0]) || memcmp(snapshot, retained_b.bytes, sizeof(snapshot)) != 0) {
        result = 10;
        goto restore;
    }
    returned = setstate((char *)retained_a.bytes);
    if (returned != (char *)retained_a.bytes) {
        result = 11;
        goto restore;
    }

restore:
    /* No automatic buffer remains selected once this function returns. */
    if (initial_state != NULL)
        (void)setstate(initial_state);
    if (result != 0)
        return result;
    printf("state=invalid-0..7-errno pointer-restoration retained-buffers\n");
    return 0;
}

struct gate {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
    int release;
};

static int gate_wait(struct gate *gate)
{
    int error;

    error = pthread_mutex_lock(&gate->mutex);
    if (error != 0)
        return error;
    gate->ready++;
    error = pthread_cond_broadcast(&gate->condition);
    while (error == 0 && !gate->release)
        error = pthread_cond_wait(&gate->condition, &gate->mutex);
    if (pthread_mutex_unlock(&gate->mutex) != 0 && error == 0)
        error = 1;
    return error;
}

struct random_worker {
    struct gate *gate;
    long *values;
    unsigned calls;
    int error;
};

static void *concurrent_random_worker(void *opaque)
{
    struct random_worker *worker = opaque;
    unsigned index;

    worker->error = gate_wait(worker->gate);
    if (worker->error != 0)
        return NULL;
    for (index = 0; index < worker->calls; index++) {
        if (checked_random(&worker->values[index])) {
            worker->error = 1;
            break;
        }
    }
    return NULL;
}

static int compare_long(const void *left, const void *right)
{
    long a = *(const long *)left;
    long b = *(const long *)right;

    return (a > b) - (a < b);
}

static int run_concurrent_random(void)
{
    enum { THREADS = 8, CALLS = 128, TOTAL = THREADS * CALLS };
    struct gate gate = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0U, 0 };
    struct random_worker workers[THREADS];
    pthread_t threads[THREADS];
    long expected[TOTAL];
    long actual[TOTAL];
    long expected_final;
    long actual_final;
    unsigned index;
    int error = 0;

    if (collect(0x6a09e667U, expected, TOTAL) || checked_random(&expected_final))
        return 1;
    srandom(0x6a09e667U);
    for (index = 0; index < THREADS; index++) {
        workers[index].gate = &gate;
        workers[index].values = actual + index * CALLS;
        workers[index].calls = CALLS;
        workers[index].error = 0;
        if (pthread_create(&threads[index], NULL, concurrent_random_worker, &workers[index]) != 0)
            return 2;
    }
    if (pthread_mutex_lock(&gate.mutex) != 0)
        return 3;
    while (gate.ready != THREADS) {
        if (pthread_cond_wait(&gate.condition, &gate.mutex) != 0) {
            (void)pthread_mutex_unlock(&gate.mutex);
            return 4;
        }
    }
    gate.release = 1;
    if (pthread_cond_broadcast(&gate.condition) != 0 || pthread_mutex_unlock(&gate.mutex) != 0)
        return 5;
    for (index = 0; index < THREADS; index++) {
        if (pthread_join(threads[index], NULL) != 0)
            return 6;
        error |= workers[index].error;
    }
    if (error || checked_random(&actual_final))
        return 7;
    qsort(expected, TOTAL, sizeof(expected[0]), compare_long);
    qsort(actual, TOTAL, sizeof(actual[0]), compare_long);
    if (memcmp(expected, actual, sizeof(expected)) != 0 || actual_final != expected_final)
        return 8;
    printf("concurrent-random=sorted-multiset-%u final=%ld\n", TOTAL, actual_final);
    return 0;
}

static union state_buffer concurrent_state_buffers[3];

struct state_worker {
    struct gate *gate;
    unsigned role;
    int error;
};

static void *concurrent_state_worker(void *opaque)
{
    struct state_worker *worker = opaque;
    unsigned index;
    long value;

    worker->error = gate_wait(worker->gate);
    if (worker->error != 0)
        return NULL;
    for (index = 0; index < 32; index++) {
        if (worker->role == 0) {
            srandom(0x31415926U + index);
        } else if (worker->role == 1) {
            if (initstate(0x27182818U + index, (char *)concurrent_state_buffers[1].bytes,
                          256) == NULL) {
                worker->error = 1;
                break;
            }
        } else if (setstate((char *)concurrent_state_buffers[2].bytes) == NULL) {
            worker->error = 1;
            break;
        }
        if (checked_random(&value)) {
            worker->error = 1;
            break;
        }
    }
    return NULL;
}

static int run_concurrent_state(void)
{
    enum { THREADS = 3, CALLS = 32 };
    struct gate gate = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0U, 0 };
    struct state_worker workers[THREADS];
    pthread_t threads[THREADS];
    char *initial_state;
    unsigned index;
    int error = 0;

    memset(concurrent_state_buffers, 0, sizeof(concurrent_state_buffers));
    initial_state = initstate(0x10203040U, (char *)concurrent_state_buffers[0].bytes, 256);
    if (initial_state == NULL ||
        initstate(0x50607080U, (char *)concurrent_state_buffers[1].bytes, 256) == NULL ||
        initstate(0x90a0b0c0U, (char *)concurrent_state_buffers[2].bytes, 256) == NULL ||
        setstate(initial_state) == NULL)
        return 1;
    for (index = 0; index < THREADS; index++) {
        workers[index].gate = &gate;
        workers[index].role = index;
        workers[index].error = 0;
        if (pthread_create(&threads[index], NULL, concurrent_state_worker, &workers[index]) != 0)
            return 2;
    }
    if (pthread_mutex_lock(&gate.mutex) != 0)
        return 3;
    while (gate.ready != THREADS) {
        if (pthread_cond_wait(&gate.condition, &gate.mutex) != 0) {
            (void)pthread_mutex_unlock(&gate.mutex);
            return 4;
        }
    }
    gate.release = 1;
    if (pthread_cond_broadcast(&gate.condition) != 0 || pthread_mutex_unlock(&gate.mutex) != 0)
        return 5;
    for (index = 0; index < THREADS; index++) {
        if (pthread_join(threads[index], NULL) != 0)
            error = 1;
        error |= workers[index].error;
    }
    /* The workers may have selected caller-owned static buffers.  Restore the
     * original process state before reporting the invariant result. */
    (void)setstate(initial_state);
    if (error)
        return 6;
    printf("concurrent-state=reseed-initstate-setstate-%u\n", THREADS * CALLS);
    return 0;
}

struct active_random_worker {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int ready;
    int stop;
    unsigned completed;
    int error;
};

static void *active_random_calls(void *opaque)
{
    struct active_random_worker *worker = opaque;
    long value;

    /* Complete one transition before advertising readiness.  Fork therefore
     * races a continuously active family caller, rather than a thread that
     * has only been scheduled. */
    if (checked_random(&value)) {
        if (pthread_mutex_lock(&worker->mutex) == 0) {
            worker->error = 1;
            worker->ready = 1;
            (void)pthread_cond_broadcast(&worker->condition);
            (void)pthread_mutex_unlock(&worker->mutex);
        }
        return NULL;
    }

    if (pthread_mutex_lock(&worker->mutex) != 0)
        return NULL;
    worker->ready = 1;
    worker->completed = 1;
    (void)pthread_cond_broadcast(&worker->condition);
    (void)pthread_mutex_unlock(&worker->mutex);
    for (;;) {
        if (checked_random(&value)) {
            if (pthread_mutex_lock(&worker->mutex) == 0) {
                worker->error = 1;
                (void)pthread_mutex_unlock(&worker->mutex);
            }
            return NULL;
        }
        if (pthread_mutex_lock(&worker->mutex) != 0)
            return NULL;
        worker->completed++;
        if (worker->stop) {
            (void)pthread_mutex_unlock(&worker->mutex);
            break;
        }
        (void)pthread_mutex_unlock(&worker->mutex);
    }
    return NULL;
}

static int run_fork_active(void)
{
    enum { CHILDREN = 32 };
    struct active_random_worker worker = {
        PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0, 0U, 0,
    };
    pthread_t thread;
    unsigned index;
    int result = 0;

    srandom(0x01234567U);
    if (pthread_create(&thread, NULL, active_random_calls, &worker) != 0)
        return 1;
    if (pthread_mutex_lock(&worker.mutex) != 0)
        return 2;
    while (!worker.ready) {
        if (pthread_cond_wait(&worker.condition, &worker.mutex) != 0) {
            (void)pthread_mutex_unlock(&worker.mutex);
            return 3;
        }
    }
    if (worker.error || worker.completed == 0 || pthread_mutex_unlock(&worker.mutex) != 0)
        return 4;
    for (index = 0; index < CHILDREN; index++) {
        pid_t child = fork();
        int status;

        if (child < 0) {
            result = 5;
            break;
        }
        if (child == 0) {
            long value;

            alarm(2);
            value = random();
            alarm(0);
            _exit(value >= 0 && value <= RANDOM_MAXIMUM ? 0 : 6);
        }
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            result = 7;
            break;
        }
    }
    if (pthread_mutex_lock(&worker.mutex) != 0)
        return 8;
    worker.stop = 1;
    if (pthread_mutex_unlock(&worker.mutex) != 0 || pthread_join(thread, NULL) != 0)
        return 9;
    if (worker.error || worker.completed == 0)
        return 10;
    if (result != 0)
        return result;
    printf("fork-active=children-%u copied-lock-repaired\n", CHILDREN);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s {core|state|concurrent-random|concurrent-state|fork-active}\n", argv[0]);
        return 64;
    }
    if (strcmp(argv[1], "core") == 0)
        return run_core();
    if (strcmp(argv[1], "state") == 0)
        return run_state();
    if (strcmp(argv[1], "concurrent-random") == 0)
        return run_concurrent_random();
    if (strcmp(argv[1], "concurrent-state") == 0)
        return run_concurrent_state();
    if (strcmp(argv[1], "fork-active") == 0)
        return run_fork_active();
    fprintf(stderr, "unknown scenario: %s\n", argv[1]);
    return 64;
}
