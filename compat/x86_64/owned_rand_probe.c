/*
 * Installed-header rand/srand workload. Pinned musl is the deterministic
 * single-thread oracle; the candidate-only concurrent case deliberately never
 * executes against musl because musl's process-global state is racy there.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
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

typedef int (*rand_signature)(void);
typedef void (*srand_signature)(unsigned);

_Static_assert(sizeof(unsigned) == 4, "unsigned is 32 bits");
_Static_assert(sizeof(int) == 4, "int is 32 bits");
_Static_assert(RAND_MAX == 0x7fffffff, "rand result bound");
_Static_assert(__builtin_types_compatible_p(__typeof__(&rand), rand_signature),
    "rand declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&srand), srand_signature),
    "srand declaration");

static int constructor_default;

__attribute__((constructor))
static void crabc_owned_rand_constructor(void)
{
    constructor_default = rand();
}

static void print_values(const char *label, const int *values, size_t count)
{
    size_t index;

    printf("%s=", label);
    for (index = 0; index < count; index++)
        printf("%s%u", index == 0 ? "" : ",", (unsigned)values[index]);
    putchar('\n');
}

static int collect(unsigned seed, int *values, size_t count)
{
    size_t index;

    srand(seed);
    for (index = 0; index < count; index++) {
        values[index] = rand();
        if (values[index] < 0 || values[index] > RAND_MAX)
            return 1;
    }
    return 0;
}

static int run_core(void)
{
    static const unsigned seeds[] = {
        0U, 1U, 2U, 0x7fffffffU, 0x80000000U, 0xfffffffeU, 0xffffffffU,
    };
    /* These literals deliberately choose broad 32-bit seed coverage without
       embedding a second PRNG in the workload. The runner raw-compares all
       64 independent 128-output streams to the pinned musl executable. */
    static const unsigned broader_seeds[] = {
        0x00000000U, 0x00000001U, 0x00000002U, 0x00000003U,
        0x00000004U, 0x00000007U, 0x0000000fU, 0x00000010U,
        0x0000001fU, 0x00000020U, 0x0000003fU, 0x00000040U,
        0x0000007fU, 0x00000080U, 0x000000ffU, 0x00000100U,
        0x0000ffffU, 0x00010000U, 0x0001ffffU, 0x00020000U,
        0x000fffffU, 0x00100000U, 0x00ffffffU, 0x01000000U,
        0x0fffffffU, 0x10000000U, 0x13579bdfU, 0x1fffffffU,
        0x20000000U, 0x2468ace0U, 0x3fffffffU, 0x40000000U,
        0x55555555U, 0x5a5a5a5aU, 0x60000000U, 0x6db6db6dU,
        0x7ffffffeU, 0x7fffffffU, 0x80000000U, 0x80000001U,
        0x81234567U, 0x89abcdefU, 0x9abcdef0U, 0xa5a5a5a5U,
        0xaaaaaaaaU, 0xbfffffffU, 0xc0000000U, 0xcafebabeU,
        0xdeadbeefU, 0xe0000000U, 0xefffffffU, 0xf0000000U,
        0xfedcba98U, 0xffffff00U, 0xffffff7fU, 0xffffff80U,
        0xfffffffeU, 0xffffffffU, 0x31415926U, 0x27182818U,
        0x10203040U, 0x40302010U, 0x01234567U, 0x76543210U,
    };
    int first_seed_one[16];
    int repeated_seed_one[16];
    int seed_values[7][4];
    static int broader_values[64][128];
    _Static_assert(sizeof(broader_seeds) / sizeof(broader_seeds[0]) ==
                       sizeof(broader_values) / sizeof(broader_values[0]),
                   "broader seed and result rows agree");
    int zero_values[4];
    int long_values[256];
    int default_second;
    int bounded;
    int function_value;
    rand_signature next = rand;
    srand_signature seed = srand;
    size_t index;

    if (constructor_default < 0 || constructor_default > RAND_MAX)
        return 1;

    errno = E2BIG;
    default_second = rand();
    if (default_second < 0 || default_second > RAND_MAX || errno != E2BIG)
        return 2;

    errno = EDEADLK;
    seed(1U);
    if (errno != EDEADLK)
        return 3;
    function_value = next();
    /* Initial state is zero; musl srand(1) writes 1U - 1U and therefore
       recreates the constructor's first default transition. */
    if (function_value != constructor_default)
        return 4;

    if (collect(1U, first_seed_one, sizeof(first_seed_one) / sizeof(first_seed_one[0])) ||
        collect(1U, repeated_seed_one, sizeof(repeated_seed_one) / sizeof(repeated_seed_one[0])) ||
        memcmp(first_seed_one, repeated_seed_one, sizeof(first_seed_one)) != 0)
        return 5;

    for (index = 0; index < sizeof(seeds) / sizeof(seeds[0]); index++) {
        if (collect(seeds[index], seed_values[index],
                    sizeof(seed_values[index]) / sizeof(seed_values[index][0])))
            return 6;
    }
    /* This is the source-sensitive u32-wrapping seed edge: the oracle output
       is compared raw by the runner, rather than reproducing its recurrence. */
    if (collect(0U, zero_values, sizeof(zero_values) / sizeof(zero_values[0])))
        return 7;
    if (collect(0x13579bdfU, long_values,
                sizeof(long_values) / sizeof(long_values[0])))
        return 8;
    for (index = 0; index < sizeof(broader_seeds) / sizeof(broader_seeds[0]); index++) {
        if (collect(broader_seeds[index], broader_values[index],
                    sizeof(broader_values[index]) / sizeof(broader_values[index][0])))
            return 9;
    }

    errno = E2BIG;
    bounded = rand();
    if (bounded < 0 || bounded > RAND_MAX || errno != E2BIG)
        return 10;
    errno = EDEADLK;
    srand(0x2468ace0U);
    if (errno != EDEADLK)
        return 11;

    printf("constructor=%u default-second=%u seed1-first=%u\n",
           (unsigned)constructor_default, (unsigned)default_second,
           (unsigned)function_value);
    print_values("seed1", first_seed_one, sizeof(first_seed_one) / sizeof(first_seed_one[0]));
    for (index = 0; index < sizeof(seeds) / sizeof(seeds[0]); index++) {
        char label[20];

        snprintf(label, sizeof(label), "seed-%08x", seeds[index]);
        print_values(label, seed_values[index],
                     sizeof(seed_values[index]) / sizeof(seed_values[index][0]));
    }
    print_values("srand0-u32-prewiden", zero_values,
                 sizeof(zero_values) / sizeof(zero_values[0]));
    print_values("long-13579bdf", long_values,
                 sizeof(long_values) / sizeof(long_values[0]));
    for (index = 0; index < sizeof(broader_seeds) / sizeof(broader_seeds[0]); index++) {
        char label[24];

        snprintf(label, sizeof(label), "broad-%02u-%08x", (unsigned)index,
                 broader_seeds[index]);
        print_values(label, broader_values[index],
                     sizeof(broader_values[index]) / sizeof(broader_values[index][0]));
    }
    printf("rand-max=%u errno-preserved=ok reseed=ok broader=64x128\n", (unsigned)RAND_MAX);
    return 0;
}

struct serialized_worker {
    int value;
};

static void *serialized_next(void *opaque)
{
    struct serialized_worker *worker = opaque;

    worker->value = rand();
    return NULL;
}

static int run_serialized_workers(void)
{
    pthread_t thread;
    struct serialized_worker worker;
    int expected[3];
    int main_first;
    int main_last;

    if (collect(7U, expected, sizeof(expected) / sizeof(expected[0])))
        return 1;
    srand(7U);
    main_first = rand();
    if (pthread_create(&thread, NULL, serialized_next, &worker) != 0)
        return 2;
    if (pthread_join(thread, NULL) != 0)
        return 3;
    main_last = rand();
    if (main_first != expected[0] || worker.value != expected[1] || main_last != expected[2])
        return 4;

    printf("serialized-workers=%u,%u,%u\n", (unsigned)main_first,
           (unsigned)worker.value, (unsigned)main_last);
    return 0;
}

struct concurrent_gate {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
    int release;
};

struct concurrent_worker {
    struct concurrent_gate *gate;
    unsigned calls;
};

static void *concurrent_nexts(void *opaque)
{
    struct concurrent_worker *worker = opaque;
    unsigned index;

    if (pthread_mutex_lock(&worker->gate->mutex) != 0)
        return (void *)(uintptr_t)1;
    worker->gate->ready++;
    /* Main and already-ready workers wait on this same condition. Broadcast
       after changing `ready` so the final worker cannot wake only a peer and
       strand the supervising main thread. */
    if (pthread_cond_broadcast(&worker->gate->condition) != 0) {
        (void)pthread_mutex_unlock(&worker->gate->mutex);
        return (void *)(uintptr_t)2;
    }
    while (!worker->gate->release) {
        if (pthread_cond_wait(&worker->gate->condition, &worker->gate->mutex) != 0) {
            (void)pthread_mutex_unlock(&worker->gate->mutex);
            return (void *)(uintptr_t)3;
        }
    }
    if (pthread_mutex_unlock(&worker->gate->mutex) != 0)
        return (void *)(uintptr_t)4;
    for (index = 0; index < worker->calls; index++)
        (void)rand();
    return NULL;
}

static int run_candidate_concurrency(void)
{
    enum { THREADS = 8, CALLS_PER_THREAD = 128, TOTAL = THREADS * CALLS_PER_THREAD };
    struct concurrent_gate gate = {
        PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0U, 0,
    };
    struct concurrent_worker workers[THREADS];
    pthread_t threads[THREADS];
    void *returned;
    int expected_after;
    int actual_after;
    unsigned index;

    srand(0x6a09e667U);
    for (index = 0; index < TOTAL; index++)
        (void)rand();
    expected_after = rand();

    srand(0x6a09e667U);
    for (index = 0; index < THREADS; index++) {
        workers[index].gate = &gate;
        workers[index].calls = CALLS_PER_THREAD;
        if (pthread_create(&threads[index], NULL, concurrent_nexts, &workers[index]) != 0)
            return 1;
    }
    if (pthread_mutex_lock(&gate.mutex) != 0)
        return 2;
    while (gate.ready != THREADS) {
        if (pthread_cond_wait(&gate.condition, &gate.mutex) != 0) {
            (void)pthread_mutex_unlock(&gate.mutex);
            return 3;
        }
    }
    gate.release = 1;
    if (pthread_cond_broadcast(&gate.condition) != 0 || pthread_mutex_unlock(&gate.mutex) != 0)
        return 4;
    for (index = 0; index < THREADS; index++) {
        if (pthread_join(threads[index], &returned) != 0 || returned != NULL)
            return 5;
    }
    actual_after = rand();
    if (actual_after != expected_after)
        return 6;
    if (pthread_cond_destroy(&gate.condition) != 0 || pthread_mutex_destroy(&gate.mutex) != 0)
        return 7;

    printf("candidate-concurrency-transitions=%u after=%u\n", TOTAL,
           (unsigned)actual_after);
    return 0;
}

struct fork_values {
    int continuation;
    int reseeded;
};

static int write_all(int file_descriptor, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;

    while (length != 0) {
        ssize_t result = write(file_descriptor, cursor, length);
        if (result <= 0)
            return -1;
        cursor += result;
        length -= (size_t)result;
    }
    return 0;
}

static int read_all(int file_descriptor, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;

    while (length != 0) {
        ssize_t result = read(file_descriptor, cursor, length);
        if (result <= 0)
            return -1;
        cursor += result;
        length -= (size_t)result;
    }
    return 0;
}

static int run_fork(void)
{
    int pipe_fds[2];
    struct fork_values child;
    int parent_continuation;
    int prefix;
    int status;
    pid_t child_pid;

    srand(7U);
    prefix = rand();
    if (pipe(pipe_fds) != 0)
        return 1;
    child_pid = fork();
    if (child_pid < 0) {
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        return 2;
    }
    if (child_pid == 0) {
        int child_status = 0;

        (void)close(pipe_fds[0]);
        child.continuation = rand();
        srand(2U);
        child.reseeded = rand();
        if (write_all(pipe_fds[1], &child, sizeof(child)) != 0)
            child_status = 3;
        (void)close(pipe_fds[1]);
        _exit(child_status);
    }

    (void)close(pipe_fds[1]);
    parent_continuation = rand();
    if (read_all(pipe_fds[0], &child, sizeof(child)) != 0) {
        (void)close(pipe_fds[0]);
        return 4;
    }
    (void)close(pipe_fds[0]);
    if (waitpid(child_pid, &status, 0) != child_pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 5;
    if (parent_continuation != child.continuation)
        return 6;
    srand(2U);
    if (rand() != child.reseeded)
        return 7;

    printf("fork-prefix=%u continuation=%u reseed=%u\n", (unsigned)prefix,
           (unsigned)parent_continuation, (unsigned)child.reseeded);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 64;
    if (strcmp(argv[1], "core") == 0)
        return run_core();
    if (strcmp(argv[1], "serialized-workers") == 0)
        return run_serialized_workers();
    if (strcmp(argv[1], "fork") == 0)
        return run_fork();
    if (strcmp(argv[1], "candidate-concurrency") == 0)
        return run_candidate_concurrency();
    return 64;
}
