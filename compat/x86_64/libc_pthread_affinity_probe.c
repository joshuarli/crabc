/*
 * Linux/x86-64 bounded pthread affinity fixture.
 *
 * One project-header body runs against pinned musl 1.2.6 and the freestanding
 * static crabc-libc candidate. It selects only pthread_getaffinity_np and
 * pthread_setaffinity_np for the bootstrapped main self handle and one
 * executing selected worker handle.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>

_Static_assert(sizeof(cpu_set_t) == 128, "x86 cpu_set_t size");
_Static_assert(_Alignof(cpu_set_t) == 8, "x86 cpu_set_t alignment");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_getaffinity_np),
    int (*)(pthread_t, size_t, struct cpu_set_t *)),
    "pthread_getaffinity_np declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&pthread_setaffinity_np),
    int (*)(pthread_t, size_t, const struct cpu_set_t *)),
    "pthread_setaffinity_np declaration");

enum {
    parent_errno_sentinel = E2BIG,
    sys_gettid = 186,
    sys_sched_getaffinity = 204
};

struct guarded_mask {
    cpu_set_t value;
    unsigned char trailing[16];
};

struct worker_state {
    volatile int ready;
    volatile int release;
    int task;
    int initial_errno;
    int result;
    struct guarded_mask self_mask;
};

static long raw_syscall0(long number)
{
    register long accumulator __asm__("rax") = number;

    __asm__ volatile("syscall"
        : "+a"(accumulator)
        :
        : "rcx", "r11", "memory");
    return accumulator;
}

static long raw_syscall3(long number, long first, long second, long third)
{
    register long accumulator __asm__("rax") = number;
    register long argument_one __asm__("rdi") = first;
    register long argument_two __asm__("rsi") = second;
    register long argument_three __asm__("rdx") = third;

    __asm__ volatile("syscall"
        : "+a"(accumulator)
        : "D"(argument_one), "S"(argument_two), "d"(argument_three)
        : "rcx", "r11", "memory");
    return accumulator;
}

static void fill_bytes(void *opaque, size_t count, unsigned char value)
{
    unsigned char *bytes = opaque;
    size_t index;

    for (index = 0; index != count; ++index)
        bytes[index] = value;
}

static int same_bytes(const void *left_opaque, const void *right_opaque,
                      size_t count)
{
    const unsigned char *left = left_opaque;
    const unsigned char *right = right_opaque;
    size_t index;

    for (index = 0; index != count; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static int trailing_is_unchanged(const struct guarded_mask *mask)
{
    size_t index;

    for (index = 0; index != sizeof(mask->trailing); ++index) {
        if (mask->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int nonempty_mask(const cpu_set_t *mask, size_t count)
{
    const unsigned char *bytes = (const unsigned char *)mask;
    size_t index;

    for (index = 0; index != count; ++index) {
        if (bytes[index] != 0)
            return 1;
    }
    return 0;
}

static int zero_tail(const cpu_set_t *mask, size_t initialized)
{
    const unsigned char *bytes = (const unsigned char *)mask;
    size_t index;

    if (initialized > sizeof(*mask))
        return 0;
    for (index = initialized; index != sizeof(*mask); ++index) {
        if (bytes[index] != 0)
            return 0;
    }
    return 1;
}

static long raw_getaffinity(int task, cpu_set_t *mask)
{
    return raw_syscall3(sys_sched_getaffinity, task, sizeof(*mask),
        (long)(uintptr_t)mask);
}

static int check_getaffinity(pthread_t thread, int task,
                             struct guarded_mask *observed)
{
    struct guarded_mask raw;
    long written;

    fill_bytes(observed, sizeof(*observed), 0xa5);
    errno = parent_errno_sentinel;
    if (pthread_getaffinity_np(thread, sizeof(observed->value),
            &observed->value) != 0 || errno != parent_errno_sentinel)
        return 0;
    if (!trailing_is_unchanged(observed))
        return 0;

    fill_bytes(&raw, sizeof(raw), 0xa5);
    written = raw_getaffinity(task, &raw.value);
    if (written <= 0 || (size_t)written > sizeof(raw.value) ||
        !trailing_is_unchanged(&raw) ||
        !same_bytes(&observed->value, &raw.value, (size_t)written) ||
        !nonempty_mask(&observed->value, (size_t)written) ||
        !zero_tail(&observed->value, (size_t)written))
        return 0;
    return 1;
}

static int first_set_cpu(const cpu_set_t *mask)
{
    const unsigned char *bytes = (const unsigned char *)mask;
    size_t byte_index;
    unsigned int bit_index;

    for (byte_index = 0; byte_index != sizeof(*mask); ++byte_index) {
        unsigned char byte = bytes[byte_index];

        for (bit_index = 0; bit_index != 8; ++bit_index) {
            if (byte & (1u << bit_index))
                return (int)(byte_index * 8 + bit_index);
        }
    }
    return -1;
}

static void singleton_mask(cpu_set_t *mask, int cpu)
{
    unsigned char *bytes = (unsigned char *)mask;

    fill_bytes(mask, sizeof(*mask), 0);
    bytes[(unsigned int)cpu / 8] =
        (unsigned char)(1u << ((unsigned int)cpu % 8));
}

static int is_singleton_mask(const cpu_set_t *mask, int cpu)
{
    const unsigned char *bytes = (const unsigned char *)mask;
    size_t index;
    size_t expected_index = (unsigned int)cpu / 8;
    unsigned char expected = (unsigned char)(1u << ((unsigned int)cpu % 8));

    for (index = 0; index != sizeof(*mask); ++index) {
        if (bytes[index] != (index == expected_index ? expected : 0))
            return 0;
    }
    return 1;
}

static int wait_until_set(volatile int *value)
{
    unsigned long spins;

    for (spins = 0; spins != 100000000UL; ++spins) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) != 0)
            return 0;
        __asm__ volatile("pause" ::: "memory");
    }
    return 1;
}

static void *holding_worker(void *opaque)
{
    struct worker_state *state = opaque;

    state->initial_errno = errno;
    state->task = (int)raw_syscall0(sys_gettid);
    if (state->task <= 0 ||
        !check_getaffinity(pthread_self(), state->task, &state->self_mask))
        state->result = 1;
    __atomic_store_n(&state->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&state->release, __ATOMIC_ACQUIRE))
        __asm__ volatile("pause" ::: "memory");
    return opaque;
}

static int run_pthread_affinity(void)
{
    pthread_t main_thread = pthread_self();
    pthread_t worker_thread = 0;
    struct guarded_mask main_mask;
    struct guarded_mask worker_mask;
    struct guarded_mask narrowed_mask;
    cpu_set_t singleton;
    cpu_set_t empty;
    cpu_set_t short_output;
    cpu_set_t short_before;
    struct worker_state worker = {0};
    void *worker_result = 0;
    int cpu;

    errno = parent_errno_sentinel;
    if (main_thread == 0 || !check_getaffinity(main_thread, 0, &main_mask) ||
        pthread_setaffinity_np(main_thread, sizeof(main_mask.value),
            &main_mask.value) != 0 || errno != parent_errno_sentinel)
        return 10;

    fill_bytes(&short_output, sizeof(short_output), 0xa5);
    short_before = short_output;
    errno = parent_errno_sentinel;
    if (pthread_getaffinity_np(main_thread, 1, &short_output) != EINVAL ||
        !same_bytes(&short_output, &short_before, sizeof(short_output)) ||
        errno != parent_errno_sentinel)
        return 11;

    fill_bytes(&empty, sizeof(empty), 0);
    errno = parent_errno_sentinel;
    if (pthread_setaffinity_np(main_thread, sizeof(empty), &empty) != EINVAL ||
        errno != parent_errno_sentinel)
        return 12;

    errno = parent_errno_sentinel;
    if (pthread_create(&worker_thread, 0, holding_worker, &worker) != 0 ||
        wait_until_set(&worker.ready))
        return 20;
    if (worker.result != 0 || worker.task <= 0 || worker.initial_errno != 0 ||
        !check_getaffinity(worker_thread, worker.task, &worker_mask))
        return 21;

    cpu = first_set_cpu(&worker_mask.value);
    if (cpu < 0)
        return 22;
    singleton_mask(&singleton, cpu);
    errno = parent_errno_sentinel;
    if (pthread_setaffinity_np(worker_thread, sizeof(singleton), &singleton) != 0 ||
        errno != parent_errno_sentinel ||
        !check_getaffinity(worker_thread, worker.task, &narrowed_mask) ||
        !is_singleton_mask(&narrowed_mask.value, cpu))
        return 23;

    __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
    if (pthread_join(worker_thread, &worker_result) != 0 ||
        worker_result != &worker || errno != parent_errno_sentinel)
        return 24;

#if defined(CRABC_PTHREAD_AFFINITY_FREESTANDING)
    struct guarded_mask before_stale = narrowed_mask;

    fill_bytes(&narrowed_mask, sizeof(narrowed_mask), 0xa5);
    before_stale = narrowed_mask;
    errno = parent_errno_sentinel;
    if (pthread_getaffinity_np(worker_thread, sizeof(narrowed_mask.value),
            &narrowed_mask.value) != ESRCH ||
        !same_bytes(&narrowed_mask, &before_stale, sizeof(narrowed_mask)) ||
        errno != parent_errno_sentinel)
        return 30;
#endif
    return 0;
}

#if defined(CRABC_PTHREAD_AFFINITY_FREESTANDING)
int crabc_x86_64_pthread_affinity_probe(void)
{
    return run_pthread_affinity();
}
#else
int main(void)
{
    return run_pthread_affinity();
}
#endif
