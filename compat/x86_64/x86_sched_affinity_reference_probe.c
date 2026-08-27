/* Pinned-musl Linux/x86-64 sched_getaffinity(2) reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires little-endian x86-64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

struct guarded_mask {
    cpu_set_t value;
    unsigned char trailing[16];
};

/*
 * The oracle uses one pinned-musl worker only to retain a live non-leader
 * Linux task ID while the initial task addresses it. This is test-harness
 * machinery, not an admission of a C or pthread facade.
 */
struct worker_state {
    _Atomic int ready;
    _Atomic int release;
    int result;
    pid_t task;
    struct guarded_mask musl_zero_selector;
    struct guarded_mask direct_zero_selector;
    struct guarded_mask musl_explicit_selector;
    struct guarded_mask direct_explicit_selector;
};

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer size");
_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t size");
_Static_assert(sizeof(pid_t) == 4, "x86 pid_t size");
_Static_assert(sizeof(cpu_set_t) == 128, "x86 cpu_set_t size");
_Static_assert(_Alignof(cpu_set_t) == 8, "x86 cpu_set_t alignment");
_Static_assert(SYS_sched_getaffinity == 204,
               "x86 sched_getaffinity syscall number");
_Static_assert(SYS_gettid == 186, "x86 gettid syscall number");

static int unwritten_is_unchanged(const struct guarded_mask *mask, size_t length)
{
    const unsigned char *value = (const unsigned char *)&mask->value;

    if (length > sizeof(mask->value))
        return 0;
    for (size_t index = length; index < sizeof(mask->value); ++index) {
        if (value[index] != 0xa5)
            return 0;
    }
    for (size_t index = 0; index < sizeof(mask->trailing); ++index) {
        if (mask->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int trailing_is_unchanged(const struct guarded_mask *mask)
{
    for (size_t index = 0; index < sizeof(mask->trailing); ++index) {
        if (mask->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int mask_matches(const cpu_set_t *value, const cpu_set_t *other,
                        size_t length)
{
    return memcmp(value, other, length) == 0;
}

static int zero_suffix(const cpu_set_t *mask, size_t length)
{
    const unsigned char *value = (const unsigned char *)mask;

    if (length > sizeof(*mask))
        return 0;
    for (size_t index = length; index < sizeof(*mask); ++index) {
        if (value[index] != 0)
            return 0;
    }
    return 1;
}

static int has_set_bit(const cpu_set_t *mask, size_t length)
{
    const unsigned char *value = (const unsigned char *)mask;

    for (size_t index = 0; index < length; ++index) {
        if (value[index] != 0)
            return 1;
    }
    return 0;
}

static int read_musl_mask(pid_t task, struct guarded_mask *mask)
{
    memset(mask, 0xa5, sizeof(*mask));
    errno = 0;
    return sched_getaffinity(task, sizeof(mask->value), &mask->value) == 0 &&
        has_set_bit(&mask->value, sizeof(mask->value)) &&
        trailing_is_unchanged(mask);
}

static int read_raw_mask(pid_t task, struct guarded_mask *raw,
                         const struct guarded_mask *musl)
{
    long length;

    memset(raw, 0xa5, sizeof(*raw));
    errno = 0;
    length = syscall(SYS_sched_getaffinity, task, sizeof(raw->value),
                     &raw->value);
    return length > 0 && (size_t)length <= sizeof(raw->value) &&
        has_set_bit(&raw->value, (size_t)length) &&
        unwritten_is_unchanged(raw, (size_t)length) &&
        zero_suffix(&musl->value, (size_t)length) &&
        mask_matches(&musl->value, &raw->value, (size_t)length);
}

static void *record_worker_affinity(void *opaque)
{
    struct worker_state *state = opaque;

    state->task = (pid_t)syscall(SYS_gettid);
    if (state->task <= 0)
        state->result = 40;

    if (state->result == 0 &&
        (!read_musl_mask(0, &state->musl_zero_selector) ||
         !read_raw_mask(0, &state->direct_zero_selector,
                        &state->musl_zero_selector)))
        state->result = 41;

    if (state->result == 0 &&
        (!read_musl_mask(state->task, &state->musl_explicit_selector) ||
         !read_raw_mask(state->task, &state->direct_explicit_selector,
                        &state->musl_explicit_selector)))
        state->result = 42;

    atomic_store_explicit(&state->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
        sched_yield();
    return 0;
}

int main(void)
{
    pid_t calling_task;
    pthread_t worker_thread;
    void *worker_return = (void *)(uintptr_t)1;
    struct worker_state worker = {0};
    struct guarded_mask musl_zero_selector;
    struct guarded_mask direct_zero_selector;
    struct guarded_mask musl_explicit_selector;
    struct guarded_mask direct_explicit_selector;
    struct guarded_mask musl_worker_selector;
    struct guarded_mask direct_worker_selector;
    struct guarded_mask musl_short;
    struct guarded_mask direct_short;
    struct guarded_mask musl_missing;
    struct guarded_mask direct_missing;
    int status = 0;

    calling_task = (pid_t)syscall(SYS_gettid);
    if (calling_task <= 0)
        return 1;

    if (!read_musl_mask(0, &musl_zero_selector) ||
        !read_raw_mask(0, &direct_zero_selector, &musl_zero_selector))
        return 10;

    if (!read_musl_mask(calling_task, &musl_explicit_selector) ||
        !read_raw_mask(calling_task, &direct_explicit_selector,
                       &musl_explicit_selector))
        return 11;

    memset(&musl_short, 0xa5, sizeof(musl_short));
    errno = 0;
    if (sched_getaffinity(0, 1, &musl_short.value) != -1 ||
        errno != EINVAL || !unwritten_is_unchanged(&musl_short, 0) ||
        ((const unsigned char *)&musl_short.value)[0] != 0xa5)
        return 20;

    memset(&direct_short, 0xa5, sizeof(direct_short));
    errno = 0;
    if (syscall(SYS_sched_getaffinity, 0, 1, &direct_short.value) != -1 ||
        errno != EINVAL || !unwritten_is_unchanged(&direct_short, 0) ||
        ((const unsigned char *)&direct_short.value)[0] != 0xa5)
        return 21;

    if (pthread_create(&worker_thread, 0, record_worker_affinity, &worker) != 0)
        return 30;
    while (!atomic_load_explicit(&worker.ready, memory_order_acquire))
        sched_yield();

    if (worker.result != 0 || worker.task == calling_task)
        status = worker.result != 0 ? worker.result : 31;

    if (status == 0 &&
        (!read_musl_mask(worker.task, &musl_worker_selector) ||
         !read_raw_mask(worker.task, &direct_worker_selector,
                        &musl_worker_selector)))
        status = 32;

    atomic_store_explicit(&worker.release, 1, memory_order_release);
    if (pthread_join(worker_thread, &worker_return) != 0 || worker_return != 0)
        return 33;
    if (status != 0)
        return status;

    memset(&musl_missing, 0xa5, sizeof(musl_missing));
    errno = 0;
    if (sched_getaffinity((pid_t)INT_MAX, sizeof(musl_missing.value),
                          &musl_missing.value) != -1 ||
        errno != ESRCH || !unwritten_is_unchanged(&musl_missing, 0))
        return 50;

    memset(&direct_missing, 0xa5, sizeof(direct_missing));
    errno = 0;
    if (syscall(SYS_sched_getaffinity, (pid_t)INT_MAX,
                sizeof(direct_missing.value), &direct_missing.value) != -1 ||
        errno != ESRCH || !unwritten_is_unchanged(&direct_missing, 0))
        return 51;

    puts("layout=cpu-set128 syscall=204 current=musl-success0/raw-returned-prefix-match/musl-zero-tail task=self-and-live-worker short=EINVAL missing=ESRCH");
    return 0;
}
