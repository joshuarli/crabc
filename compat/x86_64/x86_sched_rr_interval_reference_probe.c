/* Pinned-musl Linux/x86-64 sched_rr_get_interval(2) reference. */

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
#include <stddef.h>
#include <sched.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

struct guarded_timespec {
    struct timespec value;
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
    struct guarded_timespec zero_selector;
    struct guarded_timespec explicit_selector;
};

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer size");
_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t size");
_Static_assert(sizeof(pid_t) == 4, "x86 pid_t size");
_Static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
_Static_assert(_Alignof(struct timespec) == 8, "x86 timespec alignment");
_Static_assert(offsetof(struct timespec, tv_sec) == 0,
               "x86 timespec seconds offset");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8,
               "x86 timespec nanoseconds offset");
_Static_assert(SYS_sched_rr_get_interval == 148,
               "x86 sched_rr_get_interval syscall number");
_Static_assert(SYS_gettid == 186, "x86 gettid syscall number");

static int canonical_timespec(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
           value->tv_nsec < 1000000000L;
}

static int trailing_is_unchanged(const struct guarded_timespec *value)
{
    for (size_t index = 0; index < sizeof(value->trailing); ++index) {
        if (value->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static void *record_worker_interval(void *opaque)
{
    struct worker_state *state = opaque;

    state->task = (pid_t)syscall(SYS_gettid);
    if (state->task <= 0)
        state->result = 30;

    if (state->result == 0) {
        memset(&state->zero_selector, 0xa5, sizeof(state->zero_selector));
        errno = 0;
        if (sched_rr_get_interval(0, &state->zero_selector.value) != 0 ||
            !canonical_timespec(&state->zero_selector.value) ||
            !trailing_is_unchanged(&state->zero_selector))
            state->result = 31;
    }

    if (state->result == 0) {
        memset(&state->explicit_selector, 0xa5,
               sizeof(state->explicit_selector));
        errno = 0;
        if (sched_rr_get_interval(state->task,
                                  &state->explicit_selector.value) != 0 ||
            !canonical_timespec(&state->explicit_selector.value) ||
            !trailing_is_unchanged(&state->explicit_selector) ||
            memcmp(&state->zero_selector.value,
                   &state->explicit_selector.value,
                   sizeof(state->zero_selector.value)) != 0)
            state->result = 32;
    }

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
    struct guarded_timespec musl_value;
    struct guarded_timespec direct_value;
    struct guarded_timespec musl_self;
    struct guarded_timespec direct_self;
    struct guarded_timespec musl_worker;
    struct guarded_timespec direct_worker;
    struct guarded_timespec musl_missing;
    struct guarded_timespec direct_missing;
    int status = 0;

    calling_task = (pid_t)syscall(SYS_gettid);
    if (calling_task <= 0)
        return 1;

    memset(&musl_value, 0xa5, sizeof(musl_value));
    errno = 0;
    if (sched_rr_get_interval(0, &musl_value.value) != 0 ||
        !canonical_timespec(&musl_value.value) ||
        !trailing_is_unchanged(&musl_value))
        return 10;

    memset(&direct_value, 0xa5, sizeof(direct_value));
    errno = 0;
    if (syscall(SYS_sched_rr_get_interval, 0, &direct_value.value) != 0 ||
        !canonical_timespec(&direct_value.value) ||
        !trailing_is_unchanged(&direct_value) ||
        memcmp(&musl_value.value, &direct_value.value,
               sizeof(musl_value.value)) != 0)
        return 11;

    memset(&musl_self, 0xa5, sizeof(musl_self));
    errno = 0;
    if (sched_rr_get_interval(calling_task, &musl_self.value) != 0 ||
        !canonical_timespec(&musl_self.value) ||
        !trailing_is_unchanged(&musl_self) ||
        memcmp(&musl_value.value, &musl_self.value,
               sizeof(musl_value.value)) != 0)
        return 12;

    memset(&direct_self, 0xa5, sizeof(direct_self));
    errno = 0;
    if (syscall(SYS_sched_rr_get_interval, calling_task, &direct_self.value) != 0 ||
        !canonical_timespec(&direct_self.value) ||
        !trailing_is_unchanged(&direct_self) ||
        memcmp(&musl_self.value, &direct_self.value,
               sizeof(musl_self.value)) != 0)
        return 13;

    if (pthread_create(&worker_thread, 0, record_worker_interval, &worker) != 0)
        return 14;
    while (!atomic_load_explicit(&worker.ready, memory_order_acquire))
        sched_yield();

    if (worker.result != 0 || worker.task == calling_task)
        status = worker.result != 0 ? worker.result : 15;

    if (status == 0) {
        memset(&musl_worker, 0xa5, sizeof(musl_worker));
        errno = 0;
        if (sched_rr_get_interval(worker.task, &musl_worker.value) != 0 ||
            !canonical_timespec(&musl_worker.value) ||
            !trailing_is_unchanged(&musl_worker))
            status = 16;
    }

    if (status == 0) {
        memset(&direct_worker, 0xa5, sizeof(direct_worker));
        errno = 0;
        if (syscall(SYS_sched_rr_get_interval, worker.task,
                    &direct_worker.value) != 0 ||
            !canonical_timespec(&direct_worker.value) ||
            !trailing_is_unchanged(&direct_worker) ||
            memcmp(&musl_worker.value, &direct_worker.value,
                   sizeof(musl_worker.value)) != 0)
            status = 17;
    }

    atomic_store_explicit(&worker.release, 1, memory_order_release);
    if (pthread_join(worker_thread, &worker_return) != 0 || worker_return != 0)
        return 18;
    if (status != 0)
        return status;

    memset(&musl_missing, 0xa5, sizeof(musl_missing));
    errno = 0;
    if (sched_rr_get_interval((pid_t)INT_MAX, &musl_missing.value) != -1 ||
        errno != ESRCH || !trailing_is_unchanged(&musl_missing))
        return 20;

    memset(&direct_missing, 0xa5, sizeof(direct_missing));
    errno = 0;
    if (syscall(SYS_sched_rr_get_interval, (pid_t)INT_MAX,
                &direct_missing.value) != -1 || errno != ESRCH ||
        !trailing_is_unchanged(&direct_missing))
        return 21;

    puts("layout=timespec16/8 offsets=0,8 syscall=148 current=canonical direct=match task=live missing=ESRCH");
    return 0;
}
