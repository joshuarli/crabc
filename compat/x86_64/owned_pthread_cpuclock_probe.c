/* Installed Linux/x86-64 pthread CPU-clock consumer.
 *
 * The same project-header body runs through pinned musl and the installed
 * crabc static and dynamic products.  Two workers stay alive while main and
 * their peer query their opaque pthread_t values.  Every target is executing
 * during observation, excluding completion, join, detach, reaping, and
 * reusable-TID races.  All directions preserve caller errno, reproduce musl's
 * 32-bit Linux clock encoding, and yield a clock accepted by clock_gettime.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this consumer requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(clockid_t) == 4,
    "musl x86-64 clockid_t ABI");
_Static_assert(SYS_gettid == 186,
    "x86 pthread CPU-clock consumer uses gettid=186");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_getcpuclockid),
    int (*)(pthread_t, clockid_t *)), "pthread_getcpuclockid declaration");

enum { WORKER_COUNT = 2 };

struct worker_group;

struct worker_state {
    struct worker_group *group;
    int index;
    volatile int ready;
    volatile int cross_done;
    int task_id;
    int main_status;
    int self_status;
    int peer_status;
};

struct worker_group {
    volatile int start_cross;
    volatile int abort_cross;
    volatile int release;
    pthread_t main_thread;
    int main_task_id;
    pthread_t threads[WORKER_COUNT];
    struct worker_state workers[WORKER_COUNT];
};

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

/* Linux's per-thread CPU clock is (~tid << 3) | 6.  Retain the unsigned
 * 32-bit calculation emitted by musl's pthread_getcpuclockid object. */
static clockid_t expected_thread_cpu_clock(long thread_id)
{
    return (clockid_t)(((~(uint32_t)thread_id) << 3) | 6U);
}

static int normalized_timespec(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
        value->tv_nsec < 1000000000L;
}

static int check_cpu_clock(pthread_t thread, long task_id, int saved_errno)
{
    clockid_t clock_id = (clockid_t)0x5a5a5a5a;
    struct timespec value = { .tv_sec = -1, .tv_nsec = -1 };

    if (task_id <= 0 || task_id > 0x7fffffffL)
        return 1;
    errno = saved_errno;
    if (pthread_getcpuclockid(thread, &clock_id) != 0)
        return 2;
    if (errno != saved_errno)
        return 3;
    if (clock_id != expected_thread_cpu_clock(task_id))
        return 4;
    if (clock_gettime(clock_id, &value) != 0)
        return 5;
    if (!normalized_timespec(&value))
        return 6;
    if (errno != saved_errno)
        return 7;
    return 0;
}

static int wait_until_set(const volatile int *value)
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
    struct worker_group *group = state->group;
    int peer = 1 - state->index;

    state->task_id = (int)raw_syscall0(SYS_gettid);
    state->main_status = check_cpu_clock(group->main_thread,
        group->main_task_id, EILSEQ);
    state->self_status = check_cpu_clock(pthread_self(), state->task_id, E2BIG);
    __atomic_store_n(&state->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&group->start_cross, __ATOMIC_ACQUIRE))
        __asm__ volatile("pause" ::: "memory");
    if (!__atomic_load_n(&group->abort_cross, __ATOMIC_ACQUIRE))
        state->peer_status = check_cpu_clock(group->threads[peer],
            group->workers[peer].task_id, EDOM);
    __atomic_store_n(&state->cross_done, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&group->release, __ATOMIC_ACQUIRE))
        __asm__ volatile("pause" ::: "memory");
    return state;
}

/* Main and both workers remain executing until every cross-thread clock
 * lookup completes.  The barriers publish TIDs and handles before peer reads. */
static int run_live_worker_cpu_clock(struct worker_group *group)
{
    void *result = 0;
    int created = 0;
    int status = 0;
    int i;

    errno = ERANGE;
    for (i = 0; i != WORKER_COUNT; ++i) {
        group->workers[i].group = group;
        group->workers[i].index = i;
        if (pthread_create(&group->threads[i], NULL, holding_worker,
                &group->workers[i]) != 0) {
            status = 10 + i;
            goto release;
        }
        ++created;
        if (errno != ERANGE) {
            status = 12 + i;
            goto release;
        }
    }
    for (i = 0; i != WORKER_COUNT; ++i) {
        if (wait_until_set(&group->workers[i].ready)) {
            status = 20 + i;
            goto release;
        }
        if (group->workers[i].main_status != 0 ||
            group->workers[i].self_status != 0) {
            status = 30 + 10 * i + group->workers[i].main_status +
                group->workers[i].self_status;
            goto release;
        }
    }
    if (group->workers[0].task_id == group->workers[1].task_id ||
        group->workers[0].task_id == group->main_task_id ||
        group->workers[1].task_id == group->main_task_id) {
        status = 60;
        goto release;
    }
    for (i = 0; i != WORKER_COUNT; ++i) {
        status = check_cpu_clock(group->threads[i],
            group->workers[i].task_id, ERANGE);
        if (status != 0) {
            status += 70 + 10 * i;
            goto release;
        }
    }
    __atomic_store_n(&group->start_cross, 1, __ATOMIC_RELEASE);
    for (i = 0; i != WORKER_COUNT; ++i) {
        if (wait_until_set(&group->workers[i].cross_done)) {
            status = 100 + i;
            goto release;
        }
    }
    for (i = 0; i != WORKER_COUNT; ++i) {
        if (group->workers[i].peer_status != 0) {
            status = 110 + 10 * i + group->workers[i].peer_status;
            goto release;
        }
    }

release:
    if (status != 0)
        __atomic_store_n(&group->abort_cross, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&group->start_cross, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&group->release, 1, __ATOMIC_RELEASE);
    errno = ERANGE;
    for (i = 0; i != created; ++i) {
        if (pthread_join(group->threads[i], &result) != 0 ||
            result != &group->workers[i] || errno != ERANGE)
            status = 140 + i;
    }
    return status;
}

#ifdef CRABC_CANDIDATE_DIAGNOSTICS
/* Musl dereferences valid pthread records; these diagnostic handles have no
 * musl differential and exercise only the owned runtime's fail-closed route. */
static int check_candidate_invalid_handle(pthread_t thread)
{
    clockid_t clock_id = (clockid_t)0x5a5a5a5a;

    errno = EILSEQ;
    if (pthread_getcpuclockid(thread, &clock_id) != ESRCH)
        return 1;
    if (clock_id != (clockid_t)0x5a5a5a5a || errno != EILSEQ)
        return 2;
    return 0;
}
#endif

int main(void)
{
    struct worker_group group = {
        .main_thread = pthread_self(),
        .main_task_id = (int)raw_syscall0(SYS_gettid),
    };
    int status = check_cpu_clock(group.main_thread, group.main_task_id, E2BIG);

    if (status != 0)
        return status;
    status = run_live_worker_cpu_clock(&group);
    if (status != 0)
        return 64 + status;
#ifdef CRABC_CANDIDATE_DIAGNOSTICS
    status = check_candidate_invalid_handle((pthread_t)0);
    if (status != 0)
        return 220 + status;
    status = check_candidate_invalid_handle((pthread_t)(uintptr_t)1);
    if (status != 0)
        return 230 + status;
    status = check_candidate_invalid_handle(group.threads[0]);
    if (status != 0)
        return 240 + status;
#endif
    puts("pthread_getcpuclockid live thread graph: ok");
    return 0;
}
