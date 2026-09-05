/* Installed Linux/x86-64 pthread CPU-clock consumer.
 *
 * The same project-header body runs through pinned musl and the installed
 * crabc static and dynamic products.  A worker stays alive until its parent
 * has queried its opaque pthread_t, so the observation is not a completion,
 * join, detach, reaping, or reusable-TID race.  Both worker-self and
 * parent-to-live-worker queries must preserve caller errno, reproduce musl's
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

struct worker_state {
    volatile int ready;
    volatile int release;
    int task_id;
    int status;
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

    state->task_id = (int)raw_syscall0(SYS_gettid);
    state->status = check_cpu_clock(pthread_self(), state->task_id, E2BIG);
    __atomic_store_n(&state->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&state->release, __ATOMIC_ACQUIRE))
        __asm__ volatile("pause" ::: "memory");
    return state;
}

static int run_live_worker_cpu_clock(void)
{
    struct worker_state worker = { 0 };
    pthread_t thread = 0;
    void *result = 0;
    int status;

    errno = ERANGE;
    if (pthread_create(&thread, NULL, holding_worker, &worker) != 0 ||
        errno != ERANGE)
        return 10;
    if (wait_until_set(&worker.ready))
        return 11;
    if (worker.status != 0) {
        __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
        (void)pthread_join(thread, &result);
        return 20 + worker.status;
    }
    status = check_cpu_clock(thread, worker.task_id, ERANGE);
    __atomic_store_n(&worker.release, 1, __ATOMIC_RELEASE);
    if (pthread_join(thread, &result) != 0 || result != &worker ||
        errno != ERANGE)
        return 40;
    return status == 0 ? 0 : 50 + status;
}

int main(void)
{
    long main_task_id = raw_syscall0(SYS_gettid);
    int status = check_cpu_clock(pthread_self(), main_task_id, E2BIG);

    if (status != 0)
        return status;
    status = run_live_worker_cpu_clock();
    if (status != 0)
        return 64 + status;
    puts("pthread_getcpuclockid live worker: ok");
    return 0;
}
