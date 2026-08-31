/* Static crabc-libc x86-64 bounded pthread CPU-clock fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * through a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It proves only pthread_getcpuclockid for the
 * bootstrapped calling process-main pthread_self() handle: the returned Linux
 * per-thread CPU clock ID has musl's exact x86 encoding and is accepted by
 * clock_gettime. The candidate-only null-handle check is deliberately outside
 * musl's dereferenceable-TCB contract and must fail closed without modifying
 * either the output slot or errno. This does not select worker or foreign
 * handles, a pthread TCB/thread list, scheduler attributes, C clock APIs,
 * cancellation, synchronization, TSS, CRT, loader, sysroot, general
 * pthread/TLS behavior, or public x86 support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(clockid_t) == 4,
    "musl x86-64 clockid_t ABI");
_Static_assert(SYS_gettid == 186,
    "x86 pthread CPU-clock fixture uses gettid=186");
_Static_assert(CLOCK_THREAD_CPUTIME_ID == 3,
    "Linux thread CPU-clock base ID");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_getcpuclockid),
    int (*)(pthread_t, clockid_t *)), "pthread_getcpuclockid declaration");

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

/* Linux's per-thread CPU clock is (~tid << 3) | 6. This is the same unsigned
 * 32-bit machine calculation emitted by musl's pthread_getcpuclockid object. */
static clockid_t expected_thread_cpu_clock(long thread_id)
{
    return (clockid_t)(((~(uint32_t)thread_id) << 3) | 6U);
}

static int normalized_timespec(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
        value->tv_nsec < 1000000000L;
}

static int check_self_cpu_clock(void)
{
    const int preserved_errno = E2BIG;
    pthread_t self = pthread_self();
    clockid_t clock_id = (clockid_t)0x5a5a5a5a;
    struct timespec encoded_time = { .tv_sec = -1, .tv_nsec = -1 };
    struct timespec direct_time = { .tv_sec = -1, .tv_nsec = -1 };
    long thread_id;

    if (self == (pthread_t)0)
        return 1;
    errno = preserved_errno;
    if (pthread_getcpuclockid(self, &clock_id) != 0)
        return 2;
    if (errno != preserved_errno)
        return 3;

    thread_id = raw_syscall0(SYS_gettid);
    if (thread_id <= 0 || thread_id > 0x7fffffffL)
        return 4;
    if (clock_id != expected_thread_cpu_clock(thread_id))
        return 5;

    if (clock_gettime(clock_id, &encoded_time) != 0)
        return 6;
    if (!normalized_timespec(&encoded_time))
        return 7;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &direct_time) != 0)
        return 8;
    if (!normalized_timespec(&direct_time))
        return 9;
    if (errno != preserved_errno)
        return 10;
    return 0;
}

#if defined(CRABC_PTHREAD_CPUCLOCK_FREESTANDING)
static int check_candidate_null_handle_rejection(void)
{
    const int preserved_errno = ERANGE;
    const clockid_t sentinel = (clockid_t)0x4a4a4a4a;
    clockid_t clock_id = sentinel;

    errno = preserved_errno;
    if (pthread_getcpuclockid((pthread_t)0, &clock_id) != ESRCH)
        return 1;
    if (clock_id != sentinel)
        return 2;
    if (errno != preserved_errno)
        return 3;
    return 0;
}
#endif

int crabc_x86_64_pthread_cpuclock_probe(void)
{
    int status = check_self_cpu_clock();

    if (status != 0)
        return 10 + status;
#if defined(CRABC_PTHREAD_CPUCLOCK_FREESTANDING)
    status = check_candidate_null_handle_rejection();
    if (status != 0)
        return 30 + status;
#endif
    return 0;
}

#ifndef CRABC_PTHREAD_CPUCLOCK_FREESTANDING
int main(void)
{
    return crabc_x86_64_pthread_cpuclock_probe();
}
#endif
