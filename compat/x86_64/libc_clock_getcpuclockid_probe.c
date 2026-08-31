/*
 * Pinned-musl Linux/x86-64 clock_getcpuclockid differential and static body.
 *
 * The same public-header C body first executes through pinned musl 1.2.6,
 * then through exactly the selected `-nostdlib -static` candidate. It proves
 * only musl's process CPU-clock-ID encoding and its direct positive-status
 * error convention; raw syscalls below are fixture containment, not selected
 * C getpid or clock_getres ABI calls.
 */

#define _POSIX_C_SOURCE 200809L

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <limits.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>

_Static_assert(sizeof(pid_t) == 4, "x86 pid_t width");
_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec layout");
_Static_assert(CLOCK_PROCESS_CPUTIME_ID == 2, "Linux process CPU-clock ID");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_getcpuclockid),
    int (*)(pid_t, clockid_t *)), "clock_getcpuclockid declaration");
_Static_assert(SYS_getpid == 39, "x86 getpid syscall number");
_Static_assert(SYS_clock_getres == 229, "x86 clock_getres syscall number");

enum {
    LINUX_EINVAL = 22,
    LINUX_ESRCH = 3,
};

typedef int (*clock_getcpuclockid_function)(pid_t, clockid_t *);

/* Parentheses retain the selected public C ABI boundary rather than a builtin. */
static clock_getcpuclockid_function volatile direct_clock_getcpuclockid =
    (clock_getcpuclockid);

static long raw_syscall0(long number)
{
    long result = number;

    __asm__ volatile("syscall" : "+a"(result) : : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long first, long second)
{
    long result = number;

    __asm__ volatile("syscall" : "+a"(result) : "D"(first), "S"(second)
        : "rcx", "r11", "memory");
    return result;
}

/* This keeps the Linux word encoding defined for the rejected test PID. */
static clockid_t encoded_process_cpu_clock(pid_t pid)
{
    return (clockid_t)(((uint32_t)(-(int64_t)pid - 1) << 3) |
        (uint32_t)CLOCK_PROCESS_CPUTIME_ID);
}

static int normalized(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
        value->tv_nsec < 1000000000L;
}

static int check_current_and_self(void)
{
    const pid_t self = (pid_t)raw_syscall0(SYS_getpid);
    clockid_t current_clock = 0;
    clockid_t self_clock = 0;
    clockid_t wrapped_clock = 0;
    struct timespec resolution = { 0, 0 };

    if (self <= 0 || self > 268435455)
        return 1;
    if (direct_clock_getcpuclockid(0, &current_clock) != 0 || current_clock != -6)
        return 2;
    if (direct_clock_getcpuclockid(self, &self_clock) != 0 ||
        self_clock != encoded_process_cpu_clock(self))
        return 3;
    if (raw_syscall2(SYS_clock_getres, self_clock,
            (long)(uintptr_t)&resolution) != 0 || !normalized(&resolution))
        return 4;
    /* INT_MAX is source-defined: musl's unsigned multiplication wraps to 2. */
    if (direct_clock_getcpuclockid(INT_MAX, &wrapped_clock) != 0 ||
        wrapped_clock != CLOCK_PROCESS_CPUTIME_ID)
        return 5;
    return 0;
}

static int check_missing_process_status(void)
{
    const pid_t missing = INT_MAX - 1;
    clockid_t output = 0x5a5a5a5a;
    struct timespec resolution = { 0, 0 };

    if (direct_clock_getcpuclockid(missing, &output) != LINUX_ESRCH)
        return 1;
    if (output != 0x5a5a5a5a)
        return 2;
    if (raw_syscall2(SYS_clock_getres, encoded_process_cpu_clock(missing),
            (long)(uintptr_t)&resolution) != -LINUX_EINVAL)
        return 3;
    return 0;
}

int crabc_x86_64_clock_getcpuclockid_probe(void)
{
    int result = check_current_and_self();

    if (result != 0)
        return result;
    result = check_missing_process_status();
    return result == 0 ? 0 : 16 + result;
}

#ifndef CRABC_CLOCK_GETCPUCLOCKID_FREESTANDING
int main(void)
{
    return crabc_x86_64_clock_getcpuclockid_probe();
}
#endif
