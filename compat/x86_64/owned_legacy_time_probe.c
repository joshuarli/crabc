/* Musl and owned-product legacy time/clock-adjustment differential body. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(clock_t) == 8,
    "x86 LP64 clock storage");
_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8,
    "x86 timeval storage");
_Static_assert(sizeof(struct itimerval) == 32 &&
    _Alignof(struct itimerval) == 8, "x86 itimerval storage");
_Static_assert(sizeof(struct tms) == 32 && _Alignof(struct tms) == 8,
    "x86 tms storage");
_Static_assert(sizeof(struct timex) == 208 && _Alignof(struct timex) == 8,
    "x86 timex storage");
_Static_assert(offsetof(struct timex, modes) == 0 &&
    offsetof(struct timex, offset) == 8 && offsetof(struct timex, time) == 72,
    "x86 timex offsets");
_Static_assert(SYS_times == 100 && SYS_getitimer == 36 && SYS_setitimer == 38,
    "x86 timer/accounting syscall numbers");
_Static_assert(SYS_adjtimex == 159 && SYS_clock_adjtime == 305 &&
    SYS_settimeofday == 164 && SYS_clock_settime == 227 && SYS_prctl == 157 &&
    SYS_seccomp == 317, "x86 clock-adjustment/seccomp numbers");

typedef clock_t (*times_signature)(struct tms *);
typedef int (*getitimer_signature)(int, struct itimerval *);
typedef int (*setitimer_signature)(int, const struct itimerval *,
    struct itimerval *);
typedef unsigned int (*ualarm_signature)(unsigned int, unsigned int);
typedef int (*adjtime_signature)(const struct timeval *, struct timeval *);
typedef int (*adjtimex_signature)(struct timex *);
typedef int (*settimeofday_signature)(const struct timeval *,
    const struct timezone *);
typedef int (*stime_signature)(const time_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&times),
    times_signature), "times declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getitimer),
    getitimer_signature), "getitimer declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setitimer),
    setitimer_signature), "setitimer declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ualarm),
    ualarm_signature), "ualarm declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&adjtime),
    adjtime_signature), "adjtime declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&adjtimex),
    adjtimex_signature), "adjtimex declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&settimeofday),
    settimeofday_signature), "settimeofday declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&stime),
    stime_signature), "stime declaration");

enum {
    TIMER_GUARD = 16,
    TIMER_GUARD_BYTE = 0xa5,
    CRABC_BPF_LD = 0x00,
    CRABC_BPF_W = 0x00,
    CRABC_BPF_ABS = 0x20,
    CRABC_BPF_JMP = 0x05,
    CRABC_BPF_JEQ = 0x10,
    CRABC_BPF_K = 0x00,
    CRABC_BPF_RET = 0x06,
    CRABC_SECCOMP_SET_MODE_FILTER = 1,
    CRABC_SECCOMP_RET_ALLOW = 0x7fff0000U,
    CRABC_SECCOMP_RET_ERRNO = 0x00050000U,
};

struct guarded_itimerval {
    struct itimerval value;
    unsigned char trailing[TIMER_GUARD];
};

struct crabc_bpf_instruction {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t value;
};

struct crabc_bpf_program {
    uint16_t length;
    struct crabc_bpf_instruction *instructions;
};

#define CRABC_BPF_STATEMENT(code, value) \
    { (code), 0, 0, (value) }
#define CRABC_BPF_JUMP(code, value, jump_true, jump_false) \
    { (code), (jump_true), (jump_false), (value) }

static volatile sig_atomic_t delivered;

static void fail(void)
{
    _Exit(127);
}

#define CHECK(expression) do { if (!(expression)) fail(); } while (0)

static int text_equal(const char *left, const char *right)
{
    while (*left || *right) {
        if (*left != *right)
            return 0;
        left++;
        right++;
    }
    return 1;
}

static void fill_guard(unsigned char *bytes)
{
    for (size_t index = 0; index != TIMER_GUARD; ++index)
        bytes[index] = TIMER_GUARD_BYTE;
}

static int guard_is_intact(const unsigned char *bytes)
{
    for (size_t index = 0; index != TIMER_GUARD; ++index)
        if (bytes[index] != TIMER_GUARD_BYTE)
            return 0;
    return 1;
}

static int itimerval_is_disarmed(const struct itimerval *value)
{
    return value->it_interval.tv_sec == 0 && value->it_interval.tv_usec == 0 &&
        value->it_value.tv_sec == 0 && value->it_value.tv_usec == 0;
}

static int timeval_is_canonical(const struct timeval *value)
{
    return value->tv_usec >= 0 && value->tv_usec < 1000000;
}

static void disarm_timer(int which)
{
    const struct itimerval zero = { { 0, 0 }, { 0, 0 } };

    CHECK(setitimer(which, &zero, NULL) == 0);
}

static void run_times(void)
{
    struct tms first = { 0 };
    struct tms second = { 0 };
    clock_t first_elapsed;

    errno = 79;
    first_elapsed = times(&first);
    CHECK(errno == 79);
    CHECK(first.tms_utime >= 0 && first.tms_stime >= 0 &&
        first.tms_cutime >= 0 && first.tms_cstime >= 0);
    /* A negative elapsed value can be a valid wrapped clock_t. The source
     * contract is raw, so this test deliberately does not classify it as an
     * errno result. */
    (void)first_elapsed;
    errno = 61;
    (void)times(NULL);
    CHECK(errno == 61);
    errno = 53;
    (void)times(&second);
    CHECK(errno == 53);
    CHECK(second.tms_utime >= first.tms_utime &&
        second.tms_stime >= first.tms_stime &&
        second.tms_cutime >= first.tms_cutime &&
        second.tms_cstime >= first.tms_cstime);
}

static void run_timer_query(void)
{
    const int selectors[] = { ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF };

    for (size_t index = 0; index != sizeof(selectors) / sizeof(selectors[0]);
            ++index) {
        struct guarded_itimerval observed = { { { 0, 0 }, { 0, 0 } }, { 0 } };

        fill_guard(observed.trailing);
        disarm_timer(selectors[index]);
        errno = 79;
        CHECK(getitimer(selectors[index], &observed.value) == 0);
        CHECK(errno == 79);
        CHECK(itimerval_is_disarmed(&observed.value));
        CHECK(guard_is_intact(observed.trailing));
    }
}

static void timer_signal_handler(int signal_number)
{
    if (signal_number == SIGALRM)
        delivered++;
}

static void run_timer_delivery(void)
{
    struct sigaction action = { 0 };
    struct sigaction old_action = { 0 };
    sigset_t block;
    sigset_t previous;
    struct itimerval request = { { 0, 0 }, { 0, 50000 } };
    struct itimerval observed = { 0 };

    action.sa_handler = timer_signal_handler;
    CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGALRM, &action, &old_action) == 0);
    CHECK(sigemptyset(&block) == 0);
    CHECK(sigaddset(&block, SIGALRM) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &block, &previous) == 0);
    delivered = 0;
    CHECK(setitimer(ITIMER_REAL, &request, NULL) == 0);
    errno = 0;
    CHECK(sigsuspend(&previous) == -1 && errno == EINTR);
    CHECK(delivered == 1);
    CHECK(sigprocmask(SIG_SETMASK, &previous, NULL) == 0);
    CHECK(getitimer(ITIMER_REAL, &observed) == 0);
    CHECK(itimerval_is_disarmed(&observed));
    disarm_timer(ITIMER_REAL);
    CHECK(sigaction(SIGALRM, &old_action, NULL) == 0);
}

static void run_ualarm_cancel(void)
{
    const struct itimerval request = { { 0, 0 }, { 1, 0 } };
    struct itimerval observed = { 0 };
    unsigned int previous;

    CHECK(setitimer(ITIMER_REAL, &request, NULL) == 0);
    errno = 79;
    previous = ualarm(0, 0);
    CHECK(errno == 79);
    CHECK(previous > 0 && previous <= 1000000U);
    CHECK(getitimer(ITIMER_REAL, &observed) == 0);
    CHECK(itimerval_is_disarmed(&observed));
}

static void run_timer_errors(void)
{
    const struct itimerval request = { { 0, 0 }, { 1, 0 } };
    const struct itimerval invalid = { { 0, 0 }, { 0, 1000000 } };
    struct itimerval observed = { 0 };
    struct guarded_itimerval invalid_output = { { { 0, 0 }, { 0, 0 } }, { 0 } };

    CHECK(setitimer(ITIMER_REAL, &request, NULL) == 0);
    errno = 0;
    CHECK(setitimer(ITIMER_REAL, &invalid, NULL) == -1 && errno == EINVAL);
    CHECK(getitimer(ITIMER_REAL, &observed) == 0);
    CHECK(!itimerval_is_disarmed(&observed));

    fill_guard(invalid_output.trailing);
    errno = 0;
    CHECK(getitimer(-1, &invalid_output.value) == -1 && errno == EINVAL);
    CHECK(guard_is_intact(invalid_output.trailing));

    errno = 0;
    (void)ualarm(1000000U, 0);
    CHECK(errno == EINVAL);
    CHECK(getitimer(ITIMER_REAL, &observed) == 0);
    CHECK(!itimerval_is_disarmed(&observed));
    disarm_timer(ITIMER_REAL);
}

static void run_adjustment_query(void)
{
    struct timex state = { 0 };
    struct timeval remaining = { 0 };
    int status;

    errno = 79;
    status = adjtimex(&state);
    CHECK(status >= TIME_OK && status <= TIME_ERROR);
    CHECK(errno == 79);
    CHECK(timeval_is_canonical(&state.time));

    errno = 71;
    CHECK(adjtime(NULL, &remaining) == 0);
    CHECK(errno == 71);
    CHECK(timeval_is_canonical(&remaining));
}

static void run_adjustment_guards(void)
{
    const struct timeval seconds_too_large = { 1001, 0 };
    const struct timeval microseconds_too_large = { 0, 1000000001 };
    struct timeval remaining = { 17, 23 };

    errno = 0;
    CHECK(adjtime(&seconds_too_large, &remaining) == -1 && errno == EINVAL);
    CHECK(remaining.tv_sec == 17 && remaining.tv_usec == 23);
    errno = 0;
    CHECK(adjtime(&microseconds_too_large, &remaining) == -1 && errno == EINVAL);
    CHECK(remaining.tv_sec == 17 && remaining.tv_usec == 23);
}

static void run_settimeofday_null(void)
{
    const struct timezone ignored = { 17, 23 };

    errno = 71;
    CHECK(settimeofday(NULL, &ignored) == 0);
    CHECK(errno == 71);
}

static void run_settimeofday_guards(void)
{
    const struct timeval negative_microseconds = { 0, -1 };
    const struct timeval too_many_microseconds = { 0, 1000000 };

    errno = 0;
    CHECK(settimeofday(&negative_microseconds, NULL) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(settimeofday(&too_many_microseconds, NULL) == -1 && errno == EINVAL);
}

static long raw_syscall3(long number, long first, long second, long third)
{
    unsigned long result;

    __asm__ volatile ("syscall" : "=a"(result) : "a"(number), "D"(first),
        "S"(second), "d"(third) : "rcx", "r11", "memory");
    return (long)result;
}

static long raw_syscall5(long number, long first, long second, long third,
    long fourth, long fifth)
{
    unsigned long result;
    register long argument_four __asm__("r10") = fourth;
    register long argument_five __asm__("r8") = fifth;

    __asm__ volatile ("syscall" : "=a"(result) : "a"(number), "D"(first),
        "S"(second), "d"(third), "r"(argument_four), "r"(argument_five) :
        "rcx", "r11", "memory");
    return (long)result;
}

static void install_adjustment_denial(void)
{
    struct crabc_bpf_instruction instructions[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_adjtimex, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | EPERM),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_clock_adjtime, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | EPERM),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_settimeofday, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | EPERM),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_clock_settime, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | EPERM),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
    };
    struct crabc_bpf_program program = {
        sizeof(instructions) / sizeof(instructions[0]),
        instructions,
    };

    CHECK(raw_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(raw_syscall3(SYS_seccomp, CRABC_SECCOMP_SET_MODE_FILTER, 0,
        (long)(uintptr_t)&program) == 0);
}

static void run_adjustment_seccomp(void)
{
    const struct timeval adjustment = { 0, 1 };
    const struct timeval wall_clock = { 0, 1 };
    struct timeval remaining = { 17, 23 };
    struct timex state = { 0 };
    time_t seconds = 0;

    install_adjustment_denial();
    errno = 0;
    CHECK(adjtimex(&state) == -1 && errno == EPERM);
    errno = 0;
    CHECK(adjtime(&adjustment, &remaining) == -1 && errno == EPERM);
    CHECK(remaining.tv_sec == 17 && remaining.tv_usec == 23);
    errno = 0;
    CHECK(settimeofday(&wall_clock, NULL) == -1 && errno == EPERM);
    errno = 0;
    CHECK(stime(&seconds) == -1 && errno == EPERM);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (text_equal(argv[1], "times"))
        run_times();
    else if (text_equal(argv[1], "timer-query"))
        run_timer_query();
    else if (text_equal(argv[1], "timer-delivery"))
        run_timer_delivery();
    else if (text_equal(argv[1], "ualarm-cancel"))
        run_ualarm_cancel();
    else if (text_equal(argv[1], "timer-errors"))
        run_timer_errors();
    else if (text_equal(argv[1], "adjustment-query"))
        run_adjustment_query();
    else if (text_equal(argv[1], "adjustment-guards"))
        run_adjustment_guards();
    else if (text_equal(argv[1], "settimeofday-null"))
        run_settimeofday_null();
    else if (text_equal(argv[1], "settimeofday-guards"))
        run_settimeofday_guards();
    else if (text_equal(argv[1], "adjustment-seccomp"))
        run_adjustment_seccomp();
    else
        fail();
    return 0;
}
