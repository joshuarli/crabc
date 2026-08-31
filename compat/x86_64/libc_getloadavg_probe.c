/* Static x86-64 getloadavg C ABI and pinned-musl behavior fixture.
 *
 * One project-header fixture executes unchanged through pinned musl and the
 * selected true-static archive. It observes raw sysinfo snapshots immediately
 * before and after each call because load averages are live kernel state. The
 * result must match one complete adjacent snapshot, not an invented /proc or
 * scheduler policy. Both pinned-musl and static-candidate arms check stale
 * errno; the latter runs through the same direct initial-TLS route audited in
 * its final ELF and disassembly closure.
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
#include <stdint.h>
#include <sys/prctl.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

/* This candidate-only classic-BPF child denies the one selected sysinfo call.
 * Pinned musl subsequently reads an uninitialized local record after that
 * failure, so its source has no deterministic output oracle. The safe Rust
 * leaf instead promises -1/errno/no-output; the irreversible filter remains
 * confined to a raw-fork child and never affects the reference or later gate.
 */
#ifdef CRABC_GETLOADAVG_FREESTANDING
struct crabc_bpf_instruction {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t immediate;
};

struct crabc_bpf_program {
    uint16_t length;
    struct crabc_bpf_instruction *instructions;
};

enum {
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

#define CRABC_BPF_STATEMENT(instruction_code, value) \
    { (uint16_t)(instruction_code), 0, 0, (uint32_t)(value) }
#define CRABC_BPF_JUMP(instruction_code, value, yes, no) \
    { (uint16_t)(instruction_code), (uint8_t)(yes), (uint8_t)(no), \
      (uint32_t)(value) }
#endif

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(double) == 8, "x86 binary64 double");
_Static_assert(sizeof(struct sysinfo) == 368, "x86 sysinfo size");
_Static_assert(_Alignof(struct sysinfo) == 8, "x86 sysinfo alignment");
_Static_assert(SI_LOAD_SHIFT == 16 && SYS_sysinfo == 99,
    "x86 getloadavg sysinfo constants");
#ifdef CRABC_GETLOADAVG_FREESTANDING
_Static_assert(SYS_fork == 57 && SYS_exit == 60 && SYS_wait4 == 61 &&
    SYS_prctl == 157 && SYS_seccomp == 317,
    "x86 candidate-only getloadavg error-fixture syscall constants");
#endif

typedef int (*getloadavg_signature)(double *, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&getloadavg),
    getloadavg_signature), "getloadavg declaration");

static long raw_syscall1(long number, long argument_one)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one) : "rcx", "r11", "memory");
    return result;
}

#ifdef CRABC_GETLOADAVG_FREESTANDING
static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument_one, long argument_two,
    long argument_three)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument_one, long argument_two,
    long argument_three, long argument_four)
{
    long result;
    register long register_four __asm__("r10") = argument_four;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(register_four)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall5(long number, long argument_one, long argument_two,
    long argument_three, long argument_four, long argument_five)
{
    long result;
    register long register_four __asm__("r10") = argument_four;
    register long register_five __asm__("r8") = argument_five;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(register_four), "r"(register_five)
        : "rcx", "r11", "memory");
    return result;
}

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    for (;;)
        __asm__ volatile("pause" ::: "memory");
}
#endif

static int snapshot_loads(struct sysinfo *snapshot)
{
    return raw_syscall1(SYS_sysinfo, (long)(void *)snapshot) == 0 ? 0 : -1;
}

static double scaled_load(unsigned long value)
{
    return 1.0 / (1 << SI_LOAD_SHIFT) * value;
}

static int matches_adjacent_snapshot(const double *values, int count,
    const struct sysinfo *before, const struct sysinfo *after)
{
    int matches_before = 1;
    int matches_after = 1;
    int index;

    for (index = 0; index < count; index++) {
        if (values[index] != scaled_load(before->loads[index]))
            matches_before = 0;
        if (values[index] != scaled_load(after->loads[index]))
            matches_after = 0;
    }
    return matches_before || matches_after;
}

static int check_nonpositive_counts(void)
{
    errno = E2BIG;
    if (getloadavg((double *)0, 0) != 0)
        return 1;
    if (errno != E2BIG)
        return 2;
    errno = ERANGE;
    if (getloadavg((double *)0, -7) != -1)
        return 3;
    if (errno != ERANGE)
        return 4;
    return 0;
}

static int check_three_loads_and_clamp(void)
{
    const double unchanged = -1234.5;
    struct sysinfo before;
    struct sysinfo after;
    double values[4] = { unchanged, unchanged, unchanged, unchanged };

    errno = E2BIG;
    if (snapshot_loads(&before) != 0)
        return 1;
    if (getloadavg(values, 4) != 3)
        return 2;
    if (snapshot_loads(&after) != 0)
        return 3;
    if (!matches_adjacent_snapshot(values, 3, &before, &after))
        return 4;
    if (values[3] != unchanged)
        return 5;
    if (errno != E2BIG)
        return 6;
    return 0;
}

static int check_function_pointer_one_load(void)
{
    const double unchanged = -4321.5;
    const getloadavg_signature function = getloadavg;
    struct sysinfo before;
    struct sysinfo after;
    double values[4] = { unchanged, unchanged, unchanged, unchanged };

    errno = ERANGE;
    if (snapshot_loads(&before) != 0)
        return 1;
    if (function(values, 1) != 1)
        return 2;
    if (snapshot_loads(&after) != 0)
        return 3;
    if (!matches_adjacent_snapshot(values, 1, &before, &after))
        return 4;
    if (values[1] != unchanged || values[2] != unchanged ||
        values[3] != unchanged)
        return 5;
    if (errno != ERANGE)
        return 6;
    return 0;
}

#ifdef CRABC_GETLOADAVG_FREESTANDING
static int install_sysinfo_error_filter(void)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_sysinfo, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | EPERM),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
    };
    struct crabc_bpf_program program = {
        .length = (uint16_t)(sizeof(filter) / sizeof(filter[0])),
        .instructions = filter,
    };

    if (raw_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    if (raw_syscall3(SYS_seccomp, CRABC_SECCOMP_SET_MODE_FILTER, 0,
            (long)(uintptr_t)&program) != 0)
        return -1;
    return 0;
}

static int sysinfo_error_child_case(void)
{
    const double unchanged = -9876.5;
    double values[3] = { unchanged, unchanged, unchanged };

    if (install_sysinfo_error_filter() != 0)
        return 1;
    errno = E2BIG;
    if (getloadavg(values, 3) != -1)
        return 2;
    if (errno != EPERM)
        return 3;
    if (values[0] != unchanged || values[1] != unchanged ||
        values[2] != unchanged)
        return 4;
    return 0;
}

static int run_child_case(int (*child_case)(void))
{
    long child = raw_syscall0(SYS_fork);
    int status = -1;
    long waited;

    if (child == 0)
        raw_exit(child_case());
    if (child < 0)
        return 1;
    do {
        waited = raw_syscall4(SYS_wait4, child, (long)(uintptr_t)&status, 0,
            0);
    } while (waited == -EINTR);
    if (waited != child)
        return 2;
    return status == 0 ? 0 : 3;
}

static int check_safe_sysinfo_error_in_child(void)
{
    return run_child_case(sysinfo_error_child_case);
}
#else
static int check_safe_sysinfo_error_in_child(void)
{
    /* Musl's post-error local-record read is intentionally not an oracle. */
    return 0;
}
#endif

int crabc_x86_64_getloadavg_probe(void)
{
    int result = check_nonpositive_counts();

    if (result != 0)
        return result;
    result = check_three_loads_and_clamp();
    if (result != 0)
        return 10 + result;
    result = check_function_pointer_one_load();
    if (result != 0)
        return 20 + result;
    result = check_safe_sysinfo_error_in_child();
    return result == 0 ? 0 : 30 + result;
}

#ifndef CRABC_GETLOADAVG_FREESTANDING
int main(void)
{
    return crabc_x86_64_getloadavg_probe();
}
#endif
