/* Static crabc-libc x86-64 GNU sched_getcpu observation fixture.
 *
 * The project-header C body first runs through pinned musl 1.2.6 and then a
 * freestanding candidate linked only with the selected crabc archive. Both
 * prove a nonnegative instantaneous CPU observation and stale errno success.
 * The candidate-only seccomp phase forces raw getcpu=309 to fail, proving its
 * explicit raw-fallback -1/errno route; musl may use its private vDSO fast
 * path, so that forced-syscall result is intentionally not a musl comparison.
 * This fixture neither selects affinity/policy/parameter APIs nor CPU/NUMA
 * topology, process migration, clocks/timers, threads, CRT, loader, sysroot,
 * or public x86 support.
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
#include <sched.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

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

typedef int (*sched_getcpu_signature)(void);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 && sizeof(int) == 4,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct crabc_bpf_instruction) == 8 &&
    __builtin_offsetof(struct crabc_bpf_program, instructions) == 8,
    "x86 classic-BPF filter ABI");
_Static_assert(SYS_getcpu == 309 && SYS_prctl == 157 && SYS_seccomp == 317,
    "x86 selected and fixture-only getcpu syscalls");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_getcpu),
    sched_getcpu_signature), "sched_getcpu declaration");

static sched_getcpu_signature volatile direct_sched_getcpu = sched_getcpu;

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall5(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

static int check_cpu_observation_preserves_errno(void)
{
    errno = E2BIG;
    if (direct_sched_getcpu() < 0)
        return 1;
    if (errno != E2BIG)
        return 2;
    errno = EILSEQ;
    if (direct_sched_getcpu() < 0)
        return 3;
    return errno == EILSEQ ? 0 : 4;
}

#ifdef CRABC_SCHED_GETCPU_FREESTANDING
static int install_getcpu_error_filter(void)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_getcpu, 0, 1),
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
    return raw_syscall3(SYS_seccomp, CRABC_SECCOMP_SET_MODE_FILTER, 0,
        (long)(uintptr_t)&program) == 0 ? 0 : -1;
}

static int check_forced_raw_fallback_error(void)
{
    if (install_getcpu_error_filter() != 0)
        return 1;
    errno = ERANGE;
    return direct_sched_getcpu() == -1 && errno == EPERM ? 0 : 2;
}
#endif

int crabc_x86_64_sched_getcpu_probe(void)
{
    int status = check_cpu_observation_preserves_errno();

    if (status != 0)
        return status;
#ifdef CRABC_SCHED_GETCPU_FREESTANDING
    status = check_forced_raw_fallback_error();
    if (status != 0)
        return 10 + status;
#endif
    return 0;
}

#ifndef CRABC_SCHED_GETCPU_FREESTANDING
int main(void)
{
    return crabc_x86_64_sched_getcpu_probe();
}
#endif
