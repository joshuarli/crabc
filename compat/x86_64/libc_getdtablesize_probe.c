/* Static Linux/x86-64 getdtablesize C ABI and behavior fixture.
 *
 * Pinned musl 1.2.6 supplies the successful `prlimit64(RLIMIT_NOFILE)`
 * behavior oracle. The freestanding crabc candidate additionally blocks that
 * one syscall after the successful comparison: unlike musl's legacy source,
 * which reads an uninitialized record after getrlimit failure, crabc returns
 * -1 and publishes the kernel errno. That candidate-only safety contract is
 * deliberately not presented as musl error-path parity.
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
#include <limits.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef int (*getdtablesize_signature)(void);

/* A test-only classic-BPF filter supplies an observable raw-error path after
 * the normal musl comparison. It is not a public prctl/seccomp capability. */
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
    CRABC_GETDTABLESIZE_ERROR = EBADE,
};

#define CRABC_BPF_STATEMENT(instruction_code, value) \
    { (uint16_t)(instruction_code), 0, 0, (uint32_t)(value) }
#define CRABC_BPF_JUMP(instruction_code, value, yes, no) \
    { (uint16_t)(instruction_code), (uint8_t)(yes), (uint8_t)(no), \
      (uint32_t)(value) }

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct rlimit) == 16 && _Alignof(struct rlimit) == 8,
    "x86 public rlimit layout");
_Static_assert(SYS_prctl == 157 && SYS_prlimit64 == 302 && SYS_seccomp == 317,
    "x86 selected and fixture-only syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getdtablesize),
    getdtablesize_signature), "getdtablesize declaration");

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

static int check_musl_normal_path(void)
{
    struct rlimit limit;
    getdtablesize_signature indirect = getdtablesize;
    int expected;

    if (raw_syscall4(SYS_prlimit64, 0, RLIMIT_NOFILE, 0,
            (long)(uintptr_t)&limit) != 0)
        return 1;
    expected = limit.rlim_cur < (rlim_t)INT_MAX ? (int)limit.rlim_cur : INT_MAX;

    errno = E2BIG;
    if (getdtablesize() != expected || errno != E2BIG)
        return 2;
    errno = E2BIG;
    if (indirect() != expected || errno != E2BIG)
        return 3;
    return 0;
}

#ifdef CRABC_GETDTABLESIZE_FREESTANDING
static int install_getdtablesize_error_filter(void)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_prlimit64, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | CRABC_GETDTABLESIZE_ERROR),
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

static int check_candidate_error_contract(void)
{
    if (install_getdtablesize_error_filter() != 0)
        return 1;
    errno = E2BIG;
    if (getdtablesize() != -1 || errno != CRABC_GETDTABLESIZE_ERROR)
        return 2;
    return 0;
}
#endif

int crabc_x86_64_getdtablesize_probe(void)
{
    int status = check_musl_normal_path();

    if (status != 0)
        return status;
#ifdef CRABC_GETDTABLESIZE_FREESTANDING
    status = check_candidate_error_contract();
    if (status != 0)
        return 10 + status;
#endif
    return 0;
}

#ifndef CRABC_GETDTABLESIZE_FREESTANDING
int main(void)
{
    return crabc_x86_64_getdtablesize_probe();
}
#endif
