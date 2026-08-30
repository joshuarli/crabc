/* Static crabc-libc x86-64 processor/page-count fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through a freestanding executable linked solely with the selected
 * crabc archive. It specifies only musl's four legacy system-information
 * helpers: the shared 128-byte CPU-affinity count and physical/free-plus-
 * buffer page observations. It is not load observation, affinity control,
 * scheduler policy, topology, /proc parsing, sysconf, CRT, pthread/TLS
 * lifecycle, loader, sysroot, or public x86 support.
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
#include <sys/syscall.h>
#include <sys/sysinfo.h>

/* This test-only classic-BPF program denies just sched_getaffinity after its
 * child has enabled no-new-privileges. The child-local irreversible filter
 * proves musl's initialized CPU-zero fallback without affecting either parent
 * arm or any following evidence command. */
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
    CRABC_AFFINITY_ERROR = EBADE,
};

#define CRABC_BPF_STATEMENT(instruction_code, value) \
    { (uint16_t)(instruction_code), 0, 0, (uint32_t)(value) }
#define CRABC_BPF_JUMP(instruction_code, value, yes, no) \
    { (uint16_t)(instruction_code), (uint8_t)(yes), (uint8_t)(no), \
      (uint32_t)(value) }

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct sysinfo) == 368 && _Alignof(struct sysinfo) == 8,
    "x86 public sysinfo layout");
_Static_assert(SYS_fork == 57 && SYS_exit == 60 && SYS_wait4 == 61 &&
    SYS_sysinfo == 99 && SYS_prctl == 157 && SYS_sched_getaffinity == 204 &&
    SYS_seccomp == 317,
    "x86 selected and fixture-only system-information syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_nprocs_conf),
    int (*)(void)), "get_nprocs_conf declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_nprocs),
    int (*)(void)), "get_nprocs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_phys_pages),
    long (*)(void)), "get_phys_pages declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_avphys_pages),
    long (*)(void)), "get_avphys_pages declaration");

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument_one)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one)
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

static int check_stale_errno_and_live_values(void)
{
    int configured;
    int online;
    long physical;
    long available;

    errno = E2BIG;
    configured = get_nprocs_conf();
    if (configured < 1 || configured > 1024 || errno != E2BIG)
        return 1;
    errno = E2BIG;
    online = get_nprocs();
    if (online != configured || errno != E2BIG)
        return 2;
    errno = E2BIG;
    physical = get_phys_pages();
    if (physical <= 0 || errno != E2BIG)
        return 3;
    errno = E2BIG;
    available = get_avphys_pages();
    if (available < 0 || errno != E2BIG)
        return 4;
    return 0;
}

static int install_affinity_error_filter(void)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_sched_getaffinity, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | CRABC_AFFINITY_ERROR),
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

static int affinity_error_child_case(void)
{
    if (install_affinity_error_filter() != 0)
        return 1;
    errno = E2BIG;
    if (get_nprocs_conf() != 1 || errno != E2BIG)
        return 2;
    errno = E2BIG;
    if (get_nprocs() != 1 || errno != E2BIG)
        return 3;
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

static int check_affinity_error_fallback_in_child(void)
{
    return run_child_case(affinity_error_child_case);
}

int crabc_x86_64_system_information_probe(void)
{
    int status = check_stale_errno_and_live_values();

    if (status != 0)
        return status;
    status = check_affinity_error_fallback_in_child();
    if (status != 0)
        return 10 + status;
    return 0;
}

#ifndef CRABC_SYSTEM_INFORMATION_FREESTANDING
int main(void)
{
    return crabc_x86_64_system_information_probe();
}
#endif
