/* Pinned-musl Linux/x86-64 iopl/ioperm physical differential.
 *
 * Every ordinary request has an invalid level or a range outside the 16-bit
 * port namespace. A process-local seccomp filter later forces permission
 * errors before either kernel handler can change I/O state. No port-I/O
 * instruction executes, and no expected natural error assumes capabilities.
 */
#include <errno.h>
#include <stdint.h>
#include <sys/io.h>
#include <sys/syscall.h>

typedef int (*iopl_signature)(int);
typedef int (*ioperm_signature)(unsigned long, unsigned long, int);
_Static_assert(__builtin_types_compatible_p(__typeof__(&iopl), iopl_signature),
    "iopl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ioperm), ioperm_signature),
    "ioperm declaration");
_Static_assert(sizeof(unsigned long) == 8 && _Alignof(unsigned long) == 8,
    "x86 LP64 unsigned long ABI");
_Static_assert(SYS_iopl == 172 && SYS_ioperm == 173 && SYS_prctl == 157 &&
    SYS_seccomp == 317 && SYS_write == 1, "Linux 5.10 x86 syscall numbers");

struct bpf_instruction {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t immediate;
};
struct bpf_program {
    uint16_t length;
    struct bpf_instruction *instructions;
};
_Static_assert(sizeof(struct bpf_instruction) == 8 &&
    __builtin_offsetof(struct bpf_program, instructions) == 8,
    "x86 classic BPF layout");
enum {
    BPF_LOAD_WORD_ABSOLUTE = 0x20,
    BPF_JUMP_EQUAL = 0x15,
    BPF_RETURN = 0x06,
    SECCOMP_SET_MODE_FILTER = 1,
    SECCOMP_RETURN_ALLOW = 0x7fff0000U,
    SECCOMP_RETURN_ERRNO = 0x00050000U,
    PR_SET_NO_NEW_PRIVS = 38,
};
#define BPF_STATEMENT(op, value) { (op), 0, 0, (value) }
#define BPF_JUMP(op, value, yes, no) { (op), (yes), (no), (value) }

static long raw_syscall3(long number, long first, long second, long third)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall5(long number, long first, long second, long third,
    long fourth, long fifth)
{
    long result;
    register long register4 __asm__("r10") = fourth;
    register long register5 __asm__("r8") = fifth;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

static int invalid_errno_class(int error)
{
    if (error == EINVAL) return 0;
    if (error == EPERM) return 1;
    return -1;
}

/* Two wrapper calls after a raw request prove errno translation with distinct
 * stale values and catch unintended state changes between repeated calls. */
static int observe_iopl_invalid(int level)
{
    long raw;
    int observed;
    errno = ERANGE;
    raw = raw_syscall3(SYS_iopl, level, 0, 0);
    if (errno != ERANGE || raw >= 0 || invalid_errno_class((int)-raw) < 0)
        return -1;
    errno = EDOM;
    if (iopl(level) != -1 || errno != -raw) return -1;
    observed = invalid_errno_class(errno);
    errno = EBUSY;
    if (iopl(level) != -1 || errno != -raw) return -1;
    return observed;
}

static int observe_ioperm_invalid(unsigned long from, unsigned long count,
    int turn_on)
{
    long raw;
    int observed;
    errno = ERANGE;
    raw = raw_syscall3(SYS_ioperm, (long)from, (long)count, turn_on);
    if (errno != ERANGE || raw >= 0 || invalid_errno_class((int)-raw) < 0)
        return -1;
    errno = EDOM;
    if (ioperm(from, count, turn_on) != -1 || errno != -raw) return -1;
    observed = invalid_errno_class(errno);
    errno = EBUSY;
    if (ioperm(from, count, turn_on) != -1 || errno != -raw) return -1;
    return observed;
}

static int write_all(const char *bytes, unsigned long length)
{
    while (length) {
        long written = raw_syscall3(SYS_write, 1, (long)(uintptr_t)bytes,
            (long)length);
        if (written <= 0) return -1;
        bytes += written;
        length -= (unsigned long)written;
    }
    return 0;
}

static int record(const char *label, int observed)
{
    unsigned long length = 0;
    char result[2];
    if (observed < 0) return -1;
    while (label[length]) length++;
    result[0] = observed == 0 ? 'I' : 'P';
    result[1] = '\n';
    return write_all(label, length) == 0 && write_all(result, 2) == 0 ? 0 : -1;
}

static int install_permission_error_filter(void)
{
    struct bpf_instruction instructions[] = {
        BPF_STATEMENT(BPF_LOAD_WORD_ABSOLUTE, 0),
        BPF_JUMP(BPF_JUMP_EQUAL, SYS_iopl, 0, 1),
        BPF_STATEMENT(BPF_RETURN, SECCOMP_RETURN_ERRNO | EPERM),
        BPF_JUMP(BPF_JUMP_EQUAL, SYS_ioperm, 0, 1),
        BPF_STATEMENT(BPF_RETURN, SECCOMP_RETURN_ERRNO | EACCES),
        BPF_STATEMENT(BPF_RETURN, SECCOMP_RETURN_ALLOW),
    };
    struct bpf_program program = {
        (uint16_t)(sizeof(instructions) / sizeof(instructions[0])),
        instructions,
    };
    if (raw_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    if (raw_syscall3(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0,
            (long)(uintptr_t)&program) != 0)
        return -1;
    return 0;
}

static int observe_filtered_iopl(int level)
{
    errno = ERANGE;
    if (raw_syscall3(SYS_iopl, level, 0, 0) != -EPERM || errno != ERANGE)
        return -1;
    errno = EDOM;
    if (iopl(level) != -1 || errno != EPERM) return -1;
    errno = EBUSY;
    if (iopl(level) != -1 || errno != EPERM) return -1;
    return 0;
}

static int observe_filtered_ioperm(unsigned long from, unsigned long count,
    int turn_on)
{
    errno = ERANGE;
    if (raw_syscall3(SYS_ioperm, (long)from, (long)count, turn_on) !=
            -EACCES || errno != ERANGE)
        return -1;
    errno = EDOM;
    if (ioperm(from, count, turn_on) != -1 || errno != EACCES) return -1;
    errno = EBUSY;
    if (ioperm(from, count, turn_on) != -1 || errno != EACCES) return -1;
    return 0;
}

#define RECORD(label, observation, failure) \
    do { if (record((label), (observation)) != 0) return (failure); } while (0)

int crabc_x86_64_io_permissions_probe(void)
{
    RECORD("natural:iopl:-1=", observe_iopl_invalid(-1), 128);
    RECORD("natural:ioperm:past-end=",
        observe_ioperm_invalid(65536UL, 1UL, 0), 129);
    RECORD("natural:iopl:4=", observe_iopl_invalid(4), 130);
    RECORD("natural:ioperm:long-range=",
        observe_ioperm_invalid(0UL, 65537UL, 0), 131);
    RECORD("natural:iopl:-2=", observe_iopl_invalid(-2), 132);
    RECORD("natural:ioperm:cross-end=",
        observe_ioperm_invalid(65535UL, 2UL, 0), 133);
    RECORD("natural:iopl:5=", observe_iopl_invalid(5), 134);
    RECORD("natural:ioperm:past-end-enable=",
        observe_ioperm_invalid(65536UL, 1UL, 1), 135);
    RECORD("natural:ioperm:long-range-enable=",
        observe_ioperm_invalid(0UL, 65537UL, 1), 136);

    if (install_permission_error_filter() != 0) return 137;
    if (observe_filtered_iopl(-1) != 0) return 138;
    if (write_all("filtered:iopl=EPERM\n", sizeof("filtered:iopl=EPERM\n") - 1)
            != 0) return 139;
    if (observe_filtered_ioperm(65536UL, 1UL, 0) != 0) return 140;
    if (write_all("filtered:ioperm=EACCES\n",
            sizeof("filtered:ioperm=EACCES\n") - 1) != 0) return 141;
    if (observe_filtered_iopl(4) != 0 ||
        observe_filtered_ioperm(0UL, 65537UL, 0) != 0) return 142;
    if (write_all("filtered:interleaved=EPERM,EACCES\n",
            sizeof("filtered:interleaved=EPERM,EACCES\n") - 1) != 0) return 143;
    return 0;
}

#ifndef CRABC_IO_PERMISSIONS_FREESTANDING
int main(void)
{
    return crabc_x86_64_io_permissions_probe();
}
#endif
