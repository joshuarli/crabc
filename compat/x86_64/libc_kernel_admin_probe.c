/*
 * One installed-header object for the owned x86 kernel-administration ABI
 * providers. `arch_prctl` is an exported musl ELF compatibility spelling,
 * not a declaration in pinned musl's sys/prctl.h, so its source-faithful C
 * signature is bound explicitly below. The selected project syscall headers
 * remain the factual source of the Linux syscall number.
 *
 * This probe reads FS and GS only. Its negative arch_prctl calls use an
 * unknown operation and null output locations, so they cannot change a
 * segment base. The iopl/ioperm calls retain the existing invalid-only
 * negative boundary and never enable a port range or execute port I/O.
 */

#include <errno.h>
#include <stdint.h>
#include <sys/io.h>
#include <sys/syscall.h>

typedef int (*arch_prctl_signature)(int, unsigned long);
typedef int (*iopl_signature)(int);
typedef int (*ioperm_signature)(unsigned long, unsigned long, int);

extern int arch_prctl(int, unsigned long);

_Static_assert(sizeof(unsigned long) == 8 && _Alignof(unsigned long) == 8,
    "x86 LP64 unsigned long ABI");
_Static_assert(SYS_arch_prctl == 158,
    "Linux 5.10 x86 arch_prctl syscall number");
_Static_assert(SYS_iopl == 172, "Linux 5.10 x86 iopl syscall number");
_Static_assert(SYS_ioperm == 173, "Linux 5.10 x86 ioperm syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&arch_prctl),
    arch_prctl_signature), "arch_prctl source signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&iopl),
    iopl_signature), "iopl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ioperm),
    ioperm_signature), "ioperm declaration");

enum {
    ARCH_GET_FS = 0x1003,
    ARCH_GET_GS = 0x1004,
    ARCH_INVALID_OPERATION = 0x7fff,
};

static int invalid_io_errno_class(int error)
{
    if (error == EINVAL)
        return 0;
    if (error == EPERM)
        return 1;
    return -1;
}

static int observe_read(int operation, int failure)
{
    unsigned long value = 0x5a5aa5a55a5aa5a5UL;

    errno = ERANGE;
    if (arch_prctl(operation, (unsigned long)(uintptr_t)&value) != 0)
        return failure;
    if (value == 0x5a5aa5a55a5aa5a5UL)
        return failure + 1;
    return errno == ERANGE ? 0 : failure + 2;
}

static int observe_nonmutating_failures(void)
{
    errno = ERANGE;
    if (arch_prctl(ARCH_INVALID_OPERATION, 0UL) != -1 || errno != EINVAL)
        return 1;
    errno = ERANGE;
    if (arch_prctl(ARCH_GET_FS, 0UL) != -1 || errno != EFAULT)
        return 2;
    errno = ERANGE;
    if (arch_prctl(ARCH_GET_GS, 0UL) != -1 || errno != EFAULT)
        return 3;
    return 0;
}

static int observe_iopl_invalid(int level)
{
    errno = ERANGE;
    if (iopl(level) != -1)
        return -1;
    return invalid_io_errno_class(errno);
}

static int observe_ioperm_invalid(
    unsigned long from, unsigned long count, int turn_on)
{
    errno = ERANGE;
    if (ioperm(from, count, turn_on) != -1)
        return -1;
    return invalid_io_errno_class(errno);
}

int main(void)
{
    int iopl_negative;
    int iopl_large;
    int ioperm_start;
    int ioperm_count;
    int result;

    if ((result = observe_read(ARCH_GET_FS, 10)) != 0)
        return result;
    if ((result = observe_read(ARCH_GET_GS, 20)) != 0)
        return result;
    if ((result = observe_nonmutating_failures()) != 0)
        return 30 + result;

    iopl_negative = observe_iopl_invalid(-1);
    iopl_large = observe_iopl_invalid(4);
    ioperm_start = observe_ioperm_invalid(65536UL, 1UL, 0);
    ioperm_count = observe_ioperm_invalid(0UL, 65537UL, 0);
    if (iopl_negative < 0 || iopl_large < 0 ||
        ioperm_start < 0 || ioperm_count < 0)
        return 127;

    return iopl_negative | (iopl_large << 2) | (ioperm_start << 4) |
        (ioperm_count << 6);
}
