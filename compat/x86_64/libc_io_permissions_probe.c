/*
 * Pinned-musl Linux/x86-64 iopl/ioperm negative-path differential body.
 *
 * Both wrappers are direct kernel syscall veneers. This fixture deliberately
 * passes only kernel-invalid arguments: it neither requests a valid I/O
 * privilege level nor enables a port range, and it never executes an in/out
 * instruction. The chosen calls cannot make a valid permission change. Linux
 * may reject them with EINVAL or may report EPERM first when the calling task
 * lacks the required authority, so the common fixture records that exact
 * errno fingerprint instead of assuming kernel check ordering.
 */

#include <errno.h>
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
_Static_assert(SYS_iopl == 172, "Linux 5.10 x86 iopl syscall number");
_Static_assert(SYS_ioperm == 173, "Linux 5.10 x86 ioperm syscall number");

static int invalid_errno_class(int error)
{
    if (error == EINVAL)
        return 0;
    if (error == EPERM)
        return 1;
    return -1;
}

static int observe_iopl_invalid(int level)
{
    errno = ERANGE;
    if (iopl(level) != -1)
        return -1;
    return invalid_errno_class(errno);
}

static int observe_ioperm_invalid(
    unsigned long from, unsigned long count, int turn_on)
{
    errno = ERANGE;
    if (ioperm(from, count, turn_on) != -1)
        return -1;
    return invalid_errno_class(errno);
}

int crabc_x86_64_io_permissions_probe(void)
{
    int iopl_negative;
    int iopl_large;
    int ioperm_start;
    int ioperm_count;

    /* These levels are outside Linux's valid 0..3 range. */
    iopl_negative = observe_iopl_invalid(-1);
    iopl_large = observe_iopl_invalid(4);

    /* Each range exceeds the 16-bit x86 port namespace without enabling it. */
    ioperm_start = observe_ioperm_invalid(65536UL, 1UL, 0);
    ioperm_count = observe_ioperm_invalid(0UL, 65537UL, 0);

    if (iopl_negative < 0)
        return 128;
    if (iopl_large < 0)
        return 129;
    if (ioperm_start < 0)
        return 130;
    if (ioperm_count < 0)
        return 131;

    /* Each two-bit field is EINVAL=0 or EPERM=1 in call order. */
    return iopl_negative | (iopl_large << 2) | (ioperm_start << 4) |
        (ioperm_count << 6);
}

#ifndef CRABC_IO_PERMISSIONS_FREESTANDING
int main(void)
{
    return crabc_x86_64_io_permissions_probe();
}
#endif
