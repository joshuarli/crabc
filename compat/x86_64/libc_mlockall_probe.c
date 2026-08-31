/* Native Linux/x86-64 selected-static mlockall C ABI fixture.
 *
 * The same project-header body first executes through pinned musl 1.2.6 and
 * then a true -nostdlib -static crabc-libc candidate. Any successful process
 * lock is cleaned up with a fixture-private raw munlockall syscall, so the
 * candidate surface retains only mlockall. This does not select munlockall,
 * per-range locking, mapping policy, an allocator, or a C runtime.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

typedef int (*crabc_mlockall_type)(int);

_Static_assert(SYS_mlockall == 151 && SYS_munlockall == 152,
    "x86 whole-process locking syscalls");
_Static_assert(MCL_CURRENT == 1 && MCL_FUTURE == 2,
    "selected mlockall flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mlockall),
    crabc_mlockall_type), "mlockall declaration");

static long raw0(long number)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static int is_permitted_lock_error(int error)
{
    return error == EPERM || error == EAGAIN || error == ENOMEM;
}

static int unlock_after_success(int expected_errno, int failure)
{
    if (raw0(SYS_munlockall) != 0)
        return failure;
    if (errno != expected_errno)
        return failure + 1;
    return 0;
}

int crabc_x86_64_mlockall_probe(void)
{
    crabc_mlockall_type invoke = mlockall;
    int result;

    errno = EDOM;
    result = invoke(MCL_CURRENT);
    if (result == 0) {
        if (errno != EDOM)
            return 10;
        result = unlock_after_success(EDOM, 11);
        if (result != 0)
            return result;
    } else if (!is_permitted_lock_error(errno)) {
        return 13;
    }

    errno = 0;
    if (invoke(0) != -1 || errno != EINVAL)
        return 14;

    errno = 0;
    if (invoke(MCL_CURRENT | MCL_FUTURE | (1 << 30)) != -1 || errno != EINVAL)
        return 15;

    return 0;
}

#ifndef CRABC_MLOCKALL_FREESTANDING
int main(void)
{
    return crabc_x86_64_mlockall_probe();
}
#endif
