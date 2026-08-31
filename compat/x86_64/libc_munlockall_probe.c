/* Native Linux/x86-64 selected-static munlockall C ABI fixture.
 *
 * The same project-header body first executes through pinned musl 1.2.6 and
 * then a true -nostdlib -static crabc-libc candidate. This zero-argument
 * release request runs in a disposable process and proves direct success plus
 * stale errno; it does not select mlockall, per-range locking, mapping policy,
 * an allocator, or a C runtime.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

typedef int (*crabc_munlockall_type)(void);

_Static_assert(SYS_munlockall == 152, "x86 whole-process unlock syscall");
_Static_assert(__builtin_types_compatible_p(__typeof__(&munlockall),
    crabc_munlockall_type), "munlockall declaration");

int crabc_x86_64_munlockall_probe(void)
{
    crabc_munlockall_type invoke = munlockall;

    errno = EDOM;
    if (invoke() != 0)
        return 10;
    if (errno != EDOM)
        return 11;

    errno = ERANGE;
    if (invoke() != 0)
        return 12;
    if (errno != ERANGE)
        return 13;

    return 0;
}

#ifndef CRABC_MUNLOCKALL_FREESTANDING
int main(void)
{
    return crabc_x86_64_munlockall_probe();
}
#endif
