/* Static crabc-libc x86-64 lchmod unsupported-profile fixture.
 *
 * Linux has no operation that changes a symbolic link's mode.  Musl keeps
 * the GNU/BSD-visible C ABI entry by delegating to flag-bearing `fchmodat`.
 * The selected dangling-link input reports ENOTSUP without following the
 * target. The same body first runs through pinned musl and then through the
 * selected freestanding crabc archive. A fixture-local raw
 * symlink creates the no-follow input; it does not stand in for the candidate
 * C API. The freestanding candidate additionally receives a null pathname,
 * proving its deliberately pre-resolution fixed-result boundary without
 * claiming that musl's delegated `fchmodat` accepts that input.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

_Static_assert(sizeof(mode_t) == 4, "x86 LP64 mode_t width");
_Static_assert(_Alignof(mode_t) == _Alignof(unsigned int),
               "x86 LP64 mode_t alignment");
_Static_assert(ENOTSUP == EOPNOTSUPP, "Linux aliases unsupported errno");
_Static_assert(ENOTSUP == 95, "Linux x86 unsupported errno value");
_Static_assert(SYS_symlink == 88, "Linux x86 symlink syscall number");
_Static_assert(SYS_unlink == 87, "Linux x86 unlink syscall number");

static long raw_syscall2(long number, long argument1, long argument2)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2)
        : "rcx", "r11", "memory");
    return result;
}

static int check_unsupported(const char *path, mode_t mode)
{
    errno = 0;
    if (lchmod(path, mode) != -1)
        return 1;
    if (errno != ENOTSUP || errno != EOPNOTSUPP)
        return 2;
    return 0;
}

int crabc_x86_64_lchmod_unsupported_probe(void)
{
    static const char target[] = "missing-lchmod-target";
    static const char link_name[] = "lchmod-no-follow-link";
    int status;

    if (raw_syscall2(SYS_symlink, (long)target, (long)link_name) != 0)
        return 1;
    status = check_unsupported(link_name, 0000);
    if (status != 0)
        goto cleanup_first;
    status = check_unsupported(link_name, 0777);
    if (status != 0)
        goto cleanup_second;
#ifdef CRABC_LCHMOD_UNSUPPORTED_FREESTANDING
    status = check_unsupported((const char *)0, 0600);
    if (status != 0)
        goto cleanup_third;
#endif
    if (raw_syscall2(SYS_unlink, (long)link_name, 0) != 0)
        return 4;
    return 0;

cleanup_first:
    (void)raw_syscall2(SYS_unlink, (long)link_name, 0);
    return 10 + status;
cleanup_second:
    (void)raw_syscall2(SYS_unlink, (long)link_name, 0);
    return 20 + status;
cleanup_third:
    (void)raw_syscall2(SYS_unlink, (long)link_name, 0);
    return 30 + status;
}

#ifndef CRABC_LCHMOD_UNSUPPORTED_FREESTANDING
int main(void)
{
    return crabc_x86_64_lchmod_unsupported_probe();
}
#endif
