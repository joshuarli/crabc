/* Pinned-musl Linux/x86-64 getcwd(2) behavior reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires little-endian x86-64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer size");
_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t size");
_Static_assert(SYS_getcwd == 79, "x86 getcwd syscall number");

static long raw_getcwd(char *buffer, size_t size)
{
    return syscall(SYS_getcwd, buffer, size);
}

int main(void)
{
    char libc_cwd[4096];
    char syscall_cwd[4096];
    char libc_zero;
    char syscall_zero;
    char libc_small[1];
    char syscall_small[1];
    char *libc_result;
    long syscall_result;
    const char *libc_end;
    size_t libc_bytes;
    int libc_errno;

    errno = 0;
    libc_result = getcwd(libc_cwd, sizeof(libc_cwd));
    if (libc_result == NULL || libc_result != libc_cwd)
        return 10;
    libc_end = memchr(libc_cwd, '\0', sizeof(libc_cwd));
    if (libc_end == NULL)
        return 11;
    libc_bytes = (size_t)(libc_end - libc_cwd) + 1;

    memset(syscall_cwd, 0xa5, sizeof(syscall_cwd));
    errno = 0;
    syscall_result = raw_getcwd(syscall_cwd, sizeof(syscall_cwd));
    if (syscall_result <= 0 || syscall_result > (long)sizeof(syscall_cwd))
        return 12;
    if (syscall_result != (long)libc_bytes ||
        syscall_cwd[(size_t)syscall_result - 1] != '\0' ||
        memcmp(libc_cwd, syscall_cwd, libc_bytes) != 0)
        return 13;

    errno = 0;
    libc_result = getcwd(&libc_zero, 0);
    libc_errno = errno;
    if (libc_result != NULL || libc_errno != EINVAL)
        return 20;

    errno = 0;
    syscall_result = raw_getcwd(&syscall_zero, 0);
    if (syscall_result != -1 || errno != ERANGE)
        return 21;

    errno = 0;
    libc_result = getcwd(libc_small, sizeof(libc_small));
    libc_errno = errno;
    if (libc_result != NULL || libc_errno != ERANGE)
        return 30;

    errno = 0;
    syscall_result = raw_getcwd(syscall_small, sizeof(syscall_small));
    if (syscall_result != -1 || errno != ERANGE)
        return 31;

    puts("syscall=79 exact=match zero=musl-EINVAL/raw-ERANGE undersized=ERANGE");
    return 0;
}
