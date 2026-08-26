/* Pinned-musl Linux/x86-64 getgroups(2) behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(sizeof(gid_t) == 4, "x86 gid_t size");
_Static_assert(_Alignof(gid_t) == 4, "x86 gid_t alignment");
_Static_assert((gid_t)-1 > 0, "x86 gid_t unsignedness");
_Static_assert(SYS_getgroups == 115, "x86 getgroups syscall number");

static long direct_getgroups(int count, gid_t *groups)
{
    return syscall(SYS_getgroups, count, groups);
}

int main(void)
{
    gid_t *musl_groups = NULL;
    gid_t *direct_groups = NULL;
    int count;
    long direct_count;

    errno = 0;
    count = getgroups(0, NULL);
    if (count < 0)
        return 10;

    errno = 0;
    direct_count = direct_getgroups(0, NULL);
    if (direct_count != count)
        return 11;

    if (count > 0) {
        size_t bytes = (size_t)count * sizeof(*musl_groups);

        musl_groups = malloc(bytes);
        direct_groups = malloc(bytes);
        if (musl_groups == NULL || direct_groups == NULL)
            return 12;
    }

    errno = 0;
    if (getgroups(count, musl_groups) != count)
        return 20;

    errno = 0;
    if (direct_getgroups(count, direct_groups) != count)
        return 21;
    if (count > 0 && memcmp(musl_groups, direct_groups,
                            (size_t)count * sizeof(*musl_groups)) != 0)
        return 22;

    if (count > 0) {
        errno = 0;
        if (getgroups(count - 1, musl_groups) != -1 || errno != EINVAL)
            return 30;

        errno = 0;
        if (direct_getgroups(count - 1, direct_groups) != -1 || errno != EINVAL)
            return 31;
    }

    free(direct_groups);
    free(musl_groups);
    puts("gid_t=u32 align=4 syscall=115 query=direct-equivalent fill=direct-equivalent undersized=conditional-einval");
    return 0;
}
