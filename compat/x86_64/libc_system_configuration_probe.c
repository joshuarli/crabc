/* Static crabc-libc x86-64 selected system-configuration fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc libc.a. It proves the closed musl-oracle configuration surface only:
 * bounded sysconf page/tick queries, confstr, table-based pathconf/fpathconf,
 * getpagesize, and getdtablesize. It does not select statfs/statvfs, /proc,
 * a full sysconf table, startup-owned auxv, dynamic libc, CRT, loader,
 * sysroot, pthread/TLS lifecycle, allocator, or public x86 support.
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
#include <stddef.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CRABC_TYPE_IS(expression, type) \
    __builtin_types_compatible_p(__typeof__(expression), type)

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(_SC_CLK_TCK == 2 && _SC_PAGE_SIZE == 30 &&
    _SC_PAGESIZE == _SC_PAGE_SIZE, "selected sysconf selectors");
_Static_assert(_CS_PATH == 0 && _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS == 1 &&
    _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS == 5,
    "selected confstr selectors");
_Static_assert(_CS_POSIX_V6_ILP32_OFF32_CFLAGS == 1116 &&
    _CS_POSIX_V7_THREADS_LDFLAGS == 1151,
    "confstr range bounds");
_Static_assert(_PC_LINK_MAX == 0 && _PC_2_SYMLINKS == 20 &&
    _PC_FILESIZEBITS == 13 && _PC_REC_INCR_XFER_SIZE == 14,
    "pathconf selector range");
_Static_assert(SYS_statfs == 137 && SYS_fstatfs == 138,
    "x86 statfs syscall namespace remains header-only here");
_Static_assert(SYS_prlimit64 == 302, "x86 getdtablesize syscall number");
_Static_assert(CRABC_TYPE_IS(&sysconf, long (*)(int)), "sysconf declaration");
_Static_assert(CRABC_TYPE_IS(&confstr, size_t (*)(int, char *, size_t)),
    "confstr declaration");
_Static_assert(CRABC_TYPE_IS(&fpathconf, long (*)(int, int)),
    "fpathconf declaration");
_Static_assert(CRABC_TYPE_IS(&pathconf, long (*)(const char *, int)),
    "pathconf declaration");
_Static_assert(CRABC_TYPE_IS(&getpagesize, int (*)(void)),
    "getpagesize declaration");
_Static_assert(CRABC_TYPE_IS(&getdtablesize, int (*)(void)),
    "getdtablesize declaration");

static int check_common_contract(void)
{
    char path[32] = { 0 };
    char truncated[4] = { 0 };
    char untouched = 'X';
    const int stale_errno = ERANGE;
    const size_t path_length = sizeof "/bin:/usr/bin";
    int name;

    errno = stale_errno;
    if (sysconf(_SC_CLK_TCK) != 100 || errno != stale_errno)
        return 1;
    if (sysconf(_SC_PAGE_SIZE) != 4096 || errno != stale_errno)
        return 2;
    errno = 0;
    if (sysconf(-1) != -1 || errno != EINVAL)
        return 3;

    errno = stale_errno;
    if (confstr(_CS_PATH, NULL, 0) != path_length || errno != stale_errno)
        return 4;
    if (confstr(_CS_PATH, path, sizeof path) != path_length ||
        path[0] != '/' || path[4] != ':' || path[path_length - 1] != '\0' ||
        errno != stale_errno)
        return 5;
    if (confstr(_CS_PATH, truncated, sizeof truncated) != path_length ||
        truncated[sizeof truncated - 1] != '\0' || errno != stale_errno)
        return 6;
    if (confstr(_CS_PATH, &untouched, 0) != path_length || untouched != 'X' ||
        errno != stale_errno)
        return 7;
    if (confstr(_CS_POSIX_V6_WIDTH_RESTRICTED_ENVS, path, sizeof path) != 1 ||
        path[0] != '\0' || errno != stale_errno)
        return 8;
    if (confstr(_CS_POSIX_V7_WIDTH_RESTRICTED_ENVS, path, sizeof path) != 1 ||
        path[0] != '\0' || errno != stale_errno)
        return 9;
    for (name = _CS_POSIX_V6_ILP32_OFF32_CFLAGS;
         name <= _CS_POSIX_V7_THREADS_LDFLAGS; ++name) {
        errno = stale_errno;
        if (confstr(name, path, sizeof path) != 1 || path[0] != '\0' ||
            errno != stale_errno)
            return 10 + name - _CS_POSIX_V6_ILP32_OFF32_CFLAGS;
    }
    errno = 0;
    if (confstr(-1, path, sizeof path) != 0 || errno != EINVAL)
        return 46;
    errno = 0;
    if (confstr(2, path, sizeof path) != 0 || errno != EINVAL)
        return 47;
    errno = 0;
    if (confstr(1152, path, sizeof path) != 0 || errno != EINVAL)
        return 48;

    return 0;
}

static int check_musl_configuration_contract(void)
{
    static const long values[] = {
        8, 255, 255, 255, 4096, 4096, 1, 1, 0, 1, -1,
        -1, -1, 64, 4096, 4096, 4096, 4096, 4096, -1, 1,
    };
    const int stale_errno = E2BIG;
    unsigned int name;

    for (name = 0; name < sizeof values / sizeof values[0]; ++name) {
        errno = stale_errno;
        if (pathconf(NULL, (int)name) != values[name] || errno != stale_errno)
            return 1 + (int)name;
        errno = stale_errno;
        if (fpathconf(-1, (int)name) != values[name] || errno != stale_errno)
            return 30 + (int)name;
    }

    errno = 0;
    if (pathconf(NULL, -1) != -1 || errno != EINVAL)
        return 60;
    errno = 0;
    if (fpathconf(-1, 21) != -1 || errno != EINVAL)
        return 61;
    return 0;
}

static int check_pagesize_and_dtable_contract(void)
{
    struct rlimit limit;
    const int stale_errno = EOVERFLOW;
    unsigned long long expected;

    errno = stale_errno;
    if (getpagesize() != 4096 || errno != stale_errno)
        return 1;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || errno != stale_errno)
        return 2;
    expected = limit.rlim_cur < (rlim_t)INT_MAX ? limit.rlim_cur : INT_MAX;
    if (getdtablesize() != (int)expected || errno != stale_errno)
        return 3;
    return 0;
}

int crabc_x86_64_system_configuration_probe(void)
{
    int status = check_common_contract();

    if (status != 0)
        return 10 + status;
    status = check_musl_configuration_contract();
    if (status != 0)
        return 100 + status;
    status = check_pagesize_and_dtable_contract();
    return status == 0 ? 0 : 200 + status;
}

#ifndef CRABC_SYSTEM_CONFIGURATION_FREESTANDING
int main(void)
{
    return crabc_x86_64_system_configuration_probe();
}
#endif
