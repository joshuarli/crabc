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
#include <fcntl.h>
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
_Static_assert(SYS_write == 1, "x86 raw observation output syscall");
_Static_assert(SYS_openat == 257 && SYS_close == 3 &&
    SYS_pipe2 == 293 && SYS_unlinkat == 263 && SYS_getpid == 39,
    "x86 raw fixture resource syscalls");
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
    if (sysconf(INT_MAX) != -1 || errno != EINVAL)
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

/* Each initialized record is written directly so the freestanding candidate
 * and pinned-musl reference expose physical return, errno, and output bytes.
 * A raw Linux write is fixture plumbing; it selects no libc stdio or CRT.
 * Variants: 1 sysconf; 10/11/14 pathconf with null/absent/temporary-file
 * path; 12/13/15..18 fpathconf with -1/9999/file/pipe-read/pipe-write/closed
 * descriptors; 20..23 confstr with 0/1/4/16 output bytes.
 */
struct observation {
    long result;
    long error;
    long selector;
    long variant;
    unsigned char output[16];
};

_Static_assert(sizeof(struct observation) == 48, "fixed observation layout");

static int emit(const struct observation *record)
{
    long written;
    register long call_number __asm__("rax") = SYS_write;
    register long descriptor __asm__("rdi") = 1;
    register const void *source __asm__("rsi") = record;
    register size_t length __asm__("rdx") = sizeof *record;

    __asm__ volatile("syscall" : "=a"(written)
        : "0"(call_number), "D"(descriptor), "S"(source), "d"(length)
        : "rcx", "r11", "memory");
    return written == (long)sizeof *record ? 0 : 1;
}

/* Linux syscalls create only fixture resources. Their negative kernel returns
 * never enter libc errno, leaving the configuration calls' errno observable.
 */
static long raw_syscall2(long number, long first, long second)
{
    long result;
    register long fourth __asm__("r10") = 0;

    __asm__ volatile("syscall" : "=a"(result)
        : "0"(number), "D"(first), "S"(second), "d"(0L), "r"(fourth)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long first, long second, long third)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "0"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long first, long second, long third,
    long fourth_argument)
{
    long result;
    register long fourth __asm__("r10") = fourth_argument;

    __asm__ volatile("syscall" : "=a"(result)
        : "0"(number), "D"(first), "S"(second), "d"(third), "r"(fourth)
        : "rcx", "r11", "memory");
    return result;
}

struct fixture_resources {
    char path[96];
    int file;
    int pipe[2];
    int closed;
};

static int open_fixture_resources(struct fixture_resources *resources)
{
    static const char prefix[] =
        ".work/x86_64/reports/libc-system-configuration/probe-";
    unsigned long pid = (unsigned long)raw_syscall2(SYS_getpid, 0, 0);
    unsigned int index = 0;
    unsigned int digit;
    int failure;
    long descriptor;

    for (; index < sizeof prefix - 1; ++index)
        resources->path[index] = prefix[index];
    for (digit = 0; digit < 10; ++digit) {
        resources->path[index + 9 - digit] = (char)('0' + pid % 10);
        pid /= 10;
    }
    index += 10;
    resources->path[index++] = '-';
    resources->path[index + 1] = '\0';
    if (raw_syscall2(SYS_pipe2, (long)resources->pipe, O_CLOEXEC) != 0)
        return 3;
    for (digit = 0; digit < 10; ++digit) {
        resources->path[index] = (char)('0' + digit);
        descriptor = raw_syscall4(SYS_openat, AT_FDCWD,
            (long)resources->path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        if (descriptor >= 0) break;
        if (descriptor != -EEXIST) {
            failure = 1;
            goto close_pipe;
        }
    }
    if (digit == 10) {
        failure = 2;
        goto close_pipe;
    }
    resources->file = (int)descriptor;
    descriptor = raw_syscall4(SYS_openat, AT_FDCWD,
        (long)resources->path, O_RDONLY | O_CLOEXEC, 0);
    if (descriptor < 0) {
        failure = 4;
        goto close_file;
    }
    resources->closed = (int)descriptor;
    if (raw_syscall2(SYS_close, descriptor, 0) != 0) {
        failure = 5;
        goto close_file;
    }
    return 0;

close_file:
    raw_syscall2(SYS_close, resources->file, 0);
    raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)resources->path, 0);
close_pipe:
    raw_syscall2(SYS_close, resources->pipe[0], 0);
    raw_syscall2(SYS_close, resources->pipe[1], 0);
    return failure;
}

static int close_fixture_resources(const struct fixture_resources *resources)
{
    int failure = 0;

    if (raw_syscall2(SYS_close, resources->file, 0) != 0) failure = 1;
    if (raw_syscall2(SYS_close, resources->pipe[0], 0) != 0 && !failure)
        failure = 2;
    if (raw_syscall2(SYS_close, resources->pipe[1], 0) != 0 && !failure)
        failure = 3;
    if (raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)resources->path, 0) != 0)
        if (!failure) failure = 4;
    return failure;
}

static int check_live_configuration_contract(const struct fixture_resources *resources)
{
    errno = E2BIG;
    if (pathconf(resources->path, _PC_NAME_MAX) != 255 || errno != E2BIG)
        return 1;
    if (fpathconf(resources->file, _PC_PIPE_BUF) != 4096 || errno != E2BIG)
        return 2;
    if (fpathconf(resources->pipe[0], _PC_PIPE_BUF) != 4096 || errno != E2BIG)
        return 3;
    if (fpathconf(resources->pipe[1], _PC_NAME_MAX) != 255 || errno != E2BIG)
        return 4;
    if (fpathconf(resources->closed, _PC_LINK_MAX) != 8 || errno != E2BIG)
        return 5;

    errno = 0;
    if (fpathconf(resources->pipe[0], _PC_ASYNC_IO) != -1 || errno != 0)
        return 6;
    errno = 0;
    if (pathconf(resources->path, _PC_SYMLINK_MAX) != -1 || errno != 0)
        return 7;
    errno = 0;
    if (pathconf(resources->path, 21) != -1 || errno != EINVAL)
        return 8;
    errno = 0;
    if (fpathconf(resources->pipe[1], INT_MAX) != -1 || errno != EINVAL)
        return 9;
    return 0;
}

static int emit_configuration_observations(const struct fixture_resources *resources)
{
    static const int sysconf_names[] = { _SC_CLK_TCK, _SC_PAGE_SIZE, INT_MAX };
    static const int invalid_path_names[] = { 21, INT_MAX };
    static const int confstr_names[] = {
        _CS_PATH, _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS,
        _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS,
        _CS_POSIX_V6_ILP32_OFF32_CFLAGS, _CS_POSIX_V7_THREADS_LDFLAGS,
        -1, 2, 1152, INT_MAX,
    };
    static const size_t confstr_lengths[] = { 0, 1, 4, 16 };
    static const char absent_path[] = "/crabc-configuration-absent";
    struct observation record;
    unsigned int i, variant;

    for (i = 0; i < sizeof sysconf_names / sizeof sysconf_names[0]; ++i) {
        record = (struct observation){ 0 };
        record.selector = sysconf_names[i];
        record.variant = 1;
        errno = E2BIG;
        record.result = sysconf(sysconf_names[i]);
        record.error = errno;
        if (emit(&record)) return 1;
    }
    for (i = 0; i < 21 + sizeof invalid_path_names / sizeof invalid_path_names[0]; ++i) {
        int name = i < 21 ? (int)i : invalid_path_names[i - 21];
        for (variant = 0; variant < 9; ++variant) {
            record = (struct observation){ 0 };
            record.selector = name;
            record.variant = 10 + variant;
            errno = E2BIG;
            switch (variant) {
            case 0: record.result = pathconf(NULL, name); break;
            case 1: record.result = pathconf(absent_path, name); break;
            case 2: record.result = fpathconf(-1, name); break;
            case 3: record.result = fpathconf(9999, name); break;
            case 4: record.result = pathconf(resources->path, name); break;
            case 5: record.result = fpathconf(resources->file, name); break;
            case 6: record.result = fpathconf(resources->pipe[0], name); break;
            case 7: record.result = fpathconf(resources->pipe[1], name); break;
            default: record.result = fpathconf(resources->closed, name); break;
            }
            record.error = errno;
            if (emit(&record)) return 2;
        }
    }
    for (i = 0; i < sizeof confstr_names / sizeof confstr_names[0]; ++i) {
        for (variant = 0; variant < sizeof confstr_lengths / sizeof confstr_lengths[0]; ++variant) {
            unsigned int byte;
            record = (struct observation){ 0 };
            record.selector = confstr_names[i];
            record.variant = 20 + variant;
            for (byte = 0; byte < sizeof record.output; ++byte)
                record.output[byte] = 0xa5;
            errno = E2BIG;
            record.result = (long)confstr(confstr_names[i],
                (char *)record.output, confstr_lengths[variant]);
            record.error = errno;
            if (emit(&record)) return 3;
        }
    }
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
    struct fixture_resources resources = { 0 };
    int cleanup;
    int status = check_common_contract();

    if (status != 0)
        return 10 + status;
    status = check_musl_configuration_contract();
    if (status != 0)
        return 100 + status;
    status = check_pagesize_and_dtable_contract();
    if (status != 0)
        return 200 + status;
    status = open_fixture_resources(&resources);
    if (status != 0)
        return 210 + status;
    status = check_live_configuration_contract(&resources);
    if (status == 0)
        status = emit_configuration_observations(&resources) ? 10 : 0;
    cleanup = close_fixture_resources(&resources);
    if (status != 0)
        return 220 + status;
    return cleanup == 0 ? 0 : 240 + cleanup;
}

#ifndef CRABC_SYSTEM_CONFIGURATION_FREESTANDING
int main(void)
{
    return crabc_x86_64_system_configuration_probe();
}
#endif
