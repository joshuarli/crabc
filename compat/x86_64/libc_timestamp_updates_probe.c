/* Static crabc-libc x86-64 timestamp-update C ABI composition fixture.
 *
 * The exact same project-header body first runs through pinned musl 1.2.6,
 * then through the archive-owned static rcrt1/libc startup path.  It selects
 * the complete timestamp alias/conversion block only: utimensat, futimens,
 * futimes, futimesat, lutimes, utimes, and utime.  Raw Linux calls create and
 * clean the disposable fixture alone; timestamp mutation and observations
 * always use the candidate C API.  This is a bounded non-promoting C-runtime
 * artifact, not a general filesystem/runtime, dynamic libc, loader, sysroot,
 * or public-x86 claim.
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
#include <stddef.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <utime.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_getpid == 39 && SYS_openat == 257 && SYS_mkdirat == 258 &&
    SYS_unlinkat == 263 && SYS_symlinkat == 266 && SYS_close == 3,
    "x86 fixture-only lifecycle syscall numbers");
_Static_assert(SYS_utimensat == 280, "x86 utimensat syscall number");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8 &&
    offsetof(struct timespec, tv_sec) == 0 && offsetof(struct timespec, tv_nsec) == 8,
    "x86 timespec ABI");
_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8 &&
    offsetof(struct timeval, tv_sec) == 0 && offsetof(struct timeval, tv_usec) == 8,
    "x86 timeval ABI");
_Static_assert(sizeof(struct utimbuf) == 16 && _Alignof(struct utimbuf) == 8 &&
    offsetof(struct utimbuf, actime) == 0 && offsetof(struct utimbuf, modtime) == 8,
    "x86 utimbuf ABI");
_Static_assert(sizeof(struct timespec[2]) == 32 && sizeof(struct timeval[2]) == 32,
    "x86 timestamp pair ABI");
_Static_assert(AT_FDCWD == -100 && AT_SYMLINK_NOFOLLOW == 0x100 &&
    UTIME_NOW == 0x3fffffff && UTIME_OMIT == 0x3ffffffe,
    "x86 timestamp constants");

typedef int (*utimensat_signature)(int, const char *, const struct timespec *, int);
typedef int (*futimens_signature)(int, const struct timespec *);
typedef int (*futimes_signature)(int, const struct timeval *);
typedef int (*futimesat_signature)(int, const char *, const struct timeval *);
typedef int (*lutimes_signature)(const char *, const struct timeval *);
typedef int (*utimes_signature)(const char *, const struct timeval *);
typedef int (*utime_signature)(const char *, const struct utimbuf *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&utimensat), utimensat_signature),
    "utimensat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&futimens), futimens_signature),
    "futimens declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&futimes), futimes_signature),
    "futimes declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&futimesat), futimesat_signature),
    "futimesat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lutimes), lutimes_signature),
    "lutimes declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&utimes), utimes_signature),
    "utimes declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&utime), utime_signature),
    "utime declaration");

struct fixture {
    int directory_created;
    int descriptor;
    char directory[96];
    char file[112];
    char link[112];
};

/* Keep one initialized and one TBSS datum in the application PT_TLS image.
 * This is ordinary application TLS, not a test-owned startup shim: rcrt1
 * passes the untouched entry stack to libc, whose Static Initial TLS v1 owner
 * must materialize this final executable image before C `main` can read it. */
static _Thread_local unsigned long crabc_timestamp_initialized_tls = 0x74696d657374616dUL;
static _Thread_local unsigned long crabc_timestamp_zero_tls;

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number) : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(argument1) : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2, long argument3)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3) : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2, long argument3,
    long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(argument1),
        "S"(argument2), "d"(argument3), "r"(register4) : "rcx", "r11", "memory");
    return result;
}

static int append_text(char *output, size_t capacity, size_t *length, const char *text)
{
    size_t index;

    for (index = 0; text[index] != '\0'; ++index) {
        if (*length + 1 >= capacity)
            return -1;
        output[(*length)++] = text[index];
    }
    return 0;
}

static int append_process_id(char *output, size_t capacity, size_t *length, long process_id)
{
    char digits[20];
    size_t digit_count = 0;

    if (process_id <= 0)
        return -1;
    do {
        if (digit_count == sizeof(digits))
            return -1;
        digits[digit_count++] = (char)('0' + process_id % 10);
        process_id /= 10;
    } while (process_id != 0);
    while (digit_count != 0) {
        if (*length + 1 >= capacity)
            return -1;
        output[(*length)++] = digits[--digit_count];
    }
    return 0;
}

static int make_path(char *output, size_t capacity, const char *suffix, long process_id)
{
    static const char prefix[] = "/tmp/crabc-x86-64-timestamp-updates-";
    size_t length = 0;

    if (append_text(output, capacity, &length, prefix) != 0 ||
        append_process_id(output, capacity, &length, process_id) != 0 ||
        append_text(output, capacity, &length, suffix) != 0)
        return -1;
    output[length] = '\0';
    return 0;
}

static int setup_fixture(struct fixture *fixture)
{
    long process_id = raw_syscall0(SYS_getpid);

    fixture->directory_created = 0;
    fixture->descriptor = -1;
    if (make_path(fixture->directory, sizeof(fixture->directory), "", process_id) != 0 ||
        make_path(fixture->file, sizeof(fixture->file), "/file", process_id) != 0 ||
        make_path(fixture->link, sizeof(fixture->link), "/link", process_id) != 0)
        return -1;
    if (raw_syscall3(SYS_mkdirat, AT_FDCWD, (long)(void *)fixture->directory, 0700) != 0)
        return -1;
    fixture->directory_created = 1;
    fixture->descriptor = (int)raw_syscall4(SYS_openat, AT_FDCWD,
        (long)(void *)fixture->file, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fixture->descriptor < 0)
        return -1;
    if (raw_syscall3(SYS_symlinkat, (long)(void *)fixture->file, AT_FDCWD,
            (long)(void *)fixture->link) != 0)
        return -1;
    return 0;
}

static void cleanup_fixture(const struct fixture *fixture)
{
    if (fixture->descriptor >= 0)
        (void)raw_syscall1(SYS_close, fixture->descriptor);
    if (fixture->directory_created) {
        (void)raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)(void *)fixture->link, 0);
        (void)raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)(void *)fixture->file, 0);
        (void)raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)(void *)fixture->directory,
            AT_REMOVEDIR);
    }
}

static int file_has_times(int descriptor, const struct timespec expected[2])
{
    struct stat observed;

    return fstat(descriptor, &observed) == 0 &&
        observed.st_atim.tv_sec == expected[0].tv_sec &&
        observed.st_atim.tv_nsec == expected[0].tv_nsec &&
        observed.st_mtim.tv_sec == expected[1].tv_sec &&
        observed.st_mtim.tv_nsec == expected[1].tv_nsec;
}

static int read_file_times(int descriptor, struct timespec destination[2])
{
    struct stat observed;

    if (fstat(descriptor, &observed) != 0)
        return 0;
    destination[0] = observed.st_atim;
    destination[1] = observed.st_mtim;
    return 1;
}

static int link_has_times(const char *path, const struct timespec expected[2])
{
    struct stat observed;

    return lstat(path, &observed) == 0 &&
        observed.st_atim.tv_sec == expected[0].tv_sec &&
        observed.st_atim.tv_nsec == expected[0].tv_nsec &&
        observed.st_mtim.tv_sec == expected[1].tv_sec &&
        observed.st_mtim.tv_nsec == expected[1].tv_nsec;
}

static int file_keeps_atime_and_changes_mtime(int descriptor,
    const struct timespec previous[2])
{
    struct stat observed;

    return fstat(descriptor, &observed) == 0 &&
        observed.st_atim.tv_sec == previous[0].tv_sec &&
        observed.st_atim.tv_nsec == previous[0].tv_nsec &&
        (observed.st_mtim.tv_sec != previous[1].tv_sec ||
            observed.st_mtim.tv_nsec != previous[1].tv_nsec);
}

static int file_changes_both_times(int descriptor, const struct timespec previous[2])
{
    struct stat observed;

    return fstat(descriptor, &observed) == 0 &&
        (observed.st_atim.tv_sec != previous[0].tv_sec ||
            observed.st_atim.tv_nsec != previous[0].tv_nsec) &&
        (observed.st_mtim.tv_sec != previous[1].tv_sec ||
            observed.st_mtim.tv_nsec != previous[1].tv_nsec);
}

static void timeval_pair_to_timespec(const struct timeval source[2],
    struct timespec destination[2])
{
    size_t index;

    for (index = 0; index != 2; ++index) {
        destination[index].tv_sec = source[index].tv_sec;
        destination[index].tv_nsec = source[index].tv_usec * 1000;
    }
}

int main(void)
{
    static const struct timespec futimens_times[2] = {
        { 1234567, 123456789 }, { 2345678, 987654321 },
    };
    static const struct timespec utimensat_times[2] = {
        { 3456789, 111222333 }, { 4567890, 444555666 },
    };
    static const struct timespec nofollow_times[2] = {
        { 5678901, 222333444 }, { 6789012, 555666777 },
    };
    static const struct timespec omit_now_times[2] = {
        { 0, UTIME_OMIT }, { 0, UTIME_NOW },
    };
    static const struct timespec all_now_times[2] = {
        { 0, UTIME_NOW }, { 0, UTIME_NOW },
    };
    static const struct timespec invalid_timespec[2] = {
        { 1, 0 }, { 2, 1000000000L },
    };
    static const struct timeval futimes_times[2] = {
        { 7890123, 123456 }, { 8901234, 654321 },
    };
    static const struct timeval futimesat_times[2] = {
        { 9012345, 111222 }, { 10123456, 333444 },
    };
    static const struct timeval utimes_times[2] = {
        { 11223344, 222333 }, { 22334455, 444555 },
    };
    static const struct timeval lutimes_times[2] = {
        { 33445566, 555666 }, { 44556677, 777888 },
    };
    static const struct timeval invalid_timeval[2] = {
        { 1, 0 }, { 2, 1000000 },
    };
    static const struct utimbuf utime_times = { 55667788, 66778899 };
    struct fixture fixture;
    struct timespec expected[2];
    struct timespec link_expected[2];
    struct timespec target_before_nofollow[2];
    int status = 0;

    if (crabc_timestamp_initialized_tls != 0x74696d657374616dUL ||
        crabc_timestamp_zero_tls != 0)
        return 20;

    if (setup_fixture(&fixture) != 0)
        return 1;

    errno = E2BIG;
    if (futimens(fixture.descriptor, futimens_times) != 0 || errno != E2BIG ||
        !file_has_times(fixture.descriptor, futimens_times)) {
        status = 2;
        goto finish;
    }
    if (utimensat(AT_FDCWD, fixture.file, utimensat_times, 0) != 0 ||
        !file_has_times(fixture.descriptor, utimensat_times)) {
        status = 3;
        goto finish;
    }
    if (futimes(fixture.descriptor, futimes_times) != 0) {
        status = 4;
        goto finish;
    }
    timeval_pair_to_timespec(futimes_times, expected);
    if (!file_has_times(fixture.descriptor, expected)) {
        status = 5;
        goto finish;
    }
    if (futimesat(AT_FDCWD, fixture.file, futimesat_times) != 0) {
        status = 6;
        goto finish;
    }
    timeval_pair_to_timespec(futimesat_times, expected);
    if (!file_has_times(fixture.descriptor, expected)) {
        status = 7;
        goto finish;
    }
    if (utimes(fixture.file, utimes_times) != 0) {
        status = 8;
        goto finish;
    }
    timeval_pair_to_timespec(utimes_times, expected);
    if (!file_has_times(fixture.descriptor, expected)) {
        status = 9;
        goto finish;
    }
    if (lutimes(fixture.link, lutimes_times) != 0) {
        status = 10;
        goto finish;
    }
    timeval_pair_to_timespec(lutimes_times, link_expected);
    if (!link_has_times(fixture.link, link_expected) ||
        !file_has_times(fixture.descriptor, expected)) {
        status = 11;
        goto finish;
    }
    if (utime(fixture.file, &utime_times) != 0) {
        status = 12;
        goto finish;
    }
    expected[0].tv_sec = utime_times.actime;
    expected[0].tv_nsec = 0;
    expected[1].tv_sec = utime_times.modtime;
    expected[1].tv_nsec = 0;
    if (!file_has_times(fixture.descriptor, expected)) {
        status = 13;
        goto finish;
    }
    if (utimensat(AT_FDCWD, fixture.file, omit_now_times, 0) != 0 ||
        !file_keeps_atime_and_changes_mtime(fixture.descriptor, expected)) {
        status = 14;
        goto finish;
    }
    if (utimensat(AT_FDCWD, fixture.file, all_now_times, 0) != 0 ||
        !file_changes_both_times(fixture.descriptor, expected) ||
        !read_file_times(fixture.descriptor, target_before_nofollow)) {
        status = 15;
        goto finish;
    }
    if (utimensat(AT_FDCWD, fixture.link, nofollow_times, AT_SYMLINK_NOFOLLOW) != 0 ||
        !link_has_times(fixture.link, nofollow_times) ||
        !file_has_times(fixture.descriptor, target_before_nofollow)) {
        status = 16;
        goto finish;
    }

    errno = 0;
    if (utimensat(AT_FDCWD, fixture.file, invalid_timespec, 0) != -1 || errno != EINVAL) {
        status = 17;
        goto finish;
    }
    errno = 0;
    if (futimes(fixture.descriptor, invalid_timeval) != -1 || errno != EINVAL) {
        status = 18;
        goto finish;
    }
    errno = 0;
    if (utimensat(AT_FDCWD, fixture.file, futimens_times, 0x40000000) != -1 ||
        errno != EINVAL) {
        status = 19;
        goto finish;
    }
    errno = 0;
    if (futimens(-1, futimens_times) != -1 || errno != EBADF) {
        status = 21;
        goto finish;
    }
    errno = 0;
    if (utime("/definitely-missing-crabc-x86-64-timestamp", &utime_times) != -1 ||
        errno != ENOENT) {
        status = 22;
        goto finish;
    }

finish:
    cleanup_fixture(&fixture);
    return status;
}
