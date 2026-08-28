/* Pinned-musl/raw Linux/x86-64 timestamp-mutation ABI reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

enum {
    FIXTURE_POSITION = 3,
    PATH_CAPACITY = 512,
};

_Static_assert(SYS_utimensat == 280, "x86 utimensat syscall number");
_Static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
_Static_assert(_Alignof(struct timespec) == 8, "x86 timespec alignment");
_Static_assert(offsetof(struct timespec, tv_sec) == 0,
               "x86 timespec seconds offset");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8,
               "x86 timespec nanoseconds offset");
_Static_assert(sizeof(struct timespec[2]) == 32,
               "x86 utimensat timestamp-pair size");
_Static_assert(sizeof(struct timeval) == 16, "x86 timeval size");
_Static_assert(_Alignof(struct timeval) == 8, "x86 timeval alignment");
_Static_assert(offsetof(struct timeval, tv_sec) == 0,
               "x86 timeval seconds offset");
_Static_assert(offsetof(struct timeval, tv_usec) == 8,
               "x86 timeval microseconds offset");
_Static_assert(sizeof(struct timeval[2]) == 32,
               "x86 legacy timestamp-pair size");
_Static_assert(sizeof(struct utimbuf) == 16, "x86 utimbuf size");
_Static_assert(_Alignof(struct utimbuf) == 8, "x86 utimbuf alignment");
_Static_assert(offsetof(struct utimbuf, actime) == 0,
               "x86 utimbuf access-time offset");
_Static_assert(offsetof(struct utimbuf, modtime) == 8,
               "x86 utimbuf modification-time offset");
_Static_assert((time_t)-1 < (time_t)0, "x86 time_t is signed");
_Static_assert(AT_FDCWD == -100, "Linux AT_FDCWD value");
_Static_assert(AT_SYMLINK_NOFOLLOW == 0x100,
               "Linux AT_SYMLINK_NOFOLLOW value");
_Static_assert(UTIME_NOW == 0x3fffffffL, "Linux UTIME_NOW value");
_Static_assert(UTIME_OMIT == 0x3ffffffeL, "Linux UTIME_OMIT value");

struct call_result {
    long value;
    int error;
};

struct fixture {
    char directory[PATH_CAPACITY];
    char libc_path[PATH_CAPACITY];
    char raw_path[PATH_CAPACITY];
    char libc_target[PATH_CAPACITY];
    char raw_target[PATH_CAPACITY];
    char libc_link[PATH_CAPACITY];
    char raw_link[PATH_CAPACITY];
    char missing_path[PATH_CAPACITY];
    int directory_fd;
    int libc_descriptor;
    int raw_descriptor;
};

/*
 * This fixture intentionally has a relative directory name.  The runner
 * invokes the probe from a disposable work directory, while the probe itself
 * never changes its working directory.  That keeps the AT_FDCWD/utimes case
 * isolated and makes any accidental cwd mutation observable below.
 */
struct relative_fixture {
    char directory[PATH_CAPACITY];
    char libc_path[PATH_CAPACITY];
    char raw_path[PATH_CAPACITY];
};

static struct call_result libc_futimens(int fd,
                                        const struct timespec timestamps[2])
{
    struct call_result result;

    errno = 0;
    result.value = futimens(fd, timestamps);
    result.error = errno;
    return result;
}

static struct call_result libc_utimensat(int dirfd, const char *path,
                                         const struct timespec timestamps[2],
                                         int flags)
{
    struct call_result result;

    errno = 0;
    result.value = utimensat(dirfd, path, timestamps, flags);
    result.error = errno;
    return result;
}

static struct call_result libc_futimes(int fd,
                                       const struct timeval timestamps[2])
{
    struct call_result result;

    errno = 0;
    result.value = futimes(fd, timestamps);
    result.error = errno;
    return result;
}

static struct call_result libc_futimesat(int dirfd, const char *path,
                                         const struct timeval timestamps[2])
{
    struct call_result result;

    errno = 0;
    result.value = futimesat(dirfd, path, timestamps);
    result.error = errno;
    return result;
}

static struct call_result libc_lutimes(const char *path,
                                       const struct timeval timestamps[2])
{
    struct call_result result;

    errno = 0;
    result.value = lutimes(path, timestamps);
    result.error = errno;
    return result;
}

static struct call_result libc_utimes(const char *path,
                                      const struct timeval timestamps[2])
{
    struct call_result result;

    errno = 0;
    result.value = utimes(path, timestamps);
    result.error = errno;
    return result;
}

static struct call_result libc_utime(const char *path,
                                     const struct utimbuf *timestamps)
{
    struct call_result result;

    errno = 0;
    result.value = utime(path, timestamps);
    result.error = errno;
    return result;
}

/*
 * The four Linux arguments are rdi (directory descriptor), rsi (path), rdx
 * (nullable two-timespec array), and r10 (flags).  The descriptor/null-path
 * form is the kernel operation used by futimens and futimes.
 */
static struct call_result raw_utimensat(int dirfd, const char *path,
                                        const struct timespec timestamps[2],
                                        unsigned long flags)
{
    struct call_result result;

    errno = 0;
    result.value = syscall(SYS_utimensat, dirfd, path, timestamps, flags);
    result.error = errno;
    return result;
}

static int same_success(struct call_result libc_result,
                        struct call_result raw_result)
{
    return libc_result.value == 0 && raw_result.value == 0;
}

static int same_error(struct call_result libc_result,
                      struct call_result raw_result, int error)
{
    return libc_result.value == -1 && raw_result.value == -1 &&
           libc_result.error == error && raw_result.error == error;
}

static int raw_success(struct call_result result)
{
    return result.value == 0;
}

static int same_timespec(struct timespec left, struct timespec right)
{
    return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}

static int status_matches(const struct stat *before, const struct stat *after)
{
    return same_timespec(before->st_atim, after->st_atim) &&
           same_timespec(before->st_mtim, after->st_mtim);
}

static int status_matches_times(const struct stat *status,
                                const struct timespec timestamps[2])
{
    return same_timespec(status->st_atim, timestamps[0]) &&
           same_timespec(status->st_mtim, timestamps[1]);
}

static int fd_matches_times(int fd, const struct timespec timestamps[2])
{
    struct stat status;

    return fstat(fd, &status) == 0 && status_matches_times(&status, timestamps);
}

static int path_matches_times(const char *path,
                              const struct timespec timestamps[2], int nofollow)
{
    struct stat status;
    int status_result = nofollow ? lstat(path, &status) : stat(path, &status);

    return status_result == 0 && status_matches_times(&status, timestamps);
}

static int path_mtime_matches(const char *path, struct timespec timestamp,
                              int nofollow)
{
    struct stat status;
    int status_result = nofollow ? lstat(path, &status) : stat(path, &status);

    return status_result == 0 && same_timespec(status.st_mtim, timestamp);
}

static int timestamp_is_current(struct timespec timestamp, time_t before,
                                time_t after)
{
    /* Filesystems may expose coarser-than-nanosecond timestamp precision. */
    return timestamp.tv_sec >= before - 2 && timestamp.tv_sec <= after + 2;
}

static int fd_is_current(int fd, time_t before, time_t after)
{
    struct stat status;

    return fstat(fd, &status) == 0 &&
           timestamp_is_current(status.st_atim, before, after) &&
           timestamp_is_current(status.st_mtim, before, after);
}

static int path_is_current(const char *path, int nofollow, time_t before,
                           time_t after)
{
    struct stat status;
    int status_result = nofollow ? lstat(path, &status) : stat(path, &status);

    return status_result == 0 &&
           timestamp_is_current(status.st_atim, before, after) &&
           timestamp_is_current(status.st_mtim, before, after);
}

static void timeval_pair_to_timespec(const struct timeval source[2],
                                     struct timespec destination[2])
{
    size_t index;

    for (index = 0; index < 2; ++index) {
        destination[index].tv_sec = source[index].tv_sec;
        destination[index].tv_nsec = source[index].tv_usec * 1000;
    }
}

static void utimbuf_to_timespec(const struct utimbuf *source,
                                struct timespec destination[2])
{
    destination[0].tv_sec = source->actime;
    destination[0].tv_nsec = 0;
    destination[1].tv_sec = source->modtime;
    destination[1].tv_nsec = 0;
}

static int fixture_path(char destination[PATH_CAPACITY], const char *directory,
                        const char *name)
{
    int length = snprintf(destination, PATH_CAPACITY, "%s/%s", directory, name);

    return length >= 0 && (size_t)length < PATH_CAPACITY;
}

static int create_regular_at(int dirfd, const char *name)
{
    static const unsigned char payload[] = "timestamp-fixture";
    int fd;

    fd = openat(dirfd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload) ||
        lseek(fd, FIXTURE_POSITION, SEEK_SET) != (off_t)FIXTURE_POSITION) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static void cleanup_fixture(struct fixture *fixture)
{
    if (fixture->libc_descriptor >= 0)
        (void)close(fixture->libc_descriptor);
    if (fixture->raw_descriptor >= 0)
        (void)close(fixture->raw_descriptor);
    if (fixture->directory_fd >= 0) {
        (void)unlinkat(fixture->directory_fd, "libc-link", 0);
        (void)unlinkat(fixture->directory_fd, "raw-link", 0);
        (void)unlinkat(fixture->directory_fd, "libc-target", 0);
        (void)unlinkat(fixture->directory_fd, "raw-target", 0);
        (void)unlinkat(fixture->directory_fd, "libc-path", 0);
        (void)unlinkat(fixture->directory_fd, "raw-path", 0);
        (void)unlinkat(fixture->directory_fd, "libc-descriptor", 0);
        (void)unlinkat(fixture->directory_fd, "raw-descriptor", 0);
        (void)close(fixture->directory_fd);
    }
    if (fixture->directory[0] != '\0')
        (void)rmdir(fixture->directory);
}

static int initialize_fixture(struct fixture *fixture)
{
    int fd;

    memset(fixture, 0, sizeof(*fixture));
    fixture->directory_fd = -1;
    fixture->libc_descriptor = -1;
    fixture->raw_descriptor = -1;
    if (snprintf(fixture->directory, sizeof(fixture->directory),
                 "/tmp/crabc-x86-timestamp-XXXXXX") < 0 ||
        !mkdtemp(fixture->directory))
        return -1;
    if (!fixture_path(fixture->libc_path, fixture->directory, "libc-path") ||
        !fixture_path(fixture->raw_path, fixture->directory, "raw-path") ||
        !fixture_path(fixture->libc_target, fixture->directory, "libc-target") ||
        !fixture_path(fixture->raw_target, fixture->directory, "raw-target") ||
        !fixture_path(fixture->libc_link, fixture->directory, "libc-link") ||
        !fixture_path(fixture->raw_link, fixture->directory, "raw-link") ||
        !fixture_path(fixture->missing_path, fixture->directory, "missing"))
        goto failure;

    fixture->directory_fd =
        open(fixture->directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fixture->directory_fd < 0)
        goto failure;

    fixture->libc_descriptor =
        create_regular_at(fixture->directory_fd, "libc-descriptor");
    fixture->raw_descriptor =
        create_regular_at(fixture->directory_fd, "raw-descriptor");
    if (fixture->libc_descriptor < 0 || fixture->raw_descriptor < 0 ||
        unlinkat(fixture->directory_fd, "libc-descriptor", 0) != 0 ||
        unlinkat(fixture->directory_fd, "raw-descriptor", 0) != 0)
        goto failure;

    fd = create_regular_at(fixture->directory_fd, "libc-path");
    if (fd < 0 || close(fd) != 0)
        goto failure;
    fd = create_regular_at(fixture->directory_fd, "raw-path");
    if (fd < 0 || close(fd) != 0)
        goto failure;
    fd = create_regular_at(fixture->directory_fd, "libc-target");
    if (fd < 0 || close(fd) != 0)
        goto failure;
    fd = create_regular_at(fixture->directory_fd, "raw-target");
    if (fd < 0 || close(fd) != 0)
        goto failure;
    if (symlinkat("libc-target", fixture->directory_fd, "libc-link") != 0 ||
        symlinkat("raw-target", fixture->directory_fd, "raw-link") != 0)
        goto failure;
    return 0;

failure:
    cleanup_fixture(fixture);
    return -1;
}

static void cleanup_relative_fixture(struct relative_fixture *fixture)
{
    if (fixture->libc_path[0] != '\0')
        (void)unlink(fixture->libc_path);
    if (fixture->raw_path[0] != '\0')
        (void)unlink(fixture->raw_path);
    if (fixture->directory[0] != '\0')
        (void)rmdir(fixture->directory);
}

static int initialize_relative_fixture(struct relative_fixture *fixture)
{
    int fd;

    memset(fixture, 0, sizeof(*fixture));
    if (snprintf(fixture->directory, sizeof(fixture->directory),
                 "crabc-x86-timestamp-relative-XXXXXX") < 0 ||
        !mkdtemp(fixture->directory))
        return -1;
    if (!fixture_path(fixture->libc_path, fixture->directory, "libc-path") ||
        !fixture_path(fixture->raw_path, fixture->directory, "raw-path"))
        goto failure;

    fd = create_regular_at(AT_FDCWD, fixture->libc_path);
    if (fd < 0 || close(fd) != 0)
        goto failure;
    fd = create_regular_at(AT_FDCWD, fixture->raw_path);
    if (fd < 0 || close(fd) != 0)
        goto failure;
    return 0;

failure:
    cleanup_relative_fixture(fixture);
    return -1;
}

int main(void)
{
    static const struct timespec futimens_explicit[2] = {
        {.tv_sec = 1234567, .tv_nsec = 123456789},
        {.tv_sec = 2345678, .tv_nsec = 987654321},
    };
    static const struct timespec now_omit[2] = {
        {.tv_sec = 0, .tv_nsec = UTIME_OMIT},
        {.tv_sec = 0, .tv_nsec = UTIME_NOW},
    };
    static const struct timespec invalid_timespec[2] = {
        {.tv_sec = 1234567, .tv_nsec = 123456789},
        {.tv_sec = 0, .tv_nsec = 1000000000L},
    };
    static const struct timespec utimensat_explicit[2] = {
        {.tv_sec = 2456789, .tv_nsec = 135791357},
        {.tv_sec = 3567890, .tv_nsec = 246802468},
    };
    static const struct timespec utimensat_nofollow[2] = {
        {.tv_sec = 4678901, .tv_nsec = 112358132},
        {.tv_sec = 5789012, .tv_nsec = 314159265},
    };
    static const struct timeval futimes_explicit[2] = {
        {.tv_sec = 3456789, .tv_usec = 123456},
        {.tv_sec = 4567890, .tv_usec = 654321},
    };
    static const struct timeval futimesat_explicit[2] = {
        {.tv_sec = 5678901, .tv_usec = 111222},
        {.tv_sec = 6789012, .tv_usec = 333444},
    };
    static const struct timeval utimes_explicit[2] = {
        {.tv_sec = 7890123, .tv_usec = 555666},
        {.tv_sec = 8901234, .tv_usec = 777888},
    };
    static const struct timeval lutimes_explicit[2] = {
        {.tv_sec = 9012345, .tv_usec = 222333},
        {.tv_sec = 10123456, .tv_usec = 444555},
    };
    static const struct timeval invalid_timeval[2] = {
        {.tv_sec = 3456789, .tv_usec = 1000000},
        {.tv_sec = 4567890, .tv_usec = 0},
    };
    static const struct timespec target_baseline[2] = {
        {.tv_sec = 1111111, .tv_nsec = 111111111},
        {.tv_sec = 2222222, .tv_nsec = 222222222},
    };
    static const struct timespec link_baseline[2] = {
        {.tv_sec = 3333333, .tv_nsec = 333333333},
        {.tv_sec = 4444444, .tv_nsec = 444444444},
    };
    static const struct utimbuf utime_explicit = {
        .actime = 11223344,
        .modtime = 22334455,
    };
    struct fixture fixture;
    struct relative_fixture relative_fixture;
    struct call_result libc_result;
    struct call_result raw_result;
    struct stat libc_before_error;
    struct stat raw_before_error;
    struct stat libc_after;
    struct stat raw_after;
    struct timespec futimes_timespec[2];
    struct timespec futimesat_timespec[2];
    struct timespec utimes_timespec[2];
    struct timespec lutimes_timespec[2];
    struct timespec invalid_timeval_timespec[2];
    struct timespec utime_timespec[2];
    struct timespec before_now;
    struct timespec after_now;
    char cwd_before[PATH_CAPACITY];
    char cwd_after[PATH_CAPACITY];
    int closed_fd = -1;
    int result = 0;

    timeval_pair_to_timespec(futimes_explicit, futimes_timespec);
    timeval_pair_to_timespec(futimesat_explicit, futimesat_timespec);
    timeval_pair_to_timespec(utimes_explicit, utimes_timespec);
    timeval_pair_to_timespec(lutimes_explicit, lutimes_timespec);
    timeval_pair_to_timespec(invalid_timeval, invalid_timeval_timespec);
    utimbuf_to_timespec(&utime_explicit, utime_timespec);
    memset(&relative_fixture, 0, sizeof(relative_fixture));

    if (initialize_fixture(&fixture) != 0)
        return 10;

    libc_result = libc_futimens(fixture.libc_descriptor, futimens_explicit);
    raw_result = raw_utimensat(fixture.raw_descriptor, NULL, futimens_explicit, 0);
    if (!same_success(libc_result, raw_result) ||
        !fd_matches_times(fixture.libc_descriptor, futimens_explicit) ||
        !fd_matches_times(fixture.raw_descriptor, futimens_explicit) ||
        lseek(fixture.libc_descriptor, 0, SEEK_CUR) != (off_t)FIXTURE_POSITION ||
        lseek(fixture.raw_descriptor, 0, SEEK_CUR) != (off_t)FIXTURE_POSITION) {
        result = 11;
        goto cleanup;
    }

    if (clock_gettime(CLOCK_REALTIME, &before_now) != 0) {
        result = 12;
        goto cleanup;
    }
    libc_result = libc_futimens(fixture.libc_descriptor, now_omit);
    raw_result = raw_utimensat(fixture.raw_descriptor, NULL, now_omit, 0);
    if (clock_gettime(CLOCK_REALTIME, &after_now) != 0 ||
        !same_success(libc_result, raw_result) ||
        fstat(fixture.libc_descriptor, &libc_after) != 0 ||
        fstat(fixture.raw_descriptor, &raw_after) != 0 ||
        !same_timespec(libc_after.st_atim, futimens_explicit[0]) ||
        !same_timespec(raw_after.st_atim, futimens_explicit[0]) ||
        !timestamp_is_current(libc_after.st_mtim, before_now.tv_sec,
                              after_now.tv_sec) ||
        !timestamp_is_current(raw_after.st_mtim, before_now.tv_sec,
                              after_now.tv_sec)) {
        result = 13;
        goto cleanup;
    }

    if (clock_gettime(CLOCK_REALTIME, &before_now) != 0) {
        result = 14;
        goto cleanup;
    }
    libc_result = libc_futimens(fixture.libc_descriptor, NULL);
    raw_result = raw_utimensat(fixture.raw_descriptor, NULL, NULL, 0);
    if (clock_gettime(CLOCK_REALTIME, &after_now) != 0 ||
        !same_success(libc_result, raw_result) ||
        !fd_is_current(fixture.libc_descriptor, before_now.tv_sec,
                       after_now.tv_sec) ||
        !fd_is_current(fixture.raw_descriptor, before_now.tv_sec,
                       after_now.tv_sec)) {
        result = 15;
        goto cleanup;
    }

    if (fstat(fixture.libc_descriptor, &libc_before_error) != 0 ||
        fstat(fixture.raw_descriptor, &raw_before_error) != 0) {
        result = 16;
        goto cleanup;
    }
    libc_result = libc_futimens(fixture.libc_descriptor, invalid_timespec);
    raw_result = raw_utimensat(fixture.raw_descriptor, NULL, invalid_timespec, 0);
    if (!same_error(libc_result, raw_result, EINVAL) ||
        fstat(fixture.libc_descriptor, &libc_after) != 0 ||
        fstat(fixture.raw_descriptor, &raw_after) != 0 ||
        !status_matches(&libc_before_error, &libc_after) ||
        !status_matches(&raw_before_error, &raw_after)) {
        result = 17;
        goto cleanup;
    }

    raw_result = raw_utimensat(fixture.raw_descriptor, NULL, futimens_explicit,
                                0x80000000UL);
    if (raw_result.value != -1 || raw_result.error != EINVAL ||
        fstat(fixture.raw_descriptor, &raw_after) != 0 ||
        !status_matches(&raw_before_error, &raw_after)) {
        result = 18;
        goto cleanup;
    }

    closed_fd = dup(fixture.libc_descriptor);
    if (closed_fd < 0 || close(closed_fd) != 0) {
        result = 19;
        goto cleanup;
    }
    libc_result = libc_futimens(closed_fd, futimens_explicit);
    raw_result = raw_utimensat(closed_fd, NULL, futimens_explicit, 0);
    if (!same_error(libc_result, raw_result, EBADF)) {
        result = 20;
        goto cleanup;
    }
    closed_fd = -1;

    libc_result = libc_futimes(fixture.libc_descriptor, futimes_explicit);
    raw_result = raw_utimensat(fixture.raw_descriptor, NULL, futimes_timespec, 0);
    if (!same_success(libc_result, raw_result) ||
        !fd_matches_times(fixture.libc_descriptor, futimes_timespec) ||
        !fd_matches_times(fixture.raw_descriptor, futimes_timespec) ||
        lseek(fixture.libc_descriptor, 0, SEEK_CUR) != (off_t)FIXTURE_POSITION ||
        lseek(fixture.raw_descriptor, 0, SEEK_CUR) != (off_t)FIXTURE_POSITION) {
        result = 21;
        goto cleanup;
    }

    if (clock_gettime(CLOCK_REALTIME, &before_now) != 0) {
        result = 22;
        goto cleanup;
    }
    libc_result = libc_futimes(fixture.libc_descriptor, NULL);
    raw_result = raw_utimensat(fixture.raw_descriptor, NULL, NULL, 0);
    if (clock_gettime(CLOCK_REALTIME, &after_now) != 0 ||
        !same_success(libc_result, raw_result) ||
        !fd_is_current(fixture.libc_descriptor, before_now.tv_sec,
                       after_now.tv_sec) ||
        !fd_is_current(fixture.raw_descriptor, before_now.tv_sec,
                       after_now.tv_sec)) {
        result = 23;
        goto cleanup;
    }

    if (fstat(fixture.libc_descriptor, &libc_before_error) != 0 ||
        fstat(fixture.raw_descriptor, &raw_before_error) != 0) {
        result = 24;
        goto cleanup;
    }
    libc_result = libc_futimes(fixture.libc_descriptor, invalid_timeval);
    raw_result = raw_utimensat(fixture.raw_descriptor, NULL,
                                invalid_timeval_timespec, 0);
    if (!same_error(libc_result, raw_result, EINVAL) ||
        fstat(fixture.libc_descriptor, &libc_after) != 0 ||
        fstat(fixture.raw_descriptor, &raw_after) != 0 ||
        !status_matches(&libc_before_error, &libc_after) ||
        !status_matches(&raw_before_error, &raw_after)) {
        result = 25;
        goto cleanup;
    }

    libc_result = libc_futimesat(fixture.directory_fd, "libc-path",
                                 futimesat_explicit);
    raw_result = raw_utimensat(fixture.directory_fd, "raw-path",
                                futimesat_timespec, 0);
    if (!same_success(libc_result, raw_result) ||
        !path_matches_times(fixture.libc_path, futimesat_timespec, 0) ||
        !path_matches_times(fixture.raw_path, futimesat_timespec, 0)) {
        result = 26;
        goto cleanup;
    }

    if (clock_gettime(CLOCK_REALTIME, &before_now) != 0) {
        result = 27;
        goto cleanup;
    }
    libc_result = libc_futimesat(fixture.directory_fd, "libc-path", NULL);
    raw_result = raw_utimensat(fixture.directory_fd, "raw-path", NULL, 0);
    if (clock_gettime(CLOCK_REALTIME, &after_now) != 0 ||
        !same_success(libc_result, raw_result) ||
        !path_is_current(fixture.libc_path, 0, before_now.tv_sec,
                         after_now.tv_sec) ||
        !path_is_current(fixture.raw_path, 0, before_now.tv_sec,
                         after_now.tv_sec)) {
        result = 28;
        goto cleanup;
    }

    libc_result = libc_futimesat(-1, "libc-path", futimesat_explicit);
    raw_result = raw_utimensat(-1, "raw-path", futimesat_timespec, 0);
    if (!same_error(libc_result, raw_result, EBADF)) {
        result = 29;
        goto cleanup;
    }

    libc_result = libc_utimensat(fixture.directory_fd, "libc-path",
                                 utimensat_explicit, 0);
    raw_result = raw_utimensat(fixture.directory_fd, "raw-path",
                                utimensat_explicit, 0);
    if (!same_success(libc_result, raw_result) ||
        !path_matches_times(fixture.libc_path, utimensat_explicit, 0) ||
        !path_matches_times(fixture.raw_path, utimensat_explicit, 0)) {
        result = 41;
        goto cleanup;
    }

    if (!raw_success(raw_utimensat(AT_FDCWD, fixture.libc_target,
                                   target_baseline, 0)) ||
        !raw_success(raw_utimensat(AT_FDCWD, fixture.raw_target,
                                   target_baseline, 0)) ||
        !raw_success(raw_utimensat(AT_FDCWD, fixture.libc_link,
                                   link_baseline, AT_SYMLINK_NOFOLLOW)) ||
        !raw_success(raw_utimensat(AT_FDCWD, fixture.raw_link,
                                   link_baseline, AT_SYMLINK_NOFOLLOW))) {
        result = 30;
        goto cleanup;
    }

    libc_result = libc_utimes(fixture.libc_link, utimes_explicit);
    raw_result = raw_utimensat(AT_FDCWD, fixture.raw_link, utimes_timespec, 0);
    if (!same_success(libc_result, raw_result) ||
        !path_matches_times(fixture.libc_target, utimes_timespec, 0) ||
        !path_matches_times(fixture.raw_target, utimes_timespec, 0) ||
        !path_mtime_matches(fixture.libc_link, link_baseline[1], 1) ||
        !path_mtime_matches(fixture.raw_link, link_baseline[1], 1)) {
        result = 31;
        goto cleanup;
    }

    libc_result = libc_lutimes(fixture.libc_link, lutimes_explicit);
    raw_result = raw_utimensat(AT_FDCWD, fixture.raw_link, lutimes_timespec,
                                AT_SYMLINK_NOFOLLOW);
    if (!same_success(libc_result, raw_result) ||
        !path_matches_times(fixture.libc_link, lutimes_timespec, 1) ||
        !path_matches_times(fixture.raw_link, lutimes_timespec, 1) ||
        !path_matches_times(fixture.libc_target, utimes_timespec, 0) ||
        !path_matches_times(fixture.raw_target, utimes_timespec, 0)) {
        result = 32;
        goto cleanup;
    }

    libc_result = libc_utimensat(AT_FDCWD, fixture.libc_link,
                                 utimensat_nofollow, AT_SYMLINK_NOFOLLOW);
    raw_result = raw_utimensat(AT_FDCWD, fixture.raw_link,
                                utimensat_nofollow, AT_SYMLINK_NOFOLLOW);
    if (!same_success(libc_result, raw_result) ||
        !path_matches_times(fixture.libc_link, utimensat_nofollow, 1) ||
        !path_matches_times(fixture.raw_link, utimensat_nofollow, 1) ||
        !path_matches_times(fixture.libc_target, utimes_timespec, 0) ||
        !path_matches_times(fixture.raw_target, utimes_timespec, 0)) {
        result = 42;
        goto cleanup;
    }

    if (clock_gettime(CLOCK_REALTIME, &before_now) != 0) {
        result = 33;
        goto cleanup;
    }
    libc_result = libc_lutimes(fixture.libc_link, NULL);
    raw_result = raw_utimensat(AT_FDCWD, fixture.raw_link, NULL,
                                AT_SYMLINK_NOFOLLOW);
    if (clock_gettime(CLOCK_REALTIME, &after_now) != 0 ||
        !same_success(libc_result, raw_result) ||
        !path_is_current(fixture.libc_link, 1, before_now.tv_sec,
                         after_now.tv_sec) ||
        !path_is_current(fixture.raw_link, 1, before_now.tv_sec,
                         after_now.tv_sec) ||
        !path_matches_times(fixture.libc_target, utimes_timespec, 0) ||
        !path_matches_times(fixture.raw_target, utimes_timespec, 0)) {
        result = 34;
        goto cleanup;
    }

    if (clock_gettime(CLOCK_REALTIME, &before_now) != 0) {
        result = 35;
        goto cleanup;
    }
    libc_result = libc_utimes(fixture.libc_link, NULL);
    raw_result = raw_utimensat(AT_FDCWD, fixture.raw_link, NULL, 0);
    if (clock_gettime(CLOCK_REALTIME, &after_now) != 0 ||
        !same_success(libc_result, raw_result) ||
        !path_is_current(fixture.libc_target, 0, before_now.tv_sec,
                         after_now.tv_sec) ||
        !path_is_current(fixture.raw_target, 0, before_now.tv_sec,
                         after_now.tv_sec)) {
        result = 36;
        goto cleanup;
    }

    libc_result = libc_utime(fixture.libc_path, &utime_explicit);
    raw_result = raw_utimensat(AT_FDCWD, fixture.raw_path, utime_timespec, 0);
    if (!same_success(libc_result, raw_result) ||
        !path_matches_times(fixture.libc_path, utime_timespec, 0) ||
        !path_matches_times(fixture.raw_path, utime_timespec, 0)) {
        result = 37;
        goto cleanup;
    }

    if (clock_gettime(CLOCK_REALTIME, &before_now) != 0) {
        result = 38;
        goto cleanup;
    }
    libc_result = libc_utime(fixture.libc_path, NULL);
    raw_result = raw_utimensat(AT_FDCWD, fixture.raw_path, NULL, 0);
    if (clock_gettime(CLOCK_REALTIME, &after_now) != 0 ||
        !same_success(libc_result, raw_result) ||
        !path_is_current(fixture.libc_path, 0, before_now.tv_sec,
                         after_now.tv_sec) ||
        !path_is_current(fixture.raw_path, 0, before_now.tv_sec,
                         after_now.tv_sec)) {
        result = 39;
        goto cleanup;
    }

    libc_result = libc_utimes(fixture.missing_path, utimes_explicit);
    raw_result = raw_utimensat(AT_FDCWD, fixture.missing_path,
                                utimes_timespec, 0);
    if (!same_error(libc_result, raw_result, ENOENT)) {
        result = 40;
        goto cleanup;
    }

    if (getcwd(cwd_before, sizeof(cwd_before)) == NULL ||
        initialize_relative_fixture(&relative_fixture) != 0) {
        result = 43;
        goto cleanup;
    }
    libc_result = libc_utimes(relative_fixture.libc_path, utimes_explicit);
    raw_result = raw_utimensat(AT_FDCWD, relative_fixture.raw_path,
                                utimes_timespec, 0);
    if (!same_success(libc_result, raw_result) ||
        !path_matches_times(relative_fixture.libc_path, utimes_timespec, 0) ||
        !path_matches_times(relative_fixture.raw_path, utimes_timespec, 0) ||
        getcwd(cwd_after, sizeof(cwd_after)) == NULL ||
        strcmp(cwd_before, cwd_after) != 0) {
        result = 44;
        goto cleanup;
    }

cleanup:
    if (closed_fd >= 0)
        (void)close(closed_fd);
    cleanup_relative_fixture(&relative_fixture);
    cleanup_fixture(&fixture);
    if (result != 0)
        return result;

    puts("syscall=280 abi=syscall4:rdi,rsi,rdx,r10 "
         "records=timespec2x16-align8:timeval2x16-align8:utimbuf16 "
         "descriptor=null-path=futimens:futimes "
         "legacy=futimes:futimesat:lutimes:utimes:utime "
         "direct-utimensat=normal:nofollow "
         "explicit=exact null=current sentinels=now-omit "
         "nofollow=link-not-target:AT_SYMLINK_NOFOLLOW=0x100 position=stable "
         "raw=matches-musl "
         "errors=EINVAL:timespec|timeval|unknown-flags,EBADF:closed|dirfd,ENOENT:missing "
         "c-api-selection=excluded cwd=unchanged:relative-utimes-AT_FDCWD");
    return 0;
}
