/* Static crabc-libc x86-64 selected descriptor-lifecycle composition fixture.
 *
 * One project-header C body runs first through pinned musl 1.2.6, then as a
 * freestanding static executable linked solely with the selected crabc
 * `libc.a`.  It composes only open/openat/creat, the selected fcntl forms,
 * scalar descriptor I/O and positioning, fstat/fstatat, duplication,
 * truncation/synchronization, close, and direct errno/TLS results.  Raw Linux
 * syscalls own only the PID-specific temporary directory's entry/cleanup;
 * they never stand in for a candidate C descriptor operation.  This is one
 * non-promoting static composition artifact, not a general C runtime,
 * filesystem-policy, cancellation, CRT, loader, sysroot, or public x86 claim.
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
#include <sys/types.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(int) == 4 && sizeof(mode_t) == 4 && sizeof(off_t) == 8 &&
    sizeof(ssize_t) == 8 && sizeof(struct stat) == 144,
    "x86 descriptor lifecycle layouts");
_Static_assert(SYS_close == 3 && SYS_getpid == 39 && SYS_mkdirat == 258 &&
    SYS_unlinkat == 263, "x86 fixture-only lifecycle syscall numbers");
_Static_assert(O_RDONLY == 0 && O_WRONLY == 1 && O_RDWR == 2 &&
    O_CREAT == 0100 && O_EXCL == 0200 && O_TRUNC == 01000 &&
    O_APPEND == 02000 && O_CLOEXEC == 02000000 && O_DIRECTORY == 0200000 &&
    O_LARGEFILE == 0100000, "x86 selected descriptor flags");
_Static_assert(F_GETFD == 1 && F_SETFD == 2 && F_GETFL == 3 && F_SETFL == 4 &&
    FD_CLOEXEC == 1 && AT_FDCWD == -100 && AT_REMOVEDIR == 0x200,
    "x86 selected descriptor constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&open),
    int (*)(const char *, int, ...)), "open declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&openat),
    int (*)(int, const char *, int, ...)), "openat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&creat),
    int (*)(const char *, mode_t)), "creat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fcntl),
    int (*)(int, int, ...)), "fcntl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&read),
    ssize_t (*)(int, void *, size_t)), "read declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&write),
    ssize_t (*)(int, const void *, size_t)), "write declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pread),
    ssize_t (*)(int, void *, size_t, off_t)), "pread declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pwrite),
    ssize_t (*)(int, const void *, size_t, off_t)), "pwrite declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstat),
    int (*)(int, struct stat *)), "fstat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstatat),
    int (*)(int, const char *, struct stat *, int)), "fstatat declaration");

struct fixture_paths {
    int created;
    char directory[88];
    char primary_path[104];
    char created_path[104];
    char third_path[104];
};

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

static int make_path(char *output, size_t capacity, const char *prefix,
    long process_id, const char *suffix)
{
    char digits[20];
    size_t length = 0;
    size_t digit_count = 0;
    size_t index;

    if (process_id <= 0)
        return -1;
    for (index = 0; prefix[index] != '\0'; ++index) {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = prefix[index];
    }
    do {
        if (digit_count == sizeof(digits))
            return -1;
        digits[digit_count++] = (char)('0' + process_id % 10);
        process_id /= 10;
    } while (process_id != 0);
    while (digit_count != 0) {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = digits[--digit_count];
    }
    for (index = 0; suffix[index] != '\0'; ++index) {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = suffix[index];
    }
    output[length] = '\0';
    return 0;
}

static int setup_paths(struct fixture_paths *paths)
{
    static const char prefix[] = "/tmp/crabc-x86-64-descriptor-lifecycle-";
    long process_id = raw_syscall0(SYS_getpid);

    paths->created = 0;
    if (make_path(paths->directory, sizeof(paths->directory), prefix, process_id, "") != 0 ||
        make_path(paths->primary_path, sizeof(paths->primary_path), prefix, process_id,
            "/primary") != 0 ||
        make_path(paths->created_path, sizeof(paths->created_path), prefix, process_id,
            "/created") != 0 ||
        make_path(paths->third_path, sizeof(paths->third_path), prefix, process_id,
            "/third") != 0)
        return -1;
    if (raw_syscall3(SYS_mkdirat, AT_FDCWD, (long)(void *)paths->directory, 0700) != 0)
        return -1;
    paths->created = 1;
    return 0;
}

static int cleanup_paths(const struct fixture_paths *paths, int directory_fd,
    int primary, int duplicate, int target, int third)
{
    int status = 0;

    /* This raw close-only failure cleanup is outside the selected C evidence. */
    if (third >= 0 && raw_syscall1(SYS_close, third) != 0)
        status = -1;
    if (target >= 0 && raw_syscall1(SYS_close, target) != 0)
        status = -1;
    if (duplicate >= 0 && raw_syscall1(SYS_close, duplicate) != 0)
        status = -1;
    if (primary >= 0 && raw_syscall1(SYS_close, primary) != 0)
        status = -1;
    if (directory_fd >= 0 && raw_syscall1(SYS_close, directory_fd) != 0)
        status = -1;
    if (paths->created) {
        (void)raw_syscall3(SYS_unlinkat, AT_FDCWD,
            (long)(void *)paths->primary_path, 0);
        (void)raw_syscall3(SYS_unlinkat, AT_FDCWD,
            (long)(void *)paths->created_path, 0);
        (void)raw_syscall3(SYS_unlinkat, AT_FDCWD,
            (long)(void *)paths->third_path, 0);
        if (raw_syscall3(SYS_unlinkat, AT_FDCWD,
                (long)(void *)paths->directory, AT_REMOVEDIR) != 0)
            status = -1;
    }
    return status;
}

static int bytes_equal(const char *left, const char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

int crabc_x86_64_descriptor_lifecycle_probe(void)
{
    static const char initial[] = "abcd";
    static const char expected[] = "ZbQd";
    struct fixture_paths paths;
    struct stat by_fd;
    struct stat by_relative_path;
    char observed[4];
    char zeros[2];
    int directory_fd = -1;
    int primary = -1;
    int duplicate = -1;
    int target = -1;
    int third = -1;
    int status = 0;
    int cleanup_status;
    int flags;

    if (setup_paths(&paths) != 0)
        return 1;

    errno = E2BIG;
    directory_fd = open(paths.directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0 || errno != E2BIG) {
        status = 2;
        goto finish;
    }
    if (fcntl(directory_fd, F_GETFD) != FD_CLOEXEC) {
        status = 3;
        goto finish;
    }

    errno = ERANGE;
    primary = openat(directory_fd, "primary", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
        0600);
    if (primary < 0 || errno != ERANGE || fcntl(primary, F_GETFD) != FD_CLOEXEC) {
        status = 4;
        goto finish;
    }
    flags = fcntl(primary, F_GETFL);
    if ((flags & O_ACCMODE) != O_RDWR || (flags & O_LARGEFILE) != O_LARGEFILE) {
        status = 5;
        goto finish;
    }
    if (write(primary, initial, sizeof(initial) - 1) != 4 ||
        lseek(primary, 0, SEEK_SET) != 0 ||
        read(primary, observed, sizeof(observed)) != 4 ||
        !bytes_equal(observed, initial, sizeof(observed)) ||
        lseek(primary, 2, SEEK_SET) != 2 ||
        pwrite(primary, "Z", 1, 0) != 1 ||
        lseek(primary, 0, SEEK_CUR) != 2 || write(primary, "Q", 1) != 1 ||
        pread(primary, observed, sizeof(observed), 0) != 4 ||
        !bytes_equal(observed, expected, sizeof(observed)) ||
        lseek(primary, 0, SEEK_CUR) != 3) {
        status = 6;
        goto finish;
    }
    if (ftruncate(primary, 6) != 0 || pread(primary, zeros, sizeof(zeros), 4) != 2 ||
        zeros[0] != 0 || zeros[1] != 0 || fsync(primary) != 0 ||
        fdatasync(primary) != 0 || fstat(primary, &by_fd) != 0 ||
        by_fd.st_size != 6 || (by_fd.st_mode & 0777) != 0600 ||
        fstatat(directory_fd, "primary", &by_relative_path, 0) != 0 ||
        by_relative_path.st_dev != by_fd.st_dev || by_relative_path.st_ino != by_fd.st_ino) {
        status = 7;
        goto finish;
    }

    if (fcntl(primary, F_SETFD, 0) != 0 || fcntl(primary, F_GETFD) != 0 ||
        fcntl(primary, F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(primary, F_GETFD) != FD_CLOEXEC ||
        fcntl(primary, F_SETFL, flags | O_APPEND) != 0) {
        status = 8;
        goto finish;
    }
    duplicate = dup(primary);
    if (duplicate < 0 || fcntl(duplicate, F_GETFD) != 0 ||
        (fcntl(duplicate, F_GETFL) & O_APPEND) == 0) {
        status = 9;
        goto finish;
    }
    target = creat(paths.created_path, 0600);
    if (target < 0 || fstat(target, &by_fd) != 0 || by_fd.st_size != 0 ||
        dup2(duplicate, target) != target || fcntl(target, F_GETFD) != 0) {
        status = 10;
        goto finish;
    }
    third = openat(directory_fd, "third", O_RDWR | O_CREAT | O_EXCL, 0600);
    if (third < 0 || dup3(duplicate, third, O_CLOEXEC) != third ||
        fcntl(third, F_GETFD) != FD_CLOEXEC ||
        (fcntl(third, F_GETFL) & O_APPEND) == 0) {
        status = 11;
        goto finish;
    }
    errno = 0;
    if (dup3(duplicate, duplicate, O_CLOEXEC) != -1 || errno != EINVAL) {
        status = 12;
        goto finish;
    }
    errno = E2BIG;
    if (fstatat(directory_fd, "missing", &by_fd, 0) != -1 || errno != ENOENT ||
        close(primary) != 0) {
        status = 13;
        goto finish;
    }
    primary = -1;
    if (lseek(duplicate, 0, SEEK_SET) != 0 || read(duplicate, observed, 1) != 1 ||
        observed[0] != 'Z' || close(third) != 0 || close(target) != 0 ||
        close(duplicate) != 0 || close(directory_fd) != 0) {
        status = 14;
        goto finish;
    }
    third = -1;
    target = -1;
    duplicate = -1;
    directory_fd = -1;
    errno = 0;
    if (close(-1) != -1 || errno != EBADF) {
        status = 15;
        goto finish;
    }

finish:
    cleanup_status = cleanup_paths(&paths, directory_fd, primary, duplicate, target, third);
    if (status != 0)
        return 20 + status;
    return cleanup_status == 0 ? 0 : 60;
}

#ifndef CRABC_DESCRIPTOR_LIFECYCLE_FREESTANDING
int main(void)
{
    return crabc_x86_64_descriptor_lifecycle_probe();
}
#endif
