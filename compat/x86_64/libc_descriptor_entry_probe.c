/* Static crabc-libc x86-64 selected descriptor-entry fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through a freestanding executable linked solely with the selected
 * crabc libc.a. It proves C open/openat/creat descriptor entry, optional-mode
 * handling, O_CLOEXEC, relative-directory opening, create permissions, and
 * creat truncation. Fixture-local raw syscalls only create a PID-owned /tmp
 * directory, seed one file, observe descriptor/stat state, and remove that
 * directory; they do not select public C fcntl, path policy, a filesystem
 * capability, CRT, pthread cancellation, loader, sysroot, or public x86
 * support.
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
_Static_assert(sizeof(int) == 4 && sizeof(mode_t) == 4 && sizeof(off_t) == 8,
    "x86 descriptor-entry scalar widths");
_Static_assert(SYS_open == 2 && SYS_close == 3 && SYS_fstat == 5 &&
    SYS_getpid == 39 && SYS_fcntl == 72 && SYS_umask == 95 &&
    SYS_openat == 257 && SYS_mkdirat == 258 && SYS_unlinkat == 263,
    "x86 descriptor-entry syscall numbers");
_Static_assert(O_RDONLY == 0 && O_WRONLY == 1 && O_RDWR == 2 &&
    O_CREAT == 0100 && O_EXCL == 0200 && O_TRUNC == 01000 &&
    O_CLOEXEC == 02000000 && O_DIRECTORY == 0200000 &&
    O_LARGEFILE == 0100000 && O_TMPFILE == 020200000,
    "x86 selected descriptor-entry flags");
_Static_assert(F_GETFD == 1 && F_SETFD == 2 && F_GETFL == 3 &&
    FD_CLOEXEC == 1 && AT_FDCWD == -100 && AT_REMOVEDIR == 0x200,
    "x86 selected descriptor-entry constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&open),
    int (*)(const char *, int, ...)), "open declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&openat),
    int (*)(int, const char *, int, ...)), "openat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&creat),
    int (*)(const char *, mode_t)), "creat declaration");

struct fixture_paths {
    int directory_fd;
    int directory_created;
    char directory[80];
    char open_path[96];
    char creat_path[96];
};

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

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

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long argument4_register __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(argument4_register)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_close(int descriptor)
{
    return raw_syscall1(SYS_close, descriptor) == 0 ? 0 : -1;
}

static int raw_fstat(int descriptor, struct stat *value)
{
    return raw_syscall2(SYS_fstat, descriptor, (long)(void *)value) == 0 ? 0 : -1;
}

static long raw_fcntl(int descriptor, int command, long argument)
{
    return raw_syscall3(SYS_fcntl, descriptor, command, argument);
}

static int raw_unlinkat(int directory_descriptor, const char *path, int flags)
{
    return raw_syscall3(SYS_unlinkat, directory_descriptor, (long)(void *)path,
        flags) == 0 ? 0 : -1;
}

static int make_path(char *output, size_t capacity, const char *prefix,
    long process_id, const char *suffix)
{
    char digits[20];
    size_t length = 0;
    size_t digits_length = 0;
    size_t index;

    if (process_id <= 0)
        return -1;
    while (prefix[length] != '\0') {
        if (length + 1 >= capacity)
            return -1;
        output[length] = prefix[length];
        ++length;
    }
    do {
        if (digits_length == sizeof(digits))
            return -1;
        digits[digits_length++] = (char)('0' + process_id % 10);
        process_id /= 10;
    } while (process_id != 0);
    while (digits_length != 0) {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = digits[--digits_length];
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
    const char *const directory_prefix = "/tmp/crabc-x86-64-descriptor-entry-";
    long process_id = raw_syscall0(SYS_getpid);
    long result;

    paths->directory_fd = -1;
    paths->directory_created = 0;
    if (make_path(paths->directory, sizeof(paths->directory), directory_prefix,
            process_id, "") != 0 ||
        make_path(paths->open_path, sizeof(paths->open_path), directory_prefix,
            process_id, "/open") != 0 ||
        make_path(paths->creat_path, sizeof(paths->creat_path), directory_prefix,
            process_id, "/creat") != 0)
        return -1;

    result = raw_syscall3(SYS_mkdirat, AT_FDCWD, (long)(void *)paths->directory,
        0700);
    if (result != 0)
        return -1;
    paths->directory_created = 1;

    errno = E2BIG;
    paths->directory_fd = open(paths->directory, O_RDONLY | O_DIRECTORY);
    if (paths->directory_fd < 0 || errno != E2BIG)
        return -1;
    return 0;
}

static int cleanup_paths(struct fixture_paths *paths)
{
    int status = 0;

    if (paths->directory_fd >= 0) {
        (void)raw_unlinkat(paths->directory_fd, "open", 0);
        (void)raw_unlinkat(paths->directory_fd, "openat", 0);
        (void)raw_unlinkat(paths->directory_fd, "creat", 0);
        if (raw_close(paths->directory_fd) != 0)
            status = -1;
        paths->directory_fd = -1;
    }
    if (paths->directory_created &&
        raw_unlinkat(AT_FDCWD, paths->directory, AT_REMOVEDIR) != 0)
        status = -1;
    return status;
}

static int check_open_without_mode(void)
{
    int descriptor;
    long flags;

    errno = E2BIG;
    descriptor = open("/dev/null", O_RDONLY);
    if (descriptor < 0 || errno != E2BIG)
        return 1;
    flags = raw_fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        (flags & O_LARGEFILE) != O_LARGEFILE) {
        (void)raw_close(descriptor);
        return 2;
    }
    if (raw_fcntl(descriptor, F_GETFD, 0) != 0) {
        (void)raw_close(descriptor);
        return 3;
    }
    return raw_close(descriptor) == 0 ? 0 : 4;
}

static int check_open_create_cloexec(const struct fixture_paths *paths)
{
    struct stat value;
    int descriptor;
    long result;

    descriptor = open(paths->open_path,
        O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (descriptor < 0)
        return 1;
    if (raw_fstat(descriptor, &value) != 0 ||
        (value.st_mode & 0777) != 0600) {
        (void)raw_close(descriptor);
        return 2;
    }
    result = raw_fcntl(descriptor, F_GETFD, 0);
    if (result != FD_CLOEXEC) {
        (void)raw_close(descriptor);
        return 3;
    }
    result = raw_fcntl(descriptor, F_GETFL, 0);
    if (result < 0 || (result & O_ACCMODE) != O_RDWR ||
        (result & O_LARGEFILE) != O_LARGEFILE) {
        (void)raw_close(descriptor);
        return 4;
    }
    return raw_close(descriptor) == 0 ? 0 : 5;
}

static int check_openat_relative_create(const struct fixture_paths *paths)
{
    struct stat value;
    int descriptor;
    long result;

    descriptor = openat(paths->directory_fd, "openat",
        O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0640);
    if (descriptor < 0)
        return 1;
    if (raw_fstat(descriptor, &value) != 0 ||
        (value.st_mode & 0777) != 0640) {
        (void)raw_close(descriptor);
        return 2;
    }
    result = raw_fcntl(descriptor, F_GETFD, 0);
    if (result != FD_CLOEXEC) {
        (void)raw_close(descriptor);
        return 3;
    }
    result = raw_fcntl(descriptor, F_GETFL, 0);
    if (result < 0 || (result & O_ACCMODE) != O_WRONLY ||
        (result & O_LARGEFILE) != O_LARGEFILE) {
        (void)raw_close(descriptor);
        return 4;
    }
    if (raw_close(descriptor) != 0)
        return 5;

    errno = ERANGE;
    descriptor = openat(paths->directory_fd, "openat", O_RDONLY);
    if (descriptor < 0 || errno != ERANGE)
        return 6;
    result = raw_fcntl(descriptor, F_GETFD, 0);
    if (result != 0) {
        (void)raw_close(descriptor);
        return 7;
    }
    result = raw_fcntl(descriptor, F_GETFL, 0);
    if (result < 0 || (result & O_ACCMODE) != O_RDONLY ||
        (result & O_LARGEFILE) != O_LARGEFILE) {
        (void)raw_close(descriptor);
        return 8;
    }
    return raw_close(descriptor) == 0 ? 0 : 9;
}

static int check_creat_truncates(const struct fixture_paths *paths)
{
    static const char seed[] = "seed";
    struct stat value;
    int descriptor;
    long result;

    descriptor = creat(paths->creat_path, 0620);
    if (descriptor < 0)
        return 1;
    if (raw_fstat(descriptor, &value) != 0 ||
        (value.st_mode & 0777) != 0620 || value.st_size != 0) {
        (void)raw_close(descriptor);
        return 2;
    }
    result = raw_fcntl(descriptor, F_GETFL, 0);
    if (result < 0 || (result & O_ACCMODE) != O_WRONLY ||
        (result & O_LARGEFILE) != O_LARGEFILE ||
        raw_fcntl(descriptor, F_GETFD, 0) != 0 ||
        raw_syscall3(SYS_write, descriptor, (long)(void *)seed,
            sizeof(seed) - 1) != (long)(sizeof(seed) - 1) ||
        raw_close(descriptor) != 0)
        return 3;

    descriptor = creat(paths->creat_path, 0600);
    if (descriptor < 0)
        return 4;
    if (raw_fstat(descriptor, &value) != 0 ||
        (value.st_mode & 0777) != 0620 || value.st_size != 0) {
        (void)raw_close(descriptor);
        return 5;
    }
    return raw_close(descriptor) == 0 ? 0 : 6;
}

static int check_errors(const struct fixture_paths *paths)
{
    errno = 0;
    if (open(0, O_RDONLY) != -1 || errno != EFAULT)
        return 1;
    errno = 0;
    if (openat(-1, "relative", O_RDONLY) != -1 || errno != EBADF)
        return 2;
    errno = 0;
    if (openat(paths->directory_fd, "missing", O_RDONLY) != -1 ||
        errno != ENOENT)
        return 3;
    errno = 0;
    if (open(paths->open_path, O_CREAT | O_EXCL | O_WRONLY, 0600) != -1 ||
        errno != EEXIST)
        return 4;
    errno = 0;
    if (creat(0, 0600) != -1 || errno != EFAULT)
        return 5;
    return 0;
}

int crabc_x86_64_descriptor_entry_probe(void)
{
    struct fixture_paths paths;
    long prior_umask;
    int status;
    int cleanup_status;

    prior_umask = raw_syscall1(SYS_umask, 0);
    if (prior_umask < 0)
        return 1;
    if (setup_paths(&paths) != 0) {
        (void)cleanup_paths(&paths);
        (void)raw_syscall1(SYS_umask, prior_umask);
        return 2;
    }

    status = check_open_without_mode();
    if (status == 0)
        status = check_open_create_cloexec(&paths);
    if (status == 0)
        status = check_openat_relative_create(&paths);
    if (status == 0)
        status = check_creat_truncates(&paths);
    if (status == 0)
        status = check_errors(&paths);

    cleanup_status = cleanup_paths(&paths);
    if (raw_syscall1(SYS_umask, prior_umask) < 0)
        cleanup_status = -1;
    if (status != 0)
        return 10 + status;
    return cleanup_status == 0 ? 0 : 30;
}

#ifndef CRABC_DESCRIPTOR_ENTRY_FREESTANDING
int main(void)
{
    return crabc_x86_64_descriptor_entry_probe();
}
#endif
