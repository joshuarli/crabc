/* Static crabc-libc x86-64 selected fcntl status-control fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6
 * and then through a freestanding executable linked solely with the selected
 * crabc libc.a. It proves only F_GETFD/F_SETFD descriptor flags and
 * F_GETFL/F_SETFL status flags. The candidate deliberately rejects every
 * other public fcntl command with EINVAL before a syscall; the pinned-musl
 * reference branch records the distinct F_GETOWN/F_DUPFD behavior without
 * selecting it. This fixture is not generic fcntl, locking, descriptor
 * lifecycle, filesystem policy, CRT, thread lifecycle, loader, sysroot, or
 * public x86 support.
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
#include <sys/syscall.h>
#include <sys/types.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4,
    "x86 fcntl scalar widths");
_Static_assert(SYS_open == 2 && SYS_close == 3 && SYS_dup == 32 &&
    SYS_fcntl == 72 && SYS_getpid == 39 && SYS_unlink == 87,
    "x86 selected fcntl syscall numbers");
_Static_assert(F_GETFD == 1 && F_SETFD == 2 && F_GETFL == 3 && F_SETFL == 4 &&
    F_DUPFD == 0 && F_GETOWN == 9 && FD_CLOEXEC == 1,
    "x86 selected and deferred fcntl commands");
_Static_assert(O_RDONLY == 0 && O_WRONLY == 1 && O_RDWR == 2 &&
    O_CREAT == 0100 && O_EXCL == 0200 && O_TRUNC == 01000 &&
    O_APPEND == 02000 && O_NONBLOCK == 04000 && O_CLOEXEC == 02000000 &&
    O_LARGEFILE == 0100000 && O_ACCMODE == (03|O_PATH),
    "x86 fcntl status and creation flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fcntl),
    int (*)(int, int, ...)), "fcntl declaration");

struct fixture_file {
    int descriptor;
    char path[88];
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

static int make_path(char *output, size_t capacity, long process_id)
{
    static const char prefix[] = "/tmp/crabc-x86-64-fcntl-status-";
    char digits[20];
    size_t length = 0;
    size_t digits_length = 0;
    size_t index;

    if (process_id <= 0)
        return -1;
    for (index = 0; prefix[index] != '\0'; ++index) {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = prefix[index];
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
    output[length] = '\0';
    return 0;
}

static int setup_file(struct fixture_file *file)
{
    file->descriptor = -1;
    if (make_path(file->path, sizeof(file->path), raw_syscall0(SYS_getpid)) != 0)
        return -1;

    file->descriptor = (int)raw_syscall3(
        SYS_open,
        (long)(void *)file->path,
        O_CREAT | O_EXCL | O_RDWR,
        0600);
    if (file->descriptor < 0)
        return -1;
    if (raw_syscall1(SYS_unlink, (long)(void *)file->path) != 0) {
        (void)raw_syscall1(SYS_close, file->descriptor);
        file->descriptor = -1;
        return -1;
    }
    return 0;
}

static int cleanup_file(struct fixture_file *file)
{
    if (file->descriptor >= 0 && raw_syscall1(SYS_close, file->descriptor) != 0)
        return -1;
    file->descriptor = -1;
    return 0;
}

static int close_raw_descriptor(int descriptor)
{
    return raw_syscall1(SYS_close, descriptor) == 0 ? 0 : -1;
}

static int check_descriptor_flags(const struct fixture_file *file,
    int *duplicate_out)
{
    int duplicate;

    *duplicate_out = -1;
    errno = E2BIG;
    if (fcntl(file->descriptor, F_GETFD) != 0 || errno != E2BIG)
        return 1;
    duplicate = (int)raw_syscall1(SYS_dup, file->descriptor);
    if (duplicate < 0)
        return 2;
    errno = E2BIG;
    if (fcntl(duplicate, F_SETFD, FD_CLOEXEC) != 0 || errno != E2BIG ||
        fcntl(file->descriptor, F_GETFD) != 0 ||
        fcntl(duplicate, F_GETFD) != FD_CLOEXEC) {
        (void)close_raw_descriptor(duplicate);
        return 3;
    }
    *duplicate_out = duplicate;
    return 0;
}

static int check_status_flags(const struct fixture_file *file, int duplicate)
{
    int changed;
    int original;
    int requested;

    errno = ERANGE;
    original = fcntl(file->descriptor, F_GETFL);
    if (original < 0 || errno != ERANGE ||
        (original & O_ACCMODE) != O_RDWR ||
        (original & (O_CREAT | O_EXCL | O_TRUNC)) != 0 ||
        (original & O_LARGEFILE) != O_LARGEFILE)
        return 1;

    /* Deliberately omit O_LARGEFILE from the scalar C request. The selected
     * wrapper must supply musl's command-specific bit before Linux sees it. */
    requested = (original & ~(O_ACCMODE | O_LARGEFILE)) | O_WRONLY | O_APPEND |
        O_NONBLOCK | O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC;
    changed = original | O_APPEND | O_NONBLOCK;
    errno = ERANGE;
    if (fcntl(file->descriptor, F_SETFL, requested) != 0 || errno != ERANGE ||
        fcntl(duplicate, F_GETFL) != changed ||
        (changed & O_ACCMODE) != O_RDWR ||
        fcntl(file->descriptor, F_GETFD) != 0 ||
        fcntl(duplicate, F_GETFD) != FD_CLOEXEC)
        return 2;
    errno = E2BIG;
    if (fcntl(duplicate, F_SETFL, original) != 0 || errno != E2BIG ||
        fcntl(file->descriptor, F_GETFL) != original ||
        fcntl(file->descriptor, F_GETFD) != 0 ||
        fcntl(duplicate, F_GETFD) != FD_CLOEXEC)
        return 3;
    return 0;
}

static int check_errors(const struct fixture_file *file)
{
    errno = 0;
    if (fcntl(-1, F_GETFD) != -1 || errno != EBADF)
        return 1;
    errno = 0;
    if (fcntl(-1, F_SETFD, FD_CLOEXEC) != -1 || errno != EBADF)
        return 2;
    errno = 0;
    if (fcntl(-1, F_GETFL) != -1 || errno != EBADF)
        return 3;
    errno = 0;
    if (fcntl(-1, F_SETFL, O_NONBLOCK) != -1 || errno != EBADF)
        return 4;
    return fcntl(file->descriptor, F_GETFD) == 0 ? 0 : 5;
}

static int check_unsupported_commands(const struct fixture_file *file)
{
    int descriptor_flags;
    int duplicate;
    int status_flags;

    descriptor_flags = fcntl(file->descriptor, F_GETFD);
    status_flags = fcntl(file->descriptor, F_GETFL);
    if (descriptor_flags < 0 || status_flags < 0)
        return 1;

#ifdef CRABC_FCNTL_STATUS_CONTROL_FREESTANDING
    errno = E2BIG;
    if (fcntl(file->descriptor, F_GETOWN) != -1 || errno != EINVAL)
        return 2;
    errno = ERANGE;
    if (fcntl(file->descriptor, F_DUPFD, 0) != -1 || errno != EINVAL)
        return 3;
#else
    /* Pinned musl forwards these deferred commands. Keep their effects
     * contained while the candidate explicitly records its EINVAL boundary. */
    (void)fcntl(file->descriptor, F_GETOWN);
    duplicate = fcntl(file->descriptor, F_DUPFD, 0);
    if (duplicate < 0)
        return 2;
    if (close_raw_descriptor(duplicate) != 0)
        return 3;
#endif

    if (fcntl(file->descriptor, F_GETFD) != descriptor_flags ||
        fcntl(file->descriptor, F_GETFL) != status_flags)
        return 4;
    return 0;
}

int crabc_x86_64_fcntl_status_control_probe(void)
{
    struct fixture_file file;
    int duplicate = -1;
    int status;
    int cleanup_status;

    if (setup_file(&file) != 0)
        return 1;

    status = check_descriptor_flags(&file, &duplicate);
    if (status == 0)
        status = check_status_flags(&file, duplicate);
    if (status == 0)
        status = check_errors(&file);
    if (status == 0)
        status = check_unsupported_commands(&file);

    cleanup_status = duplicate >= 0 && close_raw_descriptor(duplicate) != 0 ?
        -1 : cleanup_file(&file);
    if (status != 0)
        return 10 + status;
    return cleanup_status == 0 ? 0 : 30;
}

#ifndef CRABC_FCNTL_STATUS_CONTROL_FREESTANDING
int main(void)
{
    return crabc_x86_64_fcntl_status_control_probe();
}
#endif
