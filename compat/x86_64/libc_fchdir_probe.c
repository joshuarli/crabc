/* Static x86-64 fchdir C ABI and runtime differential fixture.
 *
 * The identical project-header body runs first with pinned musl 1.2.6 and
 * then with a true `-nostdlib -static` crabc archive. It proves precisely
 * musl's `fchdir` O_PATH-directory fallback: direct Linux fchdir reports
 * EBADF for a live O_PATH descriptor, musl checks F_GETFD, then chdir(2)s the
 * fixed `/proc/self/fd/<fd>` spelling. The fixture uses raw openat/getcwd/
 * close only to set up and observe one child process's CWD; it neither selects
 * those C APIs nor general pathname, descriptor, procfs, or filesystem work.
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
#include <unistd.h>

_Static_assert(sizeof(int) == 4, "x86 signed int width");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fchdir),
    int (*)(int)), "fchdir declaration");
_Static_assert(AT_FDCWD == -100 && F_GETFD == 1,
    "x86 descriptor constants");
_Static_assert(O_DIRECTORY == 0200000 && O_CLOEXEC == 02000000 &&
    O_PATH == 010000000, "x86 open constants");
_Static_assert(SYS_close == 3 && SYS_fcntl == 72 && SYS_getcwd == 79 &&
    SYS_chdir == 80 && SYS_fchdir == 81 && SYS_openat == 257,
    "x86 Linux syscall numbers");

typedef int (*fchdir_signature)(int);

enum { CRABC_X86_CWD_CAPACITY = 4096 };

static long raw_syscall1(long number, long first)
{
    long result;

    __asm__ volatile (
        "syscall"
        : "=a" (result)
        : "a" (number), "D" (first)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long first, long second)
{
    long result;

    __asm__ volatile (
        "syscall"
        : "=a" (result)
        : "a" (number), "D" (first), "S" (second)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long first, long second, long third,
    long fourth)
{
    register long r10 __asm__("r10") = fourth;
    long result;

    __asm__ volatile (
        "syscall"
        : "=a" (result), "+r" (r10)
        : "a" (number), "D" (first), "S" (second), "d" (third)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_is_linux_error(long value)
{
    return value < 0 && value >= -4095;
}

static int raw_openat(const char *path, int flags)
{
    long result = raw_syscall4(SYS_openat, AT_FDCWD, (long)path, flags, 0);

    return raw_is_linux_error(result) ? -1 : (int)result;
}

static int raw_getcwd(char *path, size_t capacity)
{
    long result = raw_syscall2(SYS_getcwd, (long)path, (long)capacity);

    return raw_is_linux_error(result) ? -1 : (int)result;
}

static int raw_close(int descriptor)
{
    return raw_syscall1(SYS_close, descriptor) == 0 ? 0 : -1;
}

static int raw_restore_cwd(int descriptor)
{
    return raw_syscall1(SYS_fchdir, descriptor) == 0 ? 0 : -1;
}

static int bytes_equal(const char *left, const char *right)
{
    for (;;) {
        if (*left != *right)
            return 0;
        if (*left == 0)
            return 1;
        left++;
        right++;
    }
}

static int check_path_directory_fallback(const fchdir_signature function,
    int saved_cwd, const char *initial_cwd)
{
    static const char proc_directory[] = "/proc";
    char observed_cwd[CRABC_X86_CWD_CAPACITY];
    int descriptor;
    int status = 0;

    descriptor = raw_openat(proc_directory,
        O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0)
        return 1;

    errno = E2BIG;
    if (function(descriptor) != 0)
        status = 2;
    else if (errno != E2BIG)
        status = 3;
    else if (raw_getcwd(observed_cwd, sizeof(observed_cwd)) < 0)
        status = 4;
    else if (!bytes_equal(observed_cwd, proc_directory))
        status = 5;

    /* The ordinary directory descriptor takes fchdir's direct syscall path. */
    if (function(saved_cwd) != 0) {
        if (status == 0)
            status = 6;
    } else if (errno != E2BIG && status == 0) {
        status = 7;
    } else if (raw_getcwd(observed_cwd, sizeof(observed_cwd)) < 0) {
        if (status == 0)
            status = 8;
    } else if (!bytes_equal(observed_cwd, initial_cwd) && status == 0) {
        status = 9;
    }

    if (status != 0)
        (void)raw_restore_cwd(saved_cwd);
    if (raw_close(descriptor) != 0 && status == 0)
        status = 10;
    return status;
}

static int check_path_nondirectory_error(const fchdir_signature function,
    int saved_cwd, const char *initial_cwd)
{
    static const char proc_file[] = "/proc/cpuinfo";
    char observed_cwd[CRABC_X86_CWD_CAPACITY];
    int descriptor;
    int status = 0;

    descriptor = raw_openat(proc_file, O_PATH | O_CLOEXEC);
    if (descriptor < 0)
        return 1;

    errno = E2BIG;
    if (function(descriptor) != -1)
        status = 2;
    else if (errno != ENOTDIR)
        status = 3;
    else if (raw_getcwd(observed_cwd, sizeof(observed_cwd)) < 0)
        status = 4;
    else if (!bytes_equal(observed_cwd, initial_cwd))
        status = 5;

    if (status != 0)
        (void)raw_restore_cwd(saved_cwd);
    if (raw_close(descriptor) != 0 && status == 0)
        status = 6;
    return status;
}

int crabc_x86_64_fchdir_probe(void)
{
    const fchdir_signature function = fchdir;
    char initial_cwd[CRABC_X86_CWD_CAPACITY];
    int saved_cwd;
    int status;

    saved_cwd = raw_openat(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (saved_cwd < 0)
        return 1;
    if (raw_getcwd(initial_cwd, sizeof(initial_cwd)) < 0) {
        (void)raw_close(saved_cwd);
        return 2;
    }

    status = check_path_directory_fallback(function, saved_cwd, initial_cwd);
    if (status != 0) {
        (void)raw_restore_cwd(saved_cwd);
        (void)raw_close(saved_cwd);
        return 10 + status;
    }
    status = check_path_nondirectory_error(function, saved_cwd, initial_cwd);
    if (status != 0) {
        (void)raw_restore_cwd(saved_cwd);
        (void)raw_close(saved_cwd);
        return 30 + status;
    }

    errno = E2BIG;
    if (function(-1) != -1 || errno != EBADF) {
        (void)raw_close(saved_cwd);
        return 50;
    }
    return raw_close(saved_cwd) == 0 ? 0 : 51;
}

#ifndef CRABC_FCHDIR_FREESTANDING
int main(void)
{
    return crabc_x86_64_fchdir_probe();
}
#endif
