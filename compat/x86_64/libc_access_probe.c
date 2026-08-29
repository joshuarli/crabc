/* Static crabc-libc x86-64 selected access compatibility fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through a freestanding executable linked solely with the selected
 * crabc libc.a. It proves only access, faccessat, euidaccess, and musl's weak
 * eaccess alias: real versus effective credentials, legacy versus flags-bearing
 * Linux entry points, final-symlink policy, and C errno results. Fixture-local
 * raw syscalls only open runner-provisioned files and contain the credential
 * transition in a child; they do not select C descriptor, credential, process,
 * or filesystem-policy APIs from the archive under test.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef CRABC_ACCESS_ROOT
#error "the runner must provide CRABC_ACCESS_ROOT"
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define CRABC_ACCESS_RECORD CRABC_ACCESS_ROOT "/record"

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4,
    "x86 int and pid_t ABI");
_Static_assert(SYS_access == 21 && SYS_close == 3 && SYS_clone == 56 &&
    SYS_exit == 60 && SYS_wait4 == 61 && SYS_setresuid == 117 &&
    SYS_openat == 257 && SYS_faccessat == 269 && SYS_faccessat2 == 439,
    "x86 selected access syscall numbers");
_Static_assert(F_OK == 0 && X_OK == 1 && W_OK == 2 && R_OK == 4,
    "x86 access mode values");
_Static_assert(AT_FDCWD == -100 && AT_SYMLINK_NOFOLLOW == 0x100 &&
    AT_EACCESS == 0x200,
    "x86 selected access flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&access),
    int (*)(const char *, int)), "access declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&faccessat),
    int (*)(int, const char *, int, int)), "faccessat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&euidaccess),
    int (*)(const char *, int)), "euidaccess declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&eaccess),
    int (*)(const char *, int)), "eaccess declaration");

#if defined(CRABC_ACCESS_OVERRIDE_EACCESS)
static int eaccess_override_calls;

/* A caller's strong definition must replace the archive's weak musl alias. */
int eaccess(const char *path, int mode)
{
    ++eaccess_override_calls;
    return euidaccess(path, mode);
}
#endif

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

static long raw_syscall5(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5)
{
    long result;
    register long argument4_register __asm__("r10") = argument4;
    register long argument5_register __asm__("r8") = argument5;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(argument4_register), "r"(argument5_register)
        : "rcx", "r11", "memory");
    return result;
}

static __attribute__((noreturn)) void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    __builtin_unreachable();
}

/* Linux/x86-64 SIGCHLD is 17. The fixture needs only this raw clone flag. */
static __attribute__((noinline, returns_twice)) long raw_clone_sigchld(void)
{
    return raw_syscall5(SYS_clone, 17, 0, 0, 0, 0);
}

static int raw_open_root(void)
{
    return (int)raw_syscall4(SYS_openat, AT_FDCWD,
        (long)(const void *)CRABC_ACCESS_ROOT,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
}

static int raw_close(int descriptor)
{
    return raw_syscall1(SYS_close, descriptor) == 0 ? 0 : -1;
}

static int raw_wait_for(pid_t child)
{
    int status = 0;
    long result;

    do {
        result = raw_syscall4(SYS_wait4, child, (long)(void *)&status, 0, 0);
    } while (result == -EINTR);

    return result == child && (status & 0x7f) == 0 &&
        ((status >> 8) & 0xff) == 0;
}

static int failed_with(int value, int expected_errno)
{
    return value == -1 && errno == expected_errno;
}

static int check_root_baseline(int directory_fd)
{
    errno = E2BIG;
    if (access(CRABC_ACCESS_RECORD, F_OK) != 0 || errno != E2BIG)
        return 1;
    errno = ERANGE;
    if (access(CRABC_ACCESS_RECORD, R_OK) != 0 || errno != ERANGE)
        return 2;
    errno = E2BIG;
    if (faccessat(directory_fd, "record", F_OK, 0) != 0 || errno != E2BIG)
        return 3;
    errno = ERANGE;
    if (faccessat(directory_fd, "record", R_OK, 0) != 0 || errno != ERANGE)
        return 4;
    errno = E2BIG;
    if (euidaccess(CRABC_ACCESS_RECORD, R_OK) != 0 || errno != E2BIG)
        return 5;
    errno = ERANGE;
    if (eaccess(CRABC_ACCESS_RECORD, R_OK) != 0 || errno != ERANGE)
        return 6;
    return 0;
}

static int check_path_policy(int directory_fd)
{
    errno = 0;
    if (!failed_with(access(CRABC_ACCESS_ROOT "/missing", F_OK), ENOENT))
        return 1;
    errno = 0;
    if (!failed_with(faccessat(directory_fd, "missing", F_OK, 0), ENOENT))
        return 2;

    errno = 0;
    if (!failed_with(faccessat(directory_fd, "dangling", F_OK, 0), ENOENT))
        return 3;
    errno = E2BIG;
    if (faccessat(directory_fd, "dangling", F_OK,
            AT_SYMLINK_NOFOLLOW) != 0 || errno != E2BIG)
        return 4;
    return 0;
}

static int check_invalid_arguments(int directory_fd)
{
    const char *null_path = (const char *)0;

    errno = 0;
    if (!failed_with(access(CRABC_ACCESS_RECORD, 8), EINVAL))
        return 1;
    errno = 0;
    if (!failed_with(faccessat(directory_fd, "record", 8, 0), EINVAL))
        return 2;
    errno = 0;
    if (!failed_with(euidaccess(CRABC_ACCESS_RECORD, 8), EINVAL))
        return 3;
    errno = 0;
    if (!failed_with(eaccess(CRABC_ACCESS_RECORD, 8), EINVAL))
        return 4;
    errno = 0;
    if (!failed_with(faccessat(directory_fd, "record", F_OK, 0x400), EINVAL))
        return 5;
    errno = 0;
    if (!failed_with(access(null_path, F_OK), EFAULT))
        return 6;
    errno = 0;
    if (!failed_with(faccessat(directory_fd, null_path, F_OK, 0), EFAULT))
        return 7;
    errno = 0;
    if (!failed_with(euidaccess(null_path, F_OK), EFAULT))
        return 8;
    errno = 0;
    if (!failed_with(eaccess(null_path, F_OK), EFAULT))
        return 9;
    return 0;
}

static __attribute__((noreturn)) void check_real_and_effective_ids(int directory_fd)
{
    if (raw_syscall3(SYS_setresuid, 1000, 0, 0) != 0)
        raw_exit(50);

    errno = 0;
    if (!failed_with(access(CRABC_ACCESS_RECORD, R_OK), EACCES))
        raw_exit(51);
    errno = 0;
    if (!failed_with(faccessat(directory_fd, "record", R_OK, 0), EACCES))
        raw_exit(52);

    errno = E2BIG;
    if (faccessat(directory_fd, "record", R_OK, AT_EACCESS) != 0 ||
        errno != E2BIG)
        raw_exit(53);
    errno = ERANGE;
    if (euidaccess(CRABC_ACCESS_RECORD, R_OK) != 0 || errno != ERANGE)
        raw_exit(54);
    errno = E2BIG;
    if (eaccess(CRABC_ACCESS_RECORD, R_OK) != 0 || errno != E2BIG)
        raw_exit(55);
    raw_exit(0);
}

static int access_probe(void)
{
    int directory_fd;
    int status;
    long child;

    directory_fd = raw_open_root();
    if (directory_fd < 0)
        return 1;

    status = check_root_baseline(directory_fd);
    if (status != 0)
        goto close_directory;
    status = check_path_policy(directory_fd);
    if (status != 0)
        goto close_directory;
    status = check_invalid_arguments(directory_fd);
    if (status != 0)
        goto close_directory;

    child = raw_clone_sigchld();
    if (child == 0)
        check_real_and_effective_ids(directory_fd);
    if (child < 0) {
        status = 20;
        goto close_directory;
    }
    if (!raw_wait_for((pid_t)child)) {
        status = 21;
        goto close_directory;
    }

#if defined(CRABC_ACCESS_OVERRIDE_EACCESS)
    if (eaccess_override_calls == 0)
        status = 22;
#endif

close_directory:
    if (raw_close(directory_fd) != 0 && status == 0)
        status = 30;
    return status;
}

#if defined(CRABC_ACCESS_FREESTANDING)
int crabc_x86_64_access_probe(void)
{
    return access_probe();
}
#else
int main(void)
{
    return access_probe();
}
#endif
