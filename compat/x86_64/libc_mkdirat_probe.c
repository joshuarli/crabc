/* Static crabc-libc x86-64 mkdirat compatibility fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. Raw mkdirat/openat,
 * newfstatat, unlinkat, and close calls create, observe, compare, and remove
 * only fixture-owned entries. `mkdirat` is the only candidate C entry. This
 * proves caller-directed descriptor-relative directory creation, not mkdir,
 * pathname/CWD policy, allocation, cancellation, or a Rust filesystem facade.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    FIXTURE_AT_FDCWD = -100,
    FIXTURE_AT_REMOVEDIR = 0x200,
    FIXTURE_EBADF = 9,
    FIXTURE_EEXIST = 17,
    FIXTURE_EFAULT = 14,
    FIXTURE_EINTR = 4,
    FIXTURE_ENOENT = 2,
};

_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 LP64 stat record");
_Static_assert(sizeof(mode_t) == 4 && _Alignof(mode_t) == 4 &&
                   __builtin_types_compatible_p(mode_t, unsigned int),
               "x86 mode_t ABI");
_Static_assert(AT_FDCWD == FIXTURE_AT_FDCWD &&
                   AT_REMOVEDIR == FIXTURE_AT_REMOVEDIR,
               "x86 mkdirat fixture constants");
_Static_assert(O_DIRECTORY == 0200000 && O_RDONLY == 00,
               "x86 mkdirat open constants");
_Static_assert(S_IFMT == 0170000 && S_IFDIR == 0040000,
               "x86 directory mode constants");
_Static_assert(SYS_close == 3 && SYS_openat == 257 && SYS_mkdirat == 258 &&
                   SYS_newfstatat == 262 && SYS_unlinkat == 263,
               "Linux x86 mkdirat fixture syscall numbers");
_Static_assert(EBADF == FIXTURE_EBADF && EEXIST == FIXTURE_EEXIST &&
                   EFAULT == FIXTURE_EFAULT && EINTR == FIXTURE_EINTR &&
                   ENOENT == FIXTURE_ENOENT,
               "Linux x86 mkdirat errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mkdirat),
                                             int (*)(int, const char *, mode_t)),
               "mkdirat declaration");

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
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static int remove_directory_if_present_at(int dirfd, const char *path)
{
    long result = raw_syscall3(SYS_unlinkat, dirfd, (long)(uintptr_t)path,
        AT_REMOVEDIR);

    return result == 0 || result == -ENOENT ? 0 : -1;
}

static int directory_has_mode_at(int dirfd, const char *path, mode_t mode)
{
    struct stat observed;

    if (raw_syscall4(SYS_newfstatat, dirfd, (long)(uintptr_t)path,
        (long)(uintptr_t)&observed, 0) != 0)
        return -1;
    return S_ISDIR(observed.st_mode) && (observed.st_mode & 0777) == mode
        ? 0
        : -1;
}

int crabc_x86_64_mkdirat_probe(void)
{
    static const char parent[] = "mkdirat-root";
    static const char candidate_0750[] = "candidate-0750";
    static const char candidate_0000[] = "candidate-0000";
    static const char raw_directory[] = "raw-directory";
    static const char duplicate[] = "duplicate";
    static const char missing_child[] = "missing/child";
    int descriptor = -1;
    int status = 0;

    if (raw_syscall3(SYS_mkdirat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)parent, 0700) != 0)
        return 1;
    descriptor = (int)raw_syscall4(SYS_openat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)parent, O_RDONLY | O_DIRECTORY, 0);
    if (descriptor < 0)
        status = 2;

    if (status == 0) {
        /* A successful selected call leaves stale errno untouched. */
        errno = EINTR;
        if (mkdirat(descriptor, candidate_0750, 0750) != 0)
            status = 10;
        else if (errno != EINTR)
            status = 11;
        else if (directory_has_mode_at(descriptor, candidate_0750, 0750) != 0)
            status = 12;
    }
    if (status == 0) {
        errno = EINTR;
        if (mkdirat(descriptor, candidate_0000, 0000) != 0)
            status = 13;
        else if (errno != EINTR)
            status = 14;
        else if (directory_has_mode_at(descriptor, candidate_0000, 0000) != 0)
            status = 15;
    }
    if (status == 0 && raw_syscall3(SYS_mkdirat, descriptor,
        (long)(uintptr_t)raw_directory, 0710) != 0)
        status = 16;
    if (status == 0 && directory_has_mode_at(descriptor, raw_directory, 0710) != 0)
        status = 17;
    if (status == 0) {
        errno = 0;
        if (mkdirat(descriptor, candidate_0750, 0750) != -1 || errno != EEXIST)
            status = 18;
    }
    if (status == 0) {
        errno = 0;
        if (mkdirat(-1, duplicate, 0700) != -1 || errno != EBADF)
            status = 19;
    }
    if (status == 0) {
        errno = 0;
        if (mkdirat(descriptor, (const char *)0, 0700) != -1 || errno != EFAULT)
            status = 20;
    }
    if (status == 0) {
        errno = 0;
        if (mkdirat(descriptor, missing_child, 0700) != -1 || errno != ENOENT)
            status = 21;
    }

    if (descriptor >= 0) {
        if (remove_directory_if_present_at(descriptor, candidate_0750) != 0 &&
            status == 0)
            status = 30;
        if (remove_directory_if_present_at(descriptor, candidate_0000) != 0 &&
            status == 0)
            status = 31;
        if (remove_directory_if_present_at(descriptor, raw_directory) != 0 &&
            status == 0)
            status = 32;
        if (raw_syscall1(SYS_close, descriptor) != 0 && status == 0)
            status = 33;
    }
    if (remove_directory_if_present_at(FIXTURE_AT_FDCWD, parent) != 0 &&
        status == 0)
        status = 34;
    return status;
}

#ifndef CRABC_MKDIRAT_FREESTANDING
int main(void)
{
    return crabc_x86_64_mkdirat_probe();
}
#endif
