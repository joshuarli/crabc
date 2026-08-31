/* Static crabc-libc x86-64 unlinkat compatibility fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. Raw mkdirat, openat,
 * newfstatat, and unlinkat calls create, observe, compare, and remove only
 * fixture-owned entries. `unlinkat` is the only candidate C entry. This
 * proves caller-directed file removal and AT_REMOVEDIR directory removal, not
 * unlink/rmdir, a general pathname/CWD policy, allocation, cancellation, or
 * a Rust filesystem facade.
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
    FIXTURE_AT_SYMLINK_NOFOLLOW = 0x100,
    FIXTURE_EBADF = 9,
    FIXTURE_EFAULT = 14,
    FIXTURE_EINTR = 4,
    FIXTURE_EINVAL = 22,
    FIXTURE_ENOENT = 2,
};

_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 LP64 stat record");
_Static_assert(AT_FDCWD == FIXTURE_AT_FDCWD &&
                   AT_REMOVEDIR == FIXTURE_AT_REMOVEDIR &&
                   AT_SYMLINK_NOFOLLOW == FIXTURE_AT_SYMLINK_NOFOLLOW,
               "x86 unlinkat fixture constants");
_Static_assert(O_DIRECTORY == 0200000 && O_CREAT == 0100 && O_EXCL == 0200 &&
                   O_WRONLY == 01,
               "x86 unlinkat open constants");
_Static_assert(SYS_close == 3 && SYS_openat == 257 && SYS_mkdirat == 258 &&
                   SYS_newfstatat == 262 && SYS_unlinkat == 263,
               "Linux x86 unlinkat fixture syscall numbers");
_Static_assert(EBADF == FIXTURE_EBADF && EFAULT == FIXTURE_EFAULT &&
                   EINTR == FIXTURE_EINTR && EINVAL == FIXTURE_EINVAL &&
                   ENOENT == FIXTURE_ENOENT,
               "Linux x86 unlinkat errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&unlinkat),
    int (*)(int, const char *, int)), "unlinkat declaration");

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

static int remove_path_at(int dirfd, const char *path, int flags)
{
    return raw_syscall3(SYS_unlinkat, dirfd, (long)(uintptr_t)path, flags) == 0
        ? 0
        : -1;
}

static int remove_path_if_present_at(int dirfd, const char *path, int flags)
{
    long result = raw_syscall3(SYS_unlinkat, dirfd, (long)(uintptr_t)path,
        flags);

    return result == 0 || result == -ENOENT ? 0 : -1;
}

static int create_file_at(int dirfd, const char *path)
{
    long descriptor = raw_syscall4(SYS_openat, dirfd, (long)(uintptr_t)path,
        O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (descriptor < 0)
        return -1;
    return raw_syscall1(SYS_close, descriptor) == 0 ? 0 : -1;
}

static int expect_missing_at(int dirfd, const char *path)
{
    struct stat observed;

    return raw_syscall4(SYS_newfstatat, dirfd, (long)(uintptr_t)path,
        (long)(uintptr_t)&observed, 0) == -ENOENT ? 0 : -1;
}

int crabc_x86_64_unlinkat_probe(void)
{
    static const char directory[] = "unlinkat-root";
    static const char candidate_file[] = "candidate-file";
    static const char candidate_directory[] = "candidate-directory";
    static const char raw_file[] = "raw-file";
    static const char missing[] = "missing";
    int descriptor = -1;
    int status = 0;

    if (raw_syscall3(SYS_mkdirat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)directory, 0700) != 0)
        return 1;
    descriptor = (int)raw_syscall4(SYS_openat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)directory, O_RDONLY | O_DIRECTORY, 0);
    if (descriptor < 0)
        status = 2;
    if (status == 0 && create_file_at(descriptor, candidate_file) != 0)
        status = 3;
    if (status == 0) {
        /* A successful selected call leaves stale errno untouched. */
        errno = EINTR;
        if (unlinkat(descriptor, candidate_file, 0) != 0)
            status = 10;
        else if (errno != EINTR)
            status = 11;
        else if (expect_missing_at(descriptor, candidate_file) != 0)
            status = 12;
    }
    if (status == 0 && raw_syscall3(SYS_mkdirat, descriptor,
        (long)(uintptr_t)candidate_directory, 0700) != 0)
        status = 13;
    if (status == 0) {
        errno = EINTR;
        if (unlinkat(descriptor, candidate_directory, AT_REMOVEDIR) != 0)
            status = 14;
        else if (errno != EINTR)
            status = 15;
        else if (expect_missing_at(descriptor, candidate_directory) != 0)
            status = 16;
    }
    if (status == 0 && create_file_at(descriptor, raw_file) != 0)
        status = 17;
    if (status == 0 && remove_path_at(descriptor, raw_file, 0) != 0)
        status = 18;
    if (status == 0 && expect_missing_at(descriptor, raw_file) != 0)
        status = 19;
    if (status == 0) {
        errno = 0;
        if (unlinkat(descriptor, missing, 0) != -1 || errno != ENOENT)
            status = 20;
    }
    if (status == 0) {
        errno = 0;
        if (unlinkat(descriptor, missing, AT_SYMLINK_NOFOLLOW) != -1 ||
            errno != EINVAL)
            status = 21;
    }
    if (status == 0) {
        errno = 0;
        if (unlinkat(-1, missing, 0) != -1 || errno != EBADF)
            status = 22;
    }
    if (status == 0) {
        errno = 0;
        if (unlinkat(descriptor, (const char *)0, 0) != -1 || errno != EFAULT)
            status = 23;
    }

    if (descriptor >= 0) {
        if (remove_path_if_present_at(descriptor, candidate_file, 0) != 0 &&
            status == 0)
            status = 30;
        if (remove_path_if_present_at(descriptor, raw_file, 0) != 0 &&
            status == 0)
            status = 31;
        if (remove_path_if_present_at(descriptor, candidate_directory,
            AT_REMOVEDIR) != 0 && status == 0)
            status = 32;
        if (raw_syscall1(SYS_close, descriptor) != 0 && status == 0)
            status = 33;
    }
    if (remove_path_if_present_at(FIXTURE_AT_FDCWD, directory, AT_REMOVEDIR) !=
        0 && status == 0)
        status = 34;
    return status;
}

#ifndef CRABC_UNLINKAT_FREESTANDING
int main(void)
{
    return crabc_x86_64_unlinkat_probe();
}
#endif
