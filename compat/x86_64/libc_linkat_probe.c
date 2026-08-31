/* Static crabc-libc x86-64 linkat compatibility fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. Raw mkdirat/openat,
 * newfstatat, symlinkat, linkat, unlinkat, and close calls create, observe,
 * compare, and remove only fixture-owned entries. `linkat` is the only
 * candidate C entry. This proves descriptor-relative same-inode links and a
 * forwarded AT_SYMLINK_FOLLOW flag, not ordinary link, another *at entry,
 * pathname policy, allocation, CWD state, or a Rust filesystem facade.
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
    FIXTURE_AT_SYMLINK_FOLLOW = 0x400,
    FIXTURE_AT_SYMLINK_NOFOLLOW = 0x100,
    FIXTURE_EBADF = 9,
    FIXTURE_EEXIST = 17,
    FIXTURE_EFAULT = 14,
    FIXTURE_EINTR = 4,
    FIXTURE_EINVAL = 22,
    FIXTURE_ENOENT = 2,
    FIXTURE_O_CREAT = 0100,
    FIXTURE_O_DIRECTORY = 0200000,
    FIXTURE_O_EXCL = 0200,
    FIXTURE_O_RDWR = 02,
};

_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
               "x86 linkat int ABI");
_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 LP64 stat record");
_Static_assert(S_IFMT == 0170000 && S_IFREG == 0100000 && S_IFLNK == 0120000,
               "x86 hard-link mode constants");
_Static_assert(AT_FDCWD == FIXTURE_AT_FDCWD &&
                   AT_REMOVEDIR == FIXTURE_AT_REMOVEDIR &&
                   AT_SYMLINK_FOLLOW == FIXTURE_AT_SYMLINK_FOLLOW &&
                   AT_SYMLINK_NOFOLLOW == FIXTURE_AT_SYMLINK_NOFOLLOW &&
                   O_CREAT == FIXTURE_O_CREAT && O_DIRECTORY == FIXTURE_O_DIRECTORY &&
                   O_EXCL == FIXTURE_O_EXCL && O_RDWR == FIXTURE_O_RDWR,
               "x86 hard-link fixture constants");
_Static_assert(SYS_close == 3 && SYS_openat == 257 && SYS_mkdirat == 258 &&
                   SYS_newfstatat == 262 && SYS_unlinkat == 263 &&
                   SYS_linkat == 265 && SYS_symlinkat == 266,
               "Linux x86 linkat fixture syscall numbers");
_Static_assert(EBADF == FIXTURE_EBADF && EEXIST == FIXTURE_EEXIST &&
                   EFAULT == FIXTURE_EFAULT && EINTR == FIXTURE_EINTR &&
                   EINVAL == FIXTURE_EINVAL && ENOENT == FIXTURE_ENOENT,
               "Linux x86 linkat errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&linkat),
    int (*)(int, const char *, int, const char *, int)),
    "linkat declaration");

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

static long raw_syscall5(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

static int remove_path_at(int dirfd, const char *path, int flags)
{
    return raw_syscall3(SYS_unlinkat, dirfd, (long)(uintptr_t)path, flags) == 0
        ? 0
        : -1;
}

static int open_directory_at(int dirfd, const char *path)
{
    long descriptor = raw_syscall4(SYS_openat, dirfd, (long)(uintptr_t)path,
        O_RDONLY | O_DIRECTORY, 0);

    return descriptor < 0 ? -1 : (int)descriptor;
}

static int same_regular_file_at(int oldfd, const char *old_path, int newfd,
    const char *new_path)
{
    struct stat existing;
    struct stat observed;

    if (raw_syscall4(SYS_newfstatat, oldfd, (long)(uintptr_t)old_path,
        (long)(uintptr_t)&existing, 0) != 0)
        return 1;
    if (raw_syscall4(SYS_newfstatat, newfd, (long)(uintptr_t)new_path,
        (long)(uintptr_t)&observed, 0) != 0)
        return 2;
    if (!S_ISREG(existing.st_mode) || !S_ISREG(observed.st_mode))
        return 3;
    if (existing.st_dev != observed.st_dev || existing.st_ino != observed.st_ino)
        return 4;
    return existing.st_nlink >= 2 && observed.st_nlink >= 2 ? 0 : 5;
}

static int check_symlink_inode_at(int dirfd, const char *path)
{
    struct stat observed;

    if (raw_syscall4(SYS_newfstatat, dirfd, (long)(uintptr_t)path,
        (long)(uintptr_t)&observed, AT_SYMLINK_NOFOLLOW) != 0)
        return 1;
    return S_ISLNK(observed.st_mode) ? 0 : 2;
}

int crabc_x86_64_linkat_probe(void)
{
    static const char parent[] = "linkat-parent";
    static const char existing_directory[] = "existing-directory";
    static const char new_directory[] = "new-directory";
    static const char source[] = "source";
    static const char source_symlink[] = "source-symlink";
    static const char candidate_link[] = "candidate-link";
    static const char raw_link[] = "raw-link-comparator";
    static const char followed_link[] = "followed-link";
    static const char bad_old_link[] = "bad-old-link";
    static const char bad_new_link[] = "bad-new-link";
    static const char null_old_link[] = "null-old-link";
    static const char missing_source[] = "missing-source";
    int parentfd = -1;
    int oldfd = -1;
    int newfd = -1;
    long sourcefd;
    int status = 0;

    if (raw_syscall3(SYS_mkdirat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)parent, 0700) != 0)
        return 1;
    parentfd = open_directory_at(FIXTURE_AT_FDCWD, parent);
    if (parentfd < 0) {
        (void)remove_path_at(FIXTURE_AT_FDCWD, parent, AT_REMOVEDIR);
        return 2;
    }
    if (raw_syscall3(SYS_mkdirat, parentfd,
        (long)(uintptr_t)existing_directory, 0700) != 0 ||
        raw_syscall3(SYS_mkdirat, parentfd,
        (long)(uintptr_t)new_directory, 0700) != 0)
        status = 3;
    if (status == 0) {
        oldfd = open_directory_at(parentfd, existing_directory);
        newfd = open_directory_at(parentfd, new_directory);
        if (oldfd < 0 || newfd < 0)
            status = 4;
    }
    if (status == 0) {
        sourcefd = raw_syscall4(SYS_openat, oldfd, (long)(uintptr_t)source,
            O_CREAT | O_EXCL | O_RDWR, 0600);
        if (sourcefd < 0 || raw_syscall1(SYS_close, sourcefd) != 0)
            status = 5;
    }
    if (status == 0) {
        errno = EINTR;
        if (linkat(oldfd, source, newfd, candidate_link, 0) != 0)
            status = 10;
        else if (errno != EINTR)
            status = 11;
        else {
            int same = same_regular_file_at(oldfd, source, newfd, candidate_link);
            if (same != 0)
                status = 20 + same;
        }
    }
    if (status == 0) {
        errno = 0;
        if (linkat(oldfd, source, newfd, candidate_link, 0) != -1 ||
            errno != EEXIST)
            status = 30;
    }
    if (status == 0) {
        if (raw_syscall5(SYS_linkat, oldfd, (long)(uintptr_t)source, newfd,
            (long)(uintptr_t)raw_link, 0) != 0)
            status = 31;
        else {
            int same = same_regular_file_at(oldfd, source, newfd, raw_link);
            if (same != 0)
                status = 40 + same;
        }
    }
    if (status == 0) {
        if (raw_syscall3(SYS_symlinkat, (long)(uintptr_t)source, oldfd,
            (long)(uintptr_t)source_symlink) != 0)
            status = 50;
        else if (check_symlink_inode_at(oldfd, source_symlink) != 0)
            status = 51;
    }
    if (status == 0) {
        errno = EINTR;
        if (linkat(oldfd, source_symlink, newfd, followed_link,
            AT_SYMLINK_FOLLOW) != 0)
            status = 52;
        else if (errno != EINTR)
            status = 53;
        else {
            int same = same_regular_file_at(oldfd, source, newfd, followed_link);
            if (same != 0)
                status = 60 + same;
        }
    }
    if (status == 0) {
        errno = 0;
        if (linkat(-1, source, newfd, bad_old_link, 0) != -1 || errno != EBADF)
            status = 70;
    }
    if (status == 0) {
        errno = 0;
        if (linkat(oldfd, source, -1, bad_new_link, 0) != -1 || errno != EBADF)
            status = 71;
    }
    if (status == 0) {
        errno = 0;
        if (linkat(oldfd, (const char *)0, newfd, null_old_link, 0) != -1 ||
            errno != EFAULT)
            status = 72;
    }
    if (status == 0) {
        errno = 0;
        if (linkat(oldfd, source, newfd, (const char *)0, 0) != -1 ||
            errno != EFAULT)
            status = 73;
    }
    if (status == 0) {
        errno = 0;
        if (linkat(oldfd, missing_source, newfd, "missing-link", 0) != -1 ||
            errno != ENOENT)
            status = 74;
    }
    if (status == 0) {
        errno = 0;
        if (linkat(oldfd, source, newfd, "invalid-flags", 0x7fffffff) != -1 ||
            errno != EINVAL)
            status = 75;
    }

    if (newfd >= 0) {
        (void)remove_path_at(newfd, candidate_link, 0);
        (void)remove_path_at(newfd, raw_link, 0);
        (void)remove_path_at(newfd, followed_link, 0);
        (void)remove_path_at(newfd, bad_old_link, 0);
        (void)remove_path_at(newfd, bad_new_link, 0);
        (void)remove_path_at(newfd, null_old_link, 0);
        (void)remove_path_at(newfd, "missing-link", 0);
        (void)remove_path_at(newfd, "invalid-flags", 0);
    }
    if (oldfd >= 0) {
        (void)remove_path_at(oldfd, source_symlink, 0);
        (void)remove_path_at(oldfd, source, 0);
    }
    if (oldfd >= 0 && raw_syscall1(SYS_close, oldfd) != 0 && status == 0)
        status = 90;
    if (newfd >= 0 && raw_syscall1(SYS_close, newfd) != 0 && status == 0)
        status = 91;
    if (parentfd >= 0) {
        if (remove_path_at(parentfd, existing_directory, AT_REMOVEDIR) != 0 &&
            status == 0)
            status = 92;
        if (remove_path_at(parentfd, new_directory, AT_REMOVEDIR) != 0 &&
            status == 0)
            status = 93;
        if (raw_syscall1(SYS_close, parentfd) != 0 && status == 0)
            status = 94;
    }
    if (remove_path_at(FIXTURE_AT_FDCWD, parent, AT_REMOVEDIR) != 0 &&
        status == 0)
        status = 95;
    return status;
}

#ifndef CRABC_LINKAT_FREESTANDING
int main(void)
{
    return crabc_x86_64_linkat_probe();
}
#endif
