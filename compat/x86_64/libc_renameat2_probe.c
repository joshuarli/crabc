/* Static crabc-libc x86-64 GNU renameat2 compatibility fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. Fixture-local raw
 * syscalls create, observe, compare, and clean entries under one opened
 * directory. `renameat2` is the only candidate C entry. This proves musl's
 * zero-flag renameat route plus GNU no-replace/exchange/error behavior, not
 * ordinary rename, a pathname lifecycle policy, CWD state, allocation, or a
 * Rust filesystem facade.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

enum {
    FIXTURE_AT_FDCWD = -100,
    FIXTURE_AT_REMOVEDIR = 0x200,
    FIXTURE_EEXIST = 17,
    FIXTURE_EFAULT = 14,
    FIXTURE_EINTR = 4,
    FIXTURE_EINVAL = 22,
    FIXTURE_ENOENT = 2,
    FIXTURE_O_CREAT = 0100,
    FIXTURE_O_DIRECTORY = 0200000,
    FIXTURE_O_EXCL = 0200,
    FIXTURE_O_RDONLY = 00,
    FIXTURE_O_RDWR = 02,
};

_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
               "x86 renameat2 int ABI");
_Static_assert(sizeof(unsigned) == 4 && _Alignof(unsigned) == 4,
               "x86 renameat2 unsigned ABI");
_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 LP64 stat record");
_Static_assert(RENAME_NOREPLACE == 1 && RENAME_EXCHANGE == 2 &&
                   RENAME_WHITEOUT == 4,
               "x86 renameat2 GNU flags");
_Static_assert(AT_FDCWD == FIXTURE_AT_FDCWD &&
                   AT_REMOVEDIR == FIXTURE_AT_REMOVEDIR &&
                   O_CREAT == FIXTURE_O_CREAT && O_DIRECTORY == FIXTURE_O_DIRECTORY &&
                   O_EXCL == FIXTURE_O_EXCL && O_RDONLY == FIXTURE_O_RDONLY &&
                   O_RDWR == FIXTURE_O_RDWR,
               "x86 renameat2 fixture constants");
_Static_assert(SYS_close == 3 && SYS_openat == 257 && SYS_mkdirat == 258 &&
                   SYS_newfstatat == 262 && SYS_unlinkat == 263 &&
                   SYS_renameat == 264 && SYS_renameat2 == 316,
               "Linux x86 renameat2 fixture syscall numbers");
_Static_assert(EEXIST == FIXTURE_EEXIST && EFAULT == FIXTURE_EFAULT &&
                   EINTR == FIXTURE_EINTR && EINVAL == FIXTURE_EINVAL &&
                   ENOENT == FIXTURE_ENOENT,
               "Linux x86 renameat2 errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&renameat2),
    int (*)(int, const char *, int, const char *, unsigned)),
    "renameat2 declaration");

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

static int open_directory_at(int directory_descriptor, const char *path)
{
    long descriptor = raw_syscall4(SYS_openat, directory_descriptor,
        (long)(uintptr_t)path, O_RDONLY | O_DIRECTORY, 0);

    return descriptor < 0 ? -1 : (int)descriptor;
}

static int create_regular_at(int directory_descriptor, const char *path)
{
    long descriptor = raw_syscall4(SYS_openat, directory_descriptor,
        (long)(uintptr_t)path, O_CREAT | O_EXCL | O_RDWR, 0600);

    if (descriptor < 0)
        return -1;
    return raw_syscall1(SYS_close, descriptor) == 0 ? 0 : -1;
}

static int stat_at(int directory_descriptor, const char *path, struct stat *value)
{
    return raw_syscall4(SYS_newfstatat, directory_descriptor,
        (long)(uintptr_t)path, (long)(uintptr_t)value, 0) == 0 ? 0 : -1;
}

static int same_inode(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static void remove_at(int directory_descriptor, const char *path, int flags)
{
    (void)raw_syscall3(SYS_unlinkat, directory_descriptor,
        (long)(uintptr_t)path, flags);
}

static void cleanup(int rootfd)
{
    static const char parent[] = "renameat2-parent";
    static const char names[][20] = {
        "source", "destination", "one", "two", "raw-source", "raw-destination",
    };
    unsigned index;

    if (rootfd >= 0) {
        for (index = 0; index < sizeof(names) / sizeof(names[0]); index++)
            remove_at(rootfd, names[index], 0);
        (void)raw_syscall1(SYS_close, rootfd);
    }
    remove_at(FIXTURE_AT_FDCWD, parent, FIXTURE_AT_REMOVEDIR);
}

int crabc_x86_64_renameat2_probe(void)
{
    static const char parent[] = "renameat2-parent";
    static const char source[] = "source";
    static const char destination[] = "destination";
    static const char one[] = "one";
    static const char two[] = "two";
    static const char raw_source[] = "raw-source";
    static const char raw_destination[] = "raw-destination";
    struct stat source_before;
    struct stat destination_before;
    struct stat destination_after;
    struct stat one_before;
    struct stat two_before;
    struct stat one_after;
    struct stat two_after;
    struct stat raw_before;
    struct stat raw_after;
    int rootfd = -1;
    int status = 0;

    if (raw_syscall3(SYS_mkdirat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)parent, 0700) != 0)
        return 1;
    rootfd = open_directory_at(FIXTURE_AT_FDCWD, parent);
    if (rootfd < 0) {
        cleanup(rootfd);
        return 2;
    }
    if (create_regular_at(rootfd, source) != 0 ||
        create_regular_at(rootfd, destination) != 0 ||
        stat_at(rootfd, source, &source_before) != 0 ||
        stat_at(rootfd, destination, &destination_before) != 0) {
        status = 3;
        goto done;
    }

    errno = EINTR;
    if (renameat2(rootfd, source, rootfd, destination, 0) != 0 || errno != EINTR) {
        status = 10;
        goto done;
    }
    if (stat_at(rootfd, destination, &destination_after) != 0 ||
        !same_inode(&source_before, &destination_after) ||
        stat_at(rootfd, source, &source_before) == 0) {
        status = 11;
        goto done;
    }

    if (create_regular_at(rootfd, one) != 0 || create_regular_at(rootfd, two) != 0 ||
        stat_at(rootfd, one, &one_before) != 0 || stat_at(rootfd, two, &two_before) != 0) {
        status = 20;
        goto done;
    }
    errno = 0;
    if (renameat2(rootfd, one, rootfd, two, RENAME_NOREPLACE) != -1 || errno != EEXIST) {
        status = 21;
        goto done;
    }
    if (stat_at(rootfd, one, &one_after) != 0 || stat_at(rootfd, two, &two_after) != 0 ||
        !same_inode(&one_before, &one_after) || !same_inode(&two_before, &two_after)) {
        status = 22;
        goto done;
    }

    errno = EINTR;
    if (renameat2(rootfd, one, rootfd, two, RENAME_EXCHANGE) != 0 || errno != EINTR) {
        status = 30;
        goto done;
    }
    if (stat_at(rootfd, one, &one_after) != 0 || stat_at(rootfd, two, &two_after) != 0 ||
        !same_inode(&two_before, &one_after) || !same_inode(&one_before, &two_after)) {
        status = 31;
        goto done;
    }

    errno = 0;
    if (renameat2(rootfd, one, rootfd, two,
        RENAME_EXCHANGE | RENAME_WHITEOUT) != -1 || errno != EINVAL) {
        status = 40;
        goto done;
    }
    errno = 0;
    if (renameat2(rootfd, "missing", rootfd, "missing-target", 0) != -1 ||
        errno != ENOENT) {
        status = 41;
        goto done;
    }
    errno = 0;
    if (renameat2(rootfd, (const char *)0, rootfd, two, 0) != -1 || errno != EFAULT) {
        status = 42;
        goto done;
    }

    if (create_regular_at(rootfd, raw_source) != 0 ||
        create_regular_at(rootfd, raw_destination) != 0 ||
        stat_at(rootfd, raw_source, &raw_before) != 0 ||
        raw_syscall4(SYS_renameat, rootfd, (long)(uintptr_t)raw_source,
            rootfd, (long)(uintptr_t)raw_destination) != 0 ||
        stat_at(rootfd, raw_destination, &raw_after) != 0 ||
        !same_inode(&raw_before, &raw_after)) {
        status = 50;
        goto done;
    }

done:
    cleanup(rootfd);
    return status;
}

#ifndef CRABC_RENAMEAT2_FREESTANDING
int main(void)
{
    return crabc_x86_64_renameat2_probe();
}
#endif
