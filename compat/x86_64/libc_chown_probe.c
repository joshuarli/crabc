/* Static crabc-libc x86-64 chown compatibility fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. Raw mkdirat,
 * symlinkat, newfstatat, chown, and unlinkat calls create, observe, compare,
 * and remove only fixture-owned entries. `chown` is the only candidate C
 * entry. A dangling symlink and all-ones no-change uid/gid words prove that
 * the selected call follows its final component without requiring CAP_CHOWN:
 * it reports ENOENT where the separately selected lchown leaf succeeds. This
 * is not a wider ownership/credential API, pathname policy, allocation, CWD
 * state, or Rust filesystem facade.
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
    FIXTURE_EFAULT = 14,
    FIXTURE_EINTR = 4,
    FIXTURE_ENOENT = 2,
};

_Static_assert(sizeof(uid_t) == 4 && _Alignof(uid_t) == 4 &&
                   __builtin_types_compatible_p(uid_t, unsigned int),
               "x86 chown uid_t ABI");
_Static_assert(sizeof(gid_t) == 4 && _Alignof(gid_t) == 4 &&
                   __builtin_types_compatible_p(gid_t, unsigned int),
               "x86 chown gid_t ABI");
_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 LP64 stat record");
_Static_assert(S_IFMT == 0170000 && S_IFLNK == 0120000,
               "x86 symbolic-link mode constants");
_Static_assert(AT_FDCWD == FIXTURE_AT_FDCWD &&
                   AT_REMOVEDIR == FIXTURE_AT_REMOVEDIR &&
                   AT_SYMLINK_NOFOLLOW == FIXTURE_AT_SYMLINK_NOFOLLOW,
               "x86 chown fixture constants");
_Static_assert(SYS_chown == 92 && SYS_mkdirat == 258 &&
                   SYS_newfstatat == 262 && SYS_unlinkat == 263 &&
                   SYS_symlinkat == 266,
               "Linux x86 chown fixture syscall numbers");
_Static_assert(EFAULT == FIXTURE_EFAULT && EINTR == FIXTURE_EINTR &&
                   ENOENT == FIXTURE_ENOENT,
               "Linux x86 chown errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&chown),
    int (*)(const char *, uid_t, gid_t)), "chown declaration");

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

static int check_dangling_symlink(const char *path)
{
    struct stat observed;

    if (raw_syscall4(SYS_newfstatat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)path, (long)(uintptr_t)&observed,
        AT_SYMLINK_NOFOLLOW) != 0)
        return 1;
    return S_ISLNK(observed.st_mode) ? 0 : 2;
}

int crabc_x86_64_chown_probe(void)
{
    static const char directory[] = "chown-root";
    static const char dangling[] = "chown-root/dangling";
    static const char missing[] = "chown-root/missing";
    static const char target[] = "does-not-exist";
    int status = 0;

    if (raw_syscall3(SYS_mkdirat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)directory, 0700) != 0)
        return 1;
    if (raw_syscall3(SYS_symlinkat, (long)(uintptr_t)target,
        FIXTURE_AT_FDCWD, (long)(uintptr_t)dangling) != 0)
        status = 2;
    if (status == 0 && check_dangling_symlink(dangling) != 0)
        status = 3;
    if (status == 0) {
        /* A successful selected call leaves stale errno untouched. */
        errno = EINTR;
        if (chown(directory, (uid_t)-1, (gid_t)-1) != 0)
            status = 10;
        else if (errno != EINTR)
            status = 11;
    }
    if (status == 0) {
        if (raw_syscall3(SYS_chown, (long)(uintptr_t)directory,
            (long)(uint32_t)UINT32_MAX, (long)(uint32_t)UINT32_MAX) != 0)
            status = 12;
    }
    if (status == 0) {
        errno = 0;
        if (chown(dangling, (uid_t)-1, (gid_t)-1) != -1 || errno != ENOENT)
            status = 20;
        else if (raw_syscall3(SYS_chown, (long)(uintptr_t)dangling,
            (long)(uint32_t)UINT32_MAX, (long)(uint32_t)UINT32_MAX) !=
            -FIXTURE_ENOENT)
            status = 21;
    }
    if (status == 0) {
        errno = 0;
        if (chown(missing, (uid_t)-1, (gid_t)-1) != -1 || errno != ENOENT)
            status = 30;
    }
    if (status == 0) {
        errno = 0;
        if (chown((const char *)0, (uid_t)-1, (gid_t)-1) != -1 ||
            errno != EFAULT)
            status = 31;
    }
    if (status == 0) {
        errno = 0;
        if (chown("", (uid_t)-1, (gid_t)-1) != -1 || errno != ENOENT)
            status = 32;
    }

    if (remove_path_at(FIXTURE_AT_FDCWD, dangling, 0) != 0 && status == 0)
        status = 40;
    if (remove_path_at(FIXTURE_AT_FDCWD, directory, AT_REMOVEDIR) != 0 &&
        status == 0)
        status = 41;
    return status;
}

#ifndef CRABC_CHOWN_FREESTANDING
int main(void)
{
    return crabc_x86_64_chown_probe();
}
#endif
