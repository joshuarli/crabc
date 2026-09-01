/* Native Linux/x86-64 ftw/nftw C ABI regression.
 *
 * One project-header body first runs ordinary traversal through pinned musl
 * 1.2.6, then runs the allocation-free opt-in crabc archive. The candidate
 * additionally proves the frozen AArch64 FTW_CHDIR profile: callback-visible
 * CWD, re-entry after a callback changes CWD, and restoration after normal and
 * callback-abort exits. This fixture selects neither scandir nor a C allocator,
 * general filesystem policy, pthread cancellation, libc.so, CRT, loader,
 * sysroot, family completion, promotion, or public x86 support.
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
#include <ftw.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

enum {
    CRABC_AT_FDCWD = -100,
    CRABC_AT_REMOVEDIR = 0x200,
    CRABC_PATH_MAX = 4096,
};

typedef int (*ftw_callback_signature)(const char *, const struct stat *, int);
typedef int (*nftw_callback_signature)(const char *, const struct stat *, int,
    struct FTW *);
typedef int (*ftw_signature)(const char *, ftw_callback_signature, int);
typedef int (*nftw_signature)(const char *, nftw_callback_signature, int, int);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86-64 LP64 widths");
_Static_assert(sizeof(struct FTW) == 8 && _Alignof(struct FTW) == 4 &&
    offsetof(struct FTW, base) == 0 && offsetof(struct FTW, level) == 4,
    "FTW public record");
_Static_assert(FTW_F == 1 && FTW_D == 2 && FTW_DNR == 3 && FTW_NS == 4 &&
    FTW_SL == 5 && FTW_DP == 6 && FTW_SLN == 7 && FTW_PHYS == 1 &&
    FTW_MOUNT == 2 && FTW_CHDIR == 4 && FTW_DEPTH == 8,
    "FTW values");
_Static_assert(SYS_close == 3 && SYS_openat == 257 && SYS_mkdirat == 258 &&
    SYS_unlinkat == 263 && SYS_symlinkat == 266,
    "Linux x86-64 traversal fixture syscall numbers");
_Static_assert(CRABC_TYPE_IS(__typeof__(&ftw), ftw_signature),
    "ftw declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&nftw), nftw_signature),
    "nftw declaration");

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long argument1, long argument2)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile("syscall"
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

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_failed(long result)
{
    return result < 0 && result >= -4095;
}

static int raw_create_directory(const char *path)
{
    return raw_syscall3(SYS_mkdirat, CRABC_AT_FDCWD, (long)path, 0700) == 0;
}

static int raw_create_file(const char *path)
{
    long descriptor = raw_syscall4(SYS_openat, CRABC_AT_FDCWD, (long)path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    if (raw_failed(descriptor)) return 0;
    return raw_syscall1(SYS_close, descriptor) == 0;
}

static int raw_create_symlink(const char *target, const char *path)
{
    return raw_syscall3(SYS_symlinkat, (long)target, CRABC_AT_FDCWD,
        (long)path) == 0;
}

static int raw_change_mode(const char *path, long mode)
{
    return raw_syscall2(SYS_chmod, (long)path, mode) == 0;
}

static int raw_remove(const char *path, int flags)
{
    return raw_syscall3(SYS_unlinkat, CRABC_AT_FDCWD, (long)path, flags) == 0;
}

static int strings_equal(const char *left, const char *right)
{
    size_t index = 0;

    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int string_starts_with(const char *string, const char *prefix)
{
    size_t index = 0;

    while (prefix[index] != '\0') {
        if (string[index] != prefix[index]) return 0;
        ++index;
    }
    return 1;
}

static int append_bytes(char *destination, size_t capacity, const char *suffix)
{
    size_t destination_length = 0;
    size_t suffix_length = 0;

    while (destination[destination_length] != '\0') ++destination_length;
    while (suffix[suffix_length] != '\0') ++suffix_length;
    if (destination_length + suffix_length >= capacity) return 0;
    for (suffix_length = 0; suffix[suffix_length] != '\0'; ++suffix_length) {
        destination[destination_length + suffix_length] = suffix[suffix_length];
    }
    destination[destination_length + suffix_length] = '\0';
    return 1;
}

static int ftw_calls;
static int ftw_directories;
static int ftw_files;
static int ftw_links;
static int ftw_bad;

static int visit_ftw(const char *path, const struct stat *metadata, int type)
{
    if (path == NULL || metadata == NULL) return 91;
    ++ftw_calls;
    if (type == FTW_D) ++ftw_directories;
    else if (type == FTW_F) ++ftw_files;
    else if (type == FTW_SL) ++ftw_links;
    else ftw_bad = 1;
    return 0;
}

static int check_ftw_physical(void)
{
    ftw_calls = 0;
    ftw_directories = 0;
    ftw_files = 0;
    ftw_links = 0;
    ftw_bad = 0;
    errno = E2BIG;
    if (ftw("walk-tree", visit_ftw, 8) != 0 || errno != E2BIG ||
        ftw_calls != 6 || ftw_directories != 2 || ftw_files != 2 ||
        ftw_links != 2 || ftw_bad) {
        return 1;
    }
    return 0;
}

static int depth_calls;
static int depth_directories;
static int depth_root_last;
static int depth_bad_info;

static int visit_depth(const char *path, const struct stat *metadata, int type,
    struct FTW *info)
{
    if (metadata == NULL || info == NULL || info->level < 0 || info->base < 0)
        return 92;
    ++depth_calls;
    if (type == FTW_DP) ++depth_directories;
    if (strings_equal(path, "walk-tree")) {
        if (type != FTW_DP || info->level != 0 || info->base != 0 ||
            depth_calls != 6) {
            depth_bad_info = 1;
        }
        depth_root_last = 1;
    }
    return 0;
}

static int check_nftw_depth_and_mount(void)
{
    depth_calls = 0;
    depth_directories = 0;
    depth_root_last = 0;
    depth_bad_info = 0;
    errno = EDOM;
    if (nftw("walk-tree", visit_depth, 8,
            FTW_PHYS | FTW_DEPTH | FTW_MOUNT) != 0 || errno != EDOM ||
        depth_calls != 6 || depth_directories != 2 || !depth_root_last ||
        depth_bad_info) {
        return 1;
    }
    return 0;
}

static int limited_calls;
static int limited_saw_nested_file;

static int visit_limited(const char *path, const struct stat *metadata, int type,
    struct FTW *info)
{
    (void)metadata;
    (void)type;
    (void)info;
    ++limited_calls;
    if (strings_equal(path, "walk-tree/nested/beta")) limited_saw_nested_file = 1;
    return 0;
}

static int check_fd_limit(void)
{
    limited_calls = 0;
    limited_saw_nested_file = 0;
    if (nftw("walk-tree", visit_limited, 1, FTW_PHYS) != 0 ||
        limited_calls != 5 || limited_saw_nested_file) {
        return 1;
    }
    return 0;
}

static int abort_calls;

static int callback_abort(const char *path, const struct stat *metadata, int type,
    struct FTW *info)
{
    (void)path;
    (void)metadata;
    (void)type;
    (void)info;
    ++abort_calls;
    return 77;
}

static int check_callback_result_and_fd_zero(void)
{
    abort_calls = 0;
    if (nftw("walk-tree", callback_abort, 8, FTW_PHYS) != 77 || abort_calls != 1)
        return 1;
    errno = E2BIG;
    abort_calls = 0;
    if (nftw("does-not-exist", callback_abort, 0, FTW_PHYS) != 0 ||
        abort_calls != 0 || errno != E2BIG) {
        return 2;
    }
    errno = 0;
    if (nftw("does-not-exist", callback_abort, 8, FTW_PHYS) != -1 ||
        errno != ENOENT) {
        return 3;
    }
    return 0;
}

static int dnr_calls;
static int dnr_bad;

static int visit_dnr(const char *path, const struct stat *metadata, int type,
    struct FTW *info)
{
    (void)info;
    if (path == NULL || metadata == NULL || type != FTW_DNR) dnr_bad = 1;
    ++dnr_calls;
    return 0;
}

/*
 * Musl changes an unreadable directory's pre-order callback type to FTW_DNR,
 * then returns success after that callback. Exercise the one branch that is
 * easy to erase when a walker remembers its directory classification before
 * its failed readability probe. Root drops only its effective uid and retains
 * saved uid zero long enough to restore the fixture's process state.
 */
static int check_directory_not_readable(void)
{
    int dropped_root = 0;
    int result;
    int observed_errno;

    if (!raw_create_directory("walk-denied")) return 1;
    if (!raw_change_mode("walk-denied", 0000)) return 2;
    if (raw_syscall0(SYS_geteuid) == 0) {
        if (raw_syscall3(SYS_setresuid, 0, 65534, 0) != 0) return 3;
        dropped_root = 1;
    }

    dnr_calls = 0;
    dnr_bad = 0;
    errno = E2BIG;
    result = nftw("walk-denied", visit_dnr, 8, FTW_PHYS);
    observed_errno = errno;

    if (dropped_root && raw_syscall3(SYS_setresuid, 0, 0, 0) != 0) return 4;
    if (!raw_change_mode("walk-denied", 0700)) return 5;
    if (!raw_remove("walk-denied", CRABC_AT_REMOVEDIR)) return 6;
    if (result != 0 || dnr_calls != 1 || dnr_bad || observed_errno != EACCES)
        return 7;
    return 0;
}

#ifdef CRABC_TRAVERSAL_CANDIDATE
static char entry_cwd[CRABC_PATH_MAX + 1];
static char root_cwd[CRABC_PATH_MAX + 1];
static char nested_cwd[CRABC_PATH_MAX + 1];
static int chdir_calls;
static int chdir_matches;
static int chdir_changed;

static int visit_chdir(const char *path, const struct stat *metadata, int type,
    struct FTW *info)
{
    char observed[CRABC_PATH_MAX + 1];
    const char *expected;

    (void)metadata;
    (void)info;
    ++chdir_calls;
    if (getcwd(observed, sizeof(observed)) == NULL) return 93;
    if (strings_equal(path, "walk-tree") ||
        (string_starts_with(path, "walk-tree/") &&
            !strings_equal(path, "walk-tree/nested") &&
            !string_starts_with(path, "walk-tree/nested/"))) {
        expected = root_cwd;
    } else if (strings_equal(path, "walk-tree/nested") ||
        string_starts_with(path, "walk-tree/nested/")) {
        expected = nested_cwd;
    } else {
        return 94;
    }
    if (strings_equal(observed, expected)) ++chdir_matches;
    /* A file callback can change CWD too; the enclosing directory must repair
     * it before every later child callback. */
    if (!chdir_changed && type == FTW_F &&
        strings_equal(path, "walk-tree/alpha")) {
        chdir_changed = 1;
        if (chdir("/") != 0) return 95;
    }
    return 0;
}

static int check_frozen_chdir_profile(void)
{
    char after[CRABC_PATH_MAX + 1];

    if (getcwd(entry_cwd, sizeof(entry_cwd)) == NULL) {
        return 1;
    }
    /* Copy without relying on a string-library leaf. */
    {
        size_t index = 0;
        while (entry_cwd[index] != '\0') {
            root_cwd[index] = entry_cwd[index];
            ++index;
        }
        root_cwd[index] = '\0';
    }
    if (!append_bytes(root_cwd, sizeof(root_cwd), "/walk-tree")) return 2;
    {
        size_t index = 0;
        while (root_cwd[index] != '\0') {
            nested_cwd[index] = root_cwd[index];
            ++index;
        }
        nested_cwd[index] = '\0';
    }
    if (!append_bytes(nested_cwd, sizeof(nested_cwd), "/nested")) return 3;

    chdir_calls = 0;
    chdir_matches = 0;
    chdir_changed = 0;
    if (nftw("walk-tree", visit_chdir, 8, FTW_PHYS | FTW_CHDIR) != 0 ||
        chdir_calls != 6 || chdir_matches != 6 || !chdir_changed ||
        getcwd(after, sizeof(after)) == NULL || !strings_equal(after, entry_cwd)) {
        return 4;
    }
    if (nftw("walk-tree", callback_abort, 8, FTW_PHYS | FTW_CHDIR) != 77 ||
        getcwd(after, sizeof(after)) == NULL || !strings_equal(after, entry_cwd)) {
        return 5;
    }
    return 0;
}
#endif

int crabc_x86_64_filesystem_traversal_probe(void)
{
    int status = 0;

    if (!raw_create_directory("walk-tree") ||
        !raw_create_directory("walk-tree/nested") ||
        !raw_create_file("walk-tree/alpha") ||
        !raw_create_file("walk-tree/nested/beta") ||
        !raw_create_symlink("alpha", "walk-tree/link") ||
        !raw_create_symlink("missing", "walk-tree/dangling")) {
        status = 1;
        goto cleanup;
    }
    if (check_ftw_physical() != 0) {
        status = 10;
        goto cleanup;
    }
    if (check_nftw_depth_and_mount() != 0) {
        status = 20;
        goto cleanup;
    }
    if (check_fd_limit() != 0) {
        status = 30;
        goto cleanup;
    }
    if (check_callback_result_and_fd_zero() != 0) {
        status = 40;
        goto cleanup;
    }
    if (check_directory_not_readable() != 0) {
        status = 45;
        goto cleanup;
    }
#ifdef CRABC_TRAVERSAL_CANDIDATE
    if (check_frozen_chdir_profile() != 0) {
        status = 50;
        goto cleanup;
    }
#endif

cleanup:
    if (!raw_remove("walk-tree/dangling", 0) && status == 0) status = 60;
    if (!raw_remove("walk-tree/link", 0) && status == 0) status = 61;
    if (!raw_remove("walk-tree/nested/beta", 0) && status == 0) status = 62;
    if (!raw_remove("walk-tree/alpha", 0) && status == 0) status = 63;
    if (!raw_remove("walk-tree/nested", CRABC_AT_REMOVEDIR) && status == 0) status = 64;
    if (!raw_remove("walk-tree", CRABC_AT_REMOVEDIR) && status == 0) status = 65;
    return status;
}

#ifndef CRABC_TRAVERSAL_FREESTANDING
int main(void)
{
    return crabc_x86_64_filesystem_traversal_probe();
}
#endif
