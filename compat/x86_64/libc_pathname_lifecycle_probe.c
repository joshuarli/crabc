/* Native Linux/x86-64 static pathname-lifecycle C ABI fixture.
 *
 * One project-header C body runs first through pinned musl 1.2.6 and then
 * through the selected freestanding crabc archive. It exercises the bounded
 * pathname mutation/lifecycle leaf only: CWD, caller-buffer getcwd, directory
 * creation/removal, links, mode changes, O_PATH fchmod fallback, truncation,
 * and remove's EISDIR retry. It is deliberately not a general filesystem,
 * allocator, CRT, loader, sysroot, or public x86 support claim.
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
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8 && sizeof(off_t) == 8 &&
    sizeof(mode_t) == 4 && sizeof(struct stat) == 144,
    "x86 pathname lifecycle layouts");
_Static_assert(SYS_truncate == 76 && SYS_getcwd == 79 && SYS_chdir == 80 &&
    SYS_rename == 82 && SYS_mkdir == 83 && SYS_rmdir == 84 && SYS_link == 86 &&
    SYS_unlink == 87 && SYS_symlink == 88 && SYS_readlink == 89 &&
    SYS_chmod == 90 && SYS_fchmod == 91 && SYS_fcntl == 72,
    "x86 pathname lifecycle syscall numbers");
_Static_assert(F_GETFD == 1 && O_CLOEXEC == 02000000 && O_PATH == 010000000,
    "x86 selected fchmod fallback constants");
_Static_assert(S_IFMT == 0170000 && S_IFDIR == 0040000 && S_IFREG == 0100000 &&
    S_IFLNK == 0120000 && S_IRWXU == 0700,
    "x86 selected pathname mode constants");
_Static_assert(CRABC_TYPE_IS(__typeof__(&chdir), int (*)(const char *)) &&
    CRABC_TYPE_IS(__typeof__(&getcwd), char *(*)(char *, size_t)) &&
    CRABC_TYPE_IS(__typeof__(&mkdir), int (*)(const char *, mode_t)) &&
    CRABC_TYPE_IS(__typeof__(&unlink), int (*)(const char *)) &&
    CRABC_TYPE_IS(__typeof__(&rmdir), int (*)(const char *)) &&
    CRABC_TYPE_IS(__typeof__(&remove), int (*)(const char *)) &&
    CRABC_TYPE_IS(__typeof__(&rename), int (*)(const char *, const char *)) &&
    CRABC_TYPE_IS(__typeof__(&link), int (*)(const char *, const char *)) &&
    CRABC_TYPE_IS(__typeof__(&symlink), int (*)(const char *, const char *)) &&
    CRABC_TYPE_IS(__typeof__(&readlink), ssize_t (*)(const char *, char *, size_t)) &&
    CRABC_TYPE_IS(__typeof__(&chmod), int (*)(const char *, mode_t)) &&
    CRABC_TYPE_IS(__typeof__(&fchmod), int (*)(int, mode_t)) &&
    CRABC_TYPE_IS(__typeof__(&truncate), int (*)(const char *, off_t)),
    "selected pathname lifecycle declarations");

static int expect_error(int result, int error)
{
    return result == -1 && errno == error;
}

static int bytes_equal(const char *left, const char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static int same_file(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int check_getcwd_extension(void)
{
#ifdef CRABC_PATHNAME_LIFECYCLE_FREESTANDING
    errno = 0;
    return getcwd(0, 0) == 0 && errno == EINVAL;
#else
    char *allocated;

    errno = E2BIG;
    allocated = getcwd(0, 0);
    /* The pinned-musl reference owns the allocation extension. The static
     * candidate consciously rejects it so its C surface stays allocation-free;
     * this process exits immediately after the fixture and need not free this
     * reference-only allocation. */
    return allocated != 0 && allocated[0] == '/' && errno == E2BIG;
#endif
}

int crabc_x86_64_pathname_lifecycle_probe(void)
{
    static const char root[] = "root";
    static const char nested[] = "nested";
    static const char empty_directory[] = "empty-directory";
    static const char file[] = "file";
    static const char hard[] = "hard";
    static const char symbolic[] = "symbolic";
    static const char renamed[] = "renamed";
    static const char missing[] = "missing";
    char current_directory[512];
    char too_small[1];
    char target[8] = { 0 };
    struct stat renamed_stat;
    struct stat hard_stat;
    struct stat observed;
    int ordinary = -1;
    int path_only = -1;
    int status = 0;

    errno = ERANGE;
    if (mkdir(root, 0700) != 0 || errno != ERANGE) {
        status = 1;
        goto finish;
    }
    if (chdir(root) != 0) {
        status = 2;
        goto finish;
    }
    errno = E2BIG;
    if (getcwd(current_directory, sizeof(current_directory)) != current_directory ||
        current_directory[0] != '/' || errno != E2BIG) {
        status = 3;
        goto finish;
    }
    errno = 0;
    if (getcwd(current_directory, 0) != 0 || errno != EINVAL) {
        status = 4;
        goto finish;
    }
    errno = 0;
    if (getcwd(too_small, sizeof(too_small)) != 0 || errno != ERANGE) {
        status = 5;
        goto finish;
    }
    if (!check_getcwd_extension()) {
        status = 6;
        goto finish;
    }
    if (mkdir(nested, 0700) != 0 || chdir(nested) != 0 || chdir("..") != 0) {
        status = 7;
        goto finish;
    }
    if (mkdir(empty_directory, 0700) != 0) {
        status = 8;
        goto finish;
    }

    ordinary = open(file, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (ordinary < 0 || fstat(ordinary, &observed) != 0 ||
        !S_ISREG(observed.st_mode) || (observed.st_mode & 0777) != 0600) {
        status = 9;
        goto finish;
    }
    if (link(file, hard) != 0 || symlink(file, symbolic) != 0 ||
        readlink(symbolic, target, sizeof(target)) != 4 ||
        !bytes_equal(target, file, 4) || target[4] != 0) {
        status = 10;
        goto finish;
    }
    errno = E2BIG;
    if (readlink(symbolic, 0, 0) != 0 || errno != E2BIG) {
        status = 11;
        goto finish;
    }
    if (rename(file, renamed) != 0 || stat(renamed, &renamed_stat) != 0 ||
        stat(hard, &hard_stat) != 0 || !same_file(&renamed_stat, &hard_stat) ||
        renamed_stat.st_nlink != 2) {
        status = 12;
        goto finish;
    }
    errno = 0;
    if (!expect_error(open(file, O_RDONLY), ENOENT)) {
        status = 13;
        goto finish;
    }
    if (chmod(renamed, 0640) != 0 || fstat(ordinary, &observed) != 0 ||
        (observed.st_mode & 0777) != 0640 || fchmod(ordinary, 0600) != 0 ||
        fstat(ordinary, &observed) != 0 || (observed.st_mode & 0777) != 0600) {
        status = 14;
        goto finish;
    }
    path_only = open(renamed, O_PATH | O_CLOEXEC);
    if (path_only < 0 || fchmod(path_only, 0644) != 0 ||
        fstat(ordinary, &observed) != 0 || (observed.st_mode & 0777) != 0644) {
        status = 15;
        goto finish;
    }
    if (truncate(renamed, 7) != 0 || fstat(ordinary, &observed) != 0 ||
        observed.st_size != 7) {
        status = 16;
        goto finish;
    }
    errno = 0;
    if (!expect_error(truncate(renamed, (off_t)-1), EINVAL)) {
        status = 17;
        goto finish;
    }
    errno = 0;
    if (!expect_error(unlink(missing), ENOENT) || !expect_error(rmdir(missing), ENOENT) ||
        !expect_error(chdir(missing), ENOENT) || !expect_error(rename(missing, file), ENOENT) ||
        !expect_error(chmod(missing, 0600), ENOENT) || !expect_error(fchmod(-1, 0600), EBADF)) {
        status = 18;
        goto finish;
    }
    if (close(path_only) != 0) {
        status = 19;
        goto finish;
    }
    path_only = -1;
    if (close(ordinary) != 0) {
        status = 20;
        goto finish;
    }
    ordinary = -1;
    if (unlink(hard) != 0 || unlink(symbolic) != 0 || remove(renamed) != 0 ||
        remove(empty_directory) != 0 || rmdir(nested) != 0 || chdir("..") != 0 ||
        rmdir(root) != 0) {
        status = 21;
        goto finish;
    }
    return 0;

finish:
    if (path_only >= 0)
        (void)close(path_only);
    if (ordinary >= 0)
        (void)close(ordinary);
    /* Best-effort failure cleanup stays within the selected C surface. */
    (void)unlink(hard);
    (void)unlink(symbolic);
    (void)unlink(file);
    (void)unlink(renamed);
    (void)remove(empty_directory);
    (void)rmdir(nested);
    (void)chdir("..");
    (void)rmdir(root);
    return 30 + status;
}

#ifndef CRABC_PATHNAME_LIFECYCLE_FREESTANDING
int main(void)
{
    return crabc_x86_64_pathname_lifecycle_probe();
}
#endif
