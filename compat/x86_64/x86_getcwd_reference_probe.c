/* Pinned-musl Linux/x86-64 getcwd(2) and logical-PWD behavior reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires little-endian x86-64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer size");
_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t size");
_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 struct stat layout");
_Static_assert(offsetof(struct stat, st_dev) == 0 &&
                   offsetof(struct stat, st_ino) == 8,
               "x86 struct stat identity fields");
_Static_assert(SYS_getcwd == 79 && SYS_newfstatat == 262,
               "x86 getcwd and newfstatat syscall numbers");

static long raw_getcwd(char *buffer, size_t size)
{
    return syscall(SYS_getcwd, buffer, size);
}

static int raw_newfstatat(int dirfd, const char *path, struct stat *value,
                          int flags)
{
    return (int)syscall(SYS_newfstatat, dirfd, path, value, flags);
}

typedef int (*statat_call)(int, const char *, struct stat *, int);

static int musl_fstatat(int dirfd, const char *path, struct stat *value,
                        int flags)
{
    return fstatat(dirfd, path, value, flags);
}

static int same_directory(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int raw_and_musl_identity_agree(const char *path)
{
    struct stat musl_value;
    struct stat raw_value;

    return musl_fstatat(AT_FDCWD, path, &musl_value, 0) == 0 &&
           raw_newfstatat(AT_FDCWD, path, &raw_value, 0) == 0 &&
           same_directory(&musl_value, &raw_value);
}

/*
 * The native facade accepts an explicit snapshot rather than reading `PWD`
 * from the environment. It keeps musl's device/inode trust decision and adds
 * the documented absolute-path requirement before either stat call.
 */
static int absolute_snapshot_matches_current(statat_call call, const char *pwd)
{
    struct stat pwd_stat;
    struct stat dot_stat;

    if (pwd == NULL || pwd[0] != '/')
        return 0;
    if (call(AT_FDCWD, pwd, &pwd_stat, 0) != 0 ||
        call(AT_FDCWD, ".", &dot_stat, 0) != 0)
        return 0;
    return same_directory(&pwd_stat, &dot_stat);
}

static int current_dir_name_equals(const char *pwd, const char *expected)
{
    char *actual;
    int matches;

    if (setenv("PWD", pwd, 1) != 0)
        return 0;
    actual = get_current_dir_name();
    if (actual == NULL)
        return 0;
    matches = strcmp(actual, expected) == 0;
    free(actual);
    return matches;
}

static int build_path(char *destination, size_t capacity, const char *root,
                      const char *leaf)
{
    int written = snprintf(destination, capacity, "%s/%s", root, leaf);

    return written >= 0 && (size_t)written < capacity;
}

static int logical_pwd_reference(void)
{
    char template[] = "/tmp/crabc-x86-current-dir-name-XXXXXX";
    char real[sizeof(template) + sizeof("/real")];
    char logical[sizeof(template) + sizeof("/logical")];
    char other[sizeof(template) + sizeof("/other")];
    char musl_cwd[4096];
    char raw_cwd[4096];
    char *root;
    long raw_length;
    int saved_cwd = -1;
    int made_real = 0;
    int made_logical = 0;
    int made_other = 0;
    int status = 0;

    root = mkdtemp(template);
    if (root == NULL)
        return 1;
    if (!build_path(real, sizeof(real), root, "real") ||
        !build_path(logical, sizeof(logical), root, "logical") ||
        !build_path(other, sizeof(other), root, "other")) {
        status = 2;
        goto cleanup;
    }
    if (mkdir(real, 0700) != 0) {
        status = 3;
        goto cleanup;
    }
    made_real = 1;
    if (mkdir(other, 0700) != 0) {
        status = 4;
        goto cleanup;
    }
    made_other = 1;
    if (symlink("real", logical) != 0) {
        status = 5;
        goto cleanup;
    }
    made_logical = 1;
    saved_cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (saved_cwd < 0 || chdir(logical) != 0) {
        status = 6;
        goto cleanup;
    }

    memset(raw_cwd, 0xa5, sizeof(raw_cwd));
    raw_length = raw_getcwd(raw_cwd, sizeof(raw_cwd));
    if (raw_length <= 0 || raw_length > (long)sizeof(raw_cwd) ||
        raw_cwd[(size_t)raw_length - 1] != '\0') {
        status = 7;
        goto cleanup;
    }
    if (getcwd(musl_cwd, sizeof(musl_cwd)) != musl_cwd ||
        strcmp(musl_cwd, raw_cwd) != 0 || strcmp(raw_cwd, logical) == 0) {
        status = 8;
        goto cleanup;
    }

    if (!absolute_snapshot_matches_current(musl_fstatat, logical) ||
        !absolute_snapshot_matches_current(raw_newfstatat, logical) ||
        !raw_and_musl_identity_agree(logical) ||
        !raw_and_musl_identity_agree(other) ||
        !raw_and_musl_identity_agree(".")) {
        status = 9;
        goto cleanup;
    }
    if (absolute_snapshot_matches_current(musl_fstatat, other) ||
        absolute_snapshot_matches_current(raw_newfstatat, other) ||
        absolute_snapshot_matches_current(musl_fstatat, ".") ||
        absolute_snapshot_matches_current(raw_newfstatat, ".") ||
        absolute_snapshot_matches_current(musl_fstatat, "") ||
        absolute_snapshot_matches_current(raw_newfstatat, "")) {
        status = 10;
        goto cleanup;
    }

    if (!current_dir_name_equals(logical, logical)) {
        status = 11;
        goto cleanup;
    }
    if (!current_dir_name_equals(other, raw_cwd) ||
        !current_dir_name_equals("", raw_cwd)) {
        status = 12;
        goto cleanup;
    }

cleanup:
    if (saved_cwd >= 0) {
        if (fchdir(saved_cwd) != 0 && status == 0)
            status = 13;
        if (close(saved_cwd) != 0 && status == 0)
            status = 14;
    }
    if (made_logical && unlink(logical) != 0 && status == 0)
        status = 15;
    if (made_other && rmdir(other) != 0 && status == 0)
        status = 16;
    if (made_real && rmdir(real) != 0 && status == 0)
        status = 17;
    if (rmdir(root) != 0 && status == 0)
        status = 18;
    return status;
}

int main(void)
{
    char libc_cwd[4096];
    char syscall_cwd[4096];
    char libc_zero;
    char syscall_zero;
    char libc_small[1];
    char syscall_small[1];
    char *libc_result;
    long syscall_result;
    const char *libc_end;
    size_t libc_bytes;
    int libc_errno;

    errno = 0;
    libc_result = getcwd(libc_cwd, sizeof(libc_cwd));
    if (libc_result == NULL || libc_result != libc_cwd)
        return 10;
    libc_end = memchr(libc_cwd, '\0', sizeof(libc_cwd));
    if (libc_end == NULL)
        return 11;
    libc_bytes = (size_t)(libc_end - libc_cwd) + 1;

    memset(syscall_cwd, 0xa5, sizeof(syscall_cwd));
    errno = 0;
    syscall_result = raw_getcwd(syscall_cwd, sizeof(syscall_cwd));
    if (syscall_result <= 0 || syscall_result > (long)sizeof(syscall_cwd))
        return 12;
    if (syscall_result != (long)libc_bytes ||
        syscall_cwd[(size_t)syscall_result - 1] != '\0' ||
        memcmp(libc_cwd, syscall_cwd, libc_bytes) != 0)
        return 13;

    errno = 0;
    libc_result = getcwd(&libc_zero, 0);
    libc_errno = errno;
    if (libc_result != NULL || libc_errno != EINVAL)
        return 20;

    errno = 0;
    syscall_result = raw_getcwd(&syscall_zero, 0);
    if (syscall_result != -1 || errno != ERANGE)
        return 21;

    errno = 0;
    libc_result = getcwd(libc_small, sizeof(libc_small));
    libc_errno = errno;
    if (libc_result != NULL || libc_errno != ERANGE)
        return 30;

    errno = 0;
    syscall_result = raw_getcwd(syscall_small, sizeof(syscall_small));
    if (syscall_result != -1 || errno != ERANGE)
        return 31;

    libc_errno = logical_pwd_reference();
    if (libc_errno != 0)
        return 40 + libc_errno;

    puts("syscalls=getcwd:79,newfstatat:262 exact=match zero=musl-EINVAL/raw-ERANGE undersized=ERANGE pwd=devino-logical=preserved,mismatch+empty=physical native-snapshot=absolute");
    return 0;
}
