/*
 * Pinned-musl/raw Linux/x86-64 canonical-path and CWD-mutation reference.
 *
 * `realpath`, `chdir`, and `fchdir` are pinned-musl calls used solely as a
 * C/POSIX oracle for the private typed Rust boundary. The direct `openat`,
 * `readlinkat`, `getcwd`, `chdir`, and `fchdir` calls below independently pin
 * the Linux x86-64 syscall ABI. This fixture selects no crabc C pathname or
 * process API, installed C header, errno/TLS contract, or public x86 support.
 */
#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    PATH_CAPACITY = 4096,
};

_Static_assert(sizeof(size_t) == 8, "x86 size_t width");
_Static_assert(sizeof(ssize_t) == 8, "x86 ssize_t width");
_Static_assert(PATH_MAX == PATH_CAPACITY, "Linux pathname capacity");
_Static_assert(SYS_getcwd == 79, "x86 getcwd syscall number");
_Static_assert(SYS_chdir == 80, "x86 chdir syscall number");
_Static_assert(SYS_fchdir == 81, "x86 fchdir syscall number");
_Static_assert(SYS_openat == 257, "x86 openat syscall number");
_Static_assert(SYS_readlinkat == 267, "x86 readlinkat syscall number");
_Static_assert(AT_FDCWD == -100, "x86 current-directory token");
_Static_assert(O_DIRECTORY == 0x00010000, "x86 O_DIRECTORY value");
_Static_assert(O_CLOEXEC == 0x00080000, "x86 O_CLOEXEC value");

static long raw_getcwd(char *buffer, size_t capacity)
{
    return syscall(SYS_getcwd, buffer, capacity);
}

static int raw_chdir(const char *path)
{
    return (int)syscall(SYS_chdir, path);
}

static int raw_fchdir(int fd)
{
    return (int)syscall(SYS_fchdir, fd);
}

static int raw_openat(int dirfd, const char *path, int flags, mode_t mode)
{
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

static ssize_t raw_readlinkat(int dirfd, const char *path, char *target,
                              size_t capacity)
{
    return (ssize_t)syscall(SYS_readlinkat, dirfd, path, target, capacity);
}

static int expected_error(long value, int error)
{
    return value == -1 && errno == error;
}

static int build_path(char *destination, size_t capacity, const char *root,
                      const char *suffix)
{
    size_t root_length = strlen(root);
    size_t suffix_length = strlen(suffix);

    if (root_length == 0 || root_length >= capacity ||
        capacity - root_length < 2 ||
        suffix_length > capacity - root_length - 2) {
        return 0;
    }
    memcpy(destination, root, root_length);
    destination[root_length] = '/';
    memcpy(destination + root_length + 1, suffix, suffix_length);
    destination[root_length + 1 + suffix_length] = '\0';
    return 1;
}

/* Compare the two normal getcwd forms while preserving the raw byte count. */
static int cwd_pair(char raw[PATH_CAPACITY], const char *expected)
{
    char musl[PATH_CAPACITY];
    long raw_length;

    errno = 0;
    if (getcwd(musl, sizeof(musl)) != musl) return 0;
    memset(raw, 0xa5, PATH_CAPACITY);
    errno = 0;
    raw_length = raw_getcwd(raw, PATH_CAPACITY);
    if (raw_length <= 0 || (size_t)raw_length > PATH_CAPACITY ||
        raw[(size_t)raw_length - 1] != '\0' || strcmp(musl, raw) != 0) {
        return 0;
    }
    return expected == NULL || strcmp(musl, expected) == 0;
}

static int realpath_equals(const char *path, const char *expected)
{
    char resolved[PATH_CAPACITY];

    errno = 0;
    return realpath(path, resolved) == resolved && strcmp(resolved, expected) == 0;
}

static int realpath_error(const char *path, int error)
{
    char resolved[PATH_CAPACITY];

    errno = 0;
    return realpath(path, resolved) == NULL && errno == error;
}

/*
 * `realpath` is the canonicalization oracle. These raw operations separately
 * prove the direct descriptor-relative primitives used by the Rust resolver:
 * a link target is an unterminated byte prefix and an opened link is followed
 * by the kernel before the next component is opened.
 */
static int raw_path_primitives(int root_fd)
{
    char target[16];
    char short_target[2];
    int alias_fd = -1;
    int file_fd = -1;
    int status = 0;
    ssize_t length;

    memset(target, 0xa5, sizeof(target));
    errno = 0;
    length = raw_readlinkat(root_fd, "alias", target, sizeof(target));
    if (length != 4 || memcmp(target, "real", 4) != 0 ||
        target[4] != (char)0xa5) {
        status = 1;
        goto cleanup;
    }

    memset(short_target, 0xa5, sizeof(short_target));
    errno = 0;
    length = raw_readlinkat(root_fd, "alias", short_target, sizeof(short_target));
    if (length != (ssize_t)sizeof(short_target) ||
        memcmp(short_target, "re", sizeof(short_target)) != 0) {
        status = 2;
        goto cleanup;
    }

    errno = 0;
    length = raw_readlinkat(root_fd, "regular", target, sizeof(target));
    if (!expected_error(length, EINVAL)) {
        status = 3;
        goto cleanup;
    }

    alias_fd = raw_openat(root_fd, "alias", O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                          0);
    if (alias_fd < 0) {
        status = 4;
        goto cleanup;
    }
    file_fd = raw_openat(alias_fd, "child/file", O_RDONLY | O_CLOEXEC, 0);
    if (file_fd < 0) {
        status = 5;
        goto cleanup;
    }

cleanup:
    if (file_fd >= 0 && close(file_fd) != 0 && status == 0) status = 6;
    if (alias_fd >= 0 && close(alias_fd) != 0 && status == 0) status = 7;
    return status;
}

/*
 * This function runs only after fork. CWD is process-global state, so child
 * containment keeps a failed mutation test from changing the evidence
 * runner's directory. The saved descriptor, not a pathname, restores entry
 * CWD after each successful form.
 */
static int cwd_mutation_child(const char *root, const char *canonical_file,
                              int root_fd)
{
    char before[PATH_CAPACITY];
    char observed[PATH_CAPACITY];
    char missing[PATH_CAPACITY];
    char regular_path[PATH_CAPACITY];
    int original_fd = -1;
    int regular_fd = -1;
    int status = 0;

    if (!cwd_pair(before, NULL) ||
        !build_path(missing, sizeof(missing), root, "missing") ||
        !build_path(regular_path, sizeof(regular_path), root, "regular")) {
        status = 1;
        goto cleanup;
    }

    original_fd = raw_openat(AT_FDCWD, ".",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    regular_fd = raw_openat(root_fd, "regular", O_RDONLY | O_CLOEXEC, 0);
    if (original_fd < 0 || regular_fd < 0) {
        status = 2;
        goto cleanup;
    }

    errno = 0;
    if (chdir(root) != 0 || !cwd_pair(observed, root) ||
        !realpath_equals("alias/child/../child/file", canonical_file)) {
        status = 3;
        goto cleanup;
    }
    errno = 0;
    if (fchdir(original_fd) != 0 || !cwd_pair(observed, before)) {
        status = 4;
        goto cleanup;
    }

    errno = 0;
    if (raw_chdir(root) != 0 || !cwd_pair(observed, root)) {
        status = 5;
        goto cleanup;
    }
    errno = 0;
    if (raw_fchdir(original_fd) != 0 || !cwd_pair(observed, before)) {
        status = 6;
        goto cleanup;
    }

    errno = 0;
    if (!expected_error(chdir(missing), ENOENT)) {
        status = 7;
        goto cleanup;
    }
    errno = 0;
    if (!expected_error(raw_chdir(missing), ENOENT)) {
        status = 8;
        goto cleanup;
    }
    errno = 0;
    if (!expected_error(chdir(regular_path), ENOTDIR)) {
        status = 9;
        goto cleanup;
    }
    errno = 0;
    if (!expected_error(raw_chdir(regular_path), ENOTDIR)) {
        status = 10;
        goto cleanup;
    }
    errno = 0;
    if (!expected_error(fchdir(regular_fd), ENOTDIR)) {
        status = 11;
        goto cleanup;
    }
    errno = 0;
    if (!expected_error(raw_fchdir(regular_fd), ENOTDIR)) {
        status = 12;
        goto cleanup;
    }
    errno = 0;
    if (!expected_error(fchdir(-1), EBADF)) {
        status = 13;
        goto cleanup;
    }
    errno = 0;
    if (!expected_error(raw_fchdir(-1), EBADF)) {
        status = 14;
        goto cleanup;
    }

cleanup:
    if (original_fd >= 0) (void)raw_fchdir(original_fd);
    if (regular_fd >= 0 && close(regular_fd) != 0 && status == 0) status = 15;
    if (original_fd >= 0 && close(original_fd) != 0 && status == 0) status = 16;
    return status;
}

static int run_cwd_mutation_child(const char *root, const char *canonical_file,
                                  int root_fd)
{
    int wait_status;
    pid_t child = fork();

    if (child < 0) return 0;
    if (child == 0)
        _exit(cwd_mutation_child(root, canonical_file, root_fd));
    if (waitpid(child, &wait_status, 0) != child) return 0;
    return WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
}

int main(void)
{
    static const char byte_name[] = {'r', 'a', 'w', '-', (char)0xff, '\0'};
    char template[] = "/tmp/crabc-x86-cwd-canonicalize-XXXXXX";
    char root_physical[PATH_CAPACITY];
    char input[PATH_CAPACITY];
    char canonical_file[PATH_CAPACITY];
    char byte_path[PATH_CAPACITY];
    int root_fd = -1;
    int file_fd = -1;
    int regular_fd = -1;
    int byte_fd = -1;
    int status = 0;

    if (mkdtemp(template) == NULL) return 2;
    root_fd = open(template, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) {
        status = 3;
        goto cleanup;
    }
    if (mkdirat(root_fd, "real", 0700) != 0 ||
        mkdirat(root_fd, "real/child", 0700) != 0) {
        status = 4;
        goto cleanup;
    }
    file_fd = openat(root_fd, "real/child/file",
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (file_fd < 0 || write(file_fd, "file", 4) != 4 || close(file_fd) != 0) {
        file_fd = -1;
        status = 5;
        goto cleanup;
    }
    file_fd = -1;
    regular_fd = openat(root_fd, "regular", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                        0600);
    if (regular_fd < 0 || close(regular_fd) != 0) {
        regular_fd = -1;
        status = 6;
        goto cleanup;
    }
    regular_fd = -1;
    if (symlinkat("real", root_fd, "alias") != 0 ||
        symlinkat("missing", root_fd, "dangling") != 0 ||
        symlinkat("cycle-b", root_fd, "cycle-a") != 0 ||
        symlinkat("cycle-a", root_fd, "cycle-b") != 0) {
        status = 7;
        goto cleanup;
    }
    if (realpath(template, root_physical) != root_physical ||
        !build_path(canonical_file, sizeof(canonical_file), root_physical,
                    "real/child/file") ||
        !build_path(byte_path, sizeof(byte_path), root_physical, byte_name)) {
        status = 8;
        goto cleanup;
    }
    byte_fd = raw_openat(root_fd, byte_name,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (byte_fd < 0 || write(byte_fd, "byte", 4) != 4 || close(byte_fd) != 0) {
        byte_fd = -1;
        status = 9;
        goto cleanup;
    }
    byte_fd = -1;
    if (symlinkat(byte_path, root_fd, "absolute-byte-link") != 0) {
        status = 10;
        goto cleanup;
    }

    if (raw_path_primitives(root_fd) != 0) {
        status = 11;
        goto cleanup;
    }
    if (!build_path(input, sizeof(input), template,
                    "alias/child/../child/file") ||
        !realpath_equals(input, canonical_file)) {
        status = 12;
        goto cleanup;
    }
    if (!realpath_equals(byte_path, byte_path) ||
        !build_path(input, sizeof(input), template, "absolute-byte-link") ||
        !realpath_equals(input, byte_path)) {
        status = 13;
        goto cleanup;
    }
    if (!build_path(input, sizeof(input), template, "missing") ||
        !realpath_error(input, ENOENT) ||
        !build_path(input, sizeof(input), template, "dangling") ||
        !realpath_error(input, ENOENT) ||
        !build_path(input, sizeof(input), template, "cycle-a") ||
        !realpath_error(input, ELOOP) ||
        !build_path(input, sizeof(input), template, "real/child/file/") ||
        !realpath_error(input, ENOTDIR) || !realpath_error("", ENOENT)) {
        status = 14;
        goto cleanup;
    }
    if (!run_cwd_mutation_child(root_physical, canonical_file, root_fd)) {
        status = 15;
        goto cleanup;
    }

cleanup:
    if (byte_fd >= 0 && close(byte_fd) != 0 && status == 0) status = 16;
    if (regular_fd >= 0 && close(regular_fd) != 0 && status == 0) status = 17;
    if (file_fd >= 0 && close(file_fd) != 0 && status == 0) status = 18;
    if (root_fd >= 0) {
        if (unlinkat(root_fd, "absolute-byte-link", 0) != 0 && errno != ENOENT &&
            status == 0)
            status = 19;
        if (unlinkat(root_fd, byte_name, 0) != 0 && errno != ENOENT && status == 0)
            status = 20;
        if (unlinkat(root_fd, "cycle-a", 0) != 0 && errno != ENOENT && status == 0)
            status = 21;
        if (unlinkat(root_fd, "cycle-b", 0) != 0 && errno != ENOENT && status == 0)
            status = 22;
        if (unlinkat(root_fd, "dangling", 0) != 0 && errno != ENOENT && status == 0)
            status = 23;
        if (unlinkat(root_fd, "alias", 0) != 0 && errno != ENOENT && status == 0)
            status = 24;
        if (unlinkat(root_fd, "regular", 0) != 0 && errno != ENOENT && status == 0)
            status = 25;
        if (unlinkat(root_fd, "real/child/file", 0) != 0 && errno != ENOENT &&
            status == 0)
            status = 26;
        if (unlinkat(root_fd, "real/child", AT_REMOVEDIR) != 0 && errno != ENOENT &&
            status == 0)
            status = 27;
        if (unlinkat(root_fd, "real", AT_REMOVEDIR) != 0 && errno != ENOENT &&
            status == 0)
            status = 28;
        if (close(root_fd) != 0 && status == 0) status = 29;
    }
    if (rmdir(template) != 0 && status == 0) status = 30;
    if (status != 0) return status;

    puts("syscalls=getcwd:79,chdir:80,fchdir:81,openat:257,readlinkat:267 canonical=musl-realpath:relative-link:byte-path:absolute-link:empty:missing-ENOENT:trailing-file-ENOTDIR:cycle-ELOOP raw=openat:readlinkat:getcwd cwd=forked-child:chdir:fchdir:restore errors=missing-ENOENT:notdir-ENOTDIR:badfd-EBADF c-api-selection=excluded");
    return 0;
}
