/* Pinned-musl/raw Linux/x86-64 process-root-change reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4,
               "x86 int and pid_t width");
_Static_assert(sizeof(size_t) == 8, "x86 size_t width");
_Static_assert(SYS_chroot == 161, "x86 chroot syscall number");
_Static_assert(O_DIRECTORY == 0x00010000, "x86 O_DIRECTORY value");
_Static_assert(O_CLOEXEC == 0x00080000, "x86 O_CLOEXEC value");

enum invocation {
    INVOCATION_RAW,
    INVOCATION_MUSL,
};

enum {
    PRIVILEGE_UNAVAILABLE = 77,
};

struct fixture {
    char workspace[PATH_MAX];
    char new_root[PATH_MAX];
    char old_cwd[PATH_MAX];
    char inside_marker[PATH_MAX];
    char outside_marker[PATH_MAX];
    char missing[PATH_MAX];
    char regular[PATH_MAX];
};

static int build_path(char *destination, size_t capacity, const char *root,
                      const char *suffix)
{
    size_t root_length = strlen(root);
    size_t suffix_length = strlen(suffix);

    if (root_length == 0 || root_length >= capacity ||
        capacity - root_length < 2 ||
        suffix_length > capacity - root_length - 2)
        return 0;

    memcpy(destination, root, root_length);
    destination[root_length] = '/';
    memcpy(destination + root_length + 1, suffix, suffix_length);
    destination[root_length + suffix_length + 1] = '\0';
    return 1;
}

static int create_marker(const char *path, const char *bytes)
{
    int fd = -1;
    size_t length = strlen(bytes);
    size_t written = 0;

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    while (written != length) {
        ssize_t result = write(fd, bytes + written, length - written);

        if (result > 0) {
            written += (size_t)result;
            continue;
        }
        if (result == -1 && errno == EINTR) continue;
        (void)close(fd);
        return 0;
    }
    return close(fd) == 0;
}

static int prepare_fixture(struct fixture *fixture)
{
    static const char template[] = "/tmp/crabc-x86-root-change.XXXXXX";

    if (sizeof(template) > sizeof(fixture->workspace)) return 0;
    memcpy(fixture->workspace, template, sizeof(template));
    if (mkdtemp(fixture->workspace) == NULL ||
        !build_path(fixture->new_root, sizeof(fixture->new_root),
                    fixture->workspace, "new-root") ||
        !build_path(fixture->old_cwd, sizeof(fixture->old_cwd),
                    fixture->workspace, "old-cwd") ||
        !build_path(fixture->inside_marker, sizeof(fixture->inside_marker),
                    fixture->new_root, "inside-marker") ||
        !build_path(fixture->outside_marker, sizeof(fixture->outside_marker),
                    fixture->old_cwd, "outside-marker") ||
        !build_path(fixture->missing, sizeof(fixture->missing),
                    fixture->workspace, "missing") ||
        !build_path(fixture->regular, sizeof(fixture->regular),
                    fixture->workspace, "regular"))
        return 0;

    if (mkdir(fixture->new_root, 0700) != 0 ||
        mkdir(fixture->old_cwd, 0700) != 0 ||
        !create_marker(fixture->inside_marker, "inside root marker") ||
        !create_marker(fixture->outside_marker, "outside CWD marker") ||
        !create_marker(fixture->regular, "not a directory"))
        return 0;
    return 1;
}

static void cleanup_fixture(const struct fixture *fixture)
{
    (void)unlink(fixture->inside_marker);
    (void)unlink(fixture->outside_marker);
    (void)unlink(fixture->regular);
    (void)rmdir(fixture->new_root);
    (void)rmdir(fixture->old_cwd);
    (void)rmdir(fixture->workspace);
}

static int invoke_chroot(enum invocation invocation, const char *path)
{
    if (invocation == INVOCATION_RAW)
        return (int)syscall(SYS_chroot, path);
    return chroot(path);
}

static int expected_chroot_error(enum invocation invocation, const char *path,
                                 int expected)
{
    errno = 0;
    return invoke_chroot(invocation, path) == -1 && errno == expected;
}

static int marker_is_openable(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) return 0;
    return close(fd) == 0;
}

static int marker_is_missing(const char *path)
{
    int fd;

    errno = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)close(fd);
        return 0;
    }
    return errno == ENOENT;
}

/*
 * This child deliberately retains a CWD outside the new root. The relative
 * marker proves Linux did not change that CWD as part of chroot; it also makes
 * the non-sandbox boundary explicit. No child that changes root returns to the
 * parent evidence runner.
 */
static int root_change_child(enum invocation invocation,
                             const struct fixture *fixture)
{
    if (chdir(fixture->old_cwd) != 0) return 10;
    if (!expected_chroot_error(invocation, fixture->missing, ENOENT)) return 11;
    if (!expected_chroot_error(invocation, fixture->regular, ENOTDIR)) return 12;

    errno = 0;
    if (invoke_chroot(invocation, fixture->new_root) != 0) {
        if (errno == EPERM) return PRIVILEGE_UNAVAILABLE;
        return 13;
    }

    if (!marker_is_openable("/inside-marker")) return 14;
    if (!marker_is_missing("/outside-marker")) return 15;
    if (!marker_is_openable("outside-marker")) return 16;
    if (!expected_chroot_error(invocation, "/missing", ENOENT)) return 17;
    if (!expected_chroot_error(invocation, "/inside-marker", ENOTDIR)) return 18;
    return 0;
}

static int run_root_change_child(enum invocation invocation,
                                 const struct fixture *fixture)
{
    int status;
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) _exit(root_change_child(invocation, fixture));
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

int main(void)
{
    struct fixture fixture;
    int raw_status;
    int musl_status;

    memset(&fixture, 0, sizeof(fixture));
    if (!prepare_fixture(&fixture)) {
        cleanup_fixture(&fixture);
        return 1;
    }

    raw_status = run_root_change_child(INVOCATION_RAW, &fixture);
    musl_status = run_root_change_child(INVOCATION_MUSL, &fixture);
    cleanup_fixture(&fixture);

    if (raw_status == PRIVILEGE_UNAVAILABLE &&
        musl_status == PRIVILEGE_UNAVAILABLE) {
        puts("chroot=161 raw+musl=EPERM privilege=unavailable child-contained");
        return PRIVILEGE_UNAVAILABLE;
    }
    if (raw_status != 0 || musl_status != 0) return 1;

    puts("chroot=161 raw+musl=success root=absolute-inside cwd=preserved-relative errors=ENOENT,ENOTDIR child-contained");
    return 0;
}
