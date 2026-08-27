/* Pinned-musl Linux/x86-64 access/faccessat behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(SYS_access == 21, "x86 access syscall number");
_Static_assert(SYS_faccessat == 269, "x86 legacy faccessat syscall number");
_Static_assert(SYS_faccessat2 == 439, "x86 faccessat2 syscall number");
_Static_assert(AT_FDCWD == -100, "x86 AT_FDCWD value");
_Static_assert(AT_EACCESS == 0x200, "AT_EACCESS value");
_Static_assert(AT_SYMLINK_NOFOLLOW == 0x100, "AT_SYMLINK_NOFOLLOW value");
_Static_assert(F_OK == 0 && R_OK == 4, "access mode values");

struct result {
    int value;
    int error;
};

static struct result call_access(const char *path, int mode)
{
    struct result result;

    errno = 0;
    result.value = access(path, mode);
    result.error = errno;
    return result;
}

static struct result call_raw_access(const char *path, int mode)
{
    struct result result;

    errno = 0;
    result.value = (int)syscall(SYS_access, path, mode);
    result.error = errno;
    return result;
}

static struct result call_faccessat(int dirfd, const char *path, int mode,
                                    int flags)
{
    struct result result;

    errno = 0;
    result.value = faccessat(dirfd, path, mode, flags);
    result.error = errno;
    return result;
}

/* The legacy Linux syscall has no flags argument. The fourth argument in the
 * public musl wrapper is handled above; raw_faccessat is deliberately only
 * the three-register kernel ABI. */
static struct result call_raw_faccessat(int dirfd, const char *path, int mode)
{
    struct result result;

    errno = 0;
    result.value = (int)syscall(SYS_faccessat, dirfd, path, mode);
    result.error = errno;
    return result;
}

static struct result call_raw_faccessat2(int dirfd, const char *path, int mode,
                                          int flags)
{
    struct result result;

    errno = 0;
    result.value = (int)syscall(SYS_faccessat2, dirfd, path, mode, flags);
    result.error = errno;
    return result;
}

static int same_result(struct result left, struct result right, int value,
                       int error)
{
    if (left.value != value || right.value != value || left.value != right.value)
        return 0;
    if (value < 0 &&
        (left.error != error || right.error != error || left.error != right.error))
        return 0;
    return 1;
}

static int verify_real_and_effective_ids(int dirfd, const char *record)
{
    pid_t child;
    int status;

    /* The fixture is root-owned and this contained child switches only its
     * real UID. Keeping the transition in a child prevents credentials from
     * leaking into the rest of the reference process. */
    if (geteuid() != 0)
        return 0;
    child = fork();
    if (child < 0)
        return 0;
    if (child == 0) {
        if (setresuid(1000, 0, 0) != 0)
            _exit(30);
        if (!same_result(call_access(record, R_OK),
                         call_raw_access(record, R_OK), -1, EACCES) ||
            !same_result(call_access(record, R_OK),
                         call_raw_faccessat(AT_FDCWD, record, R_OK), -1,
                         EACCES) ||
            !same_result(call_faccessat(dirfd, "record", R_OK, 0),
                         call_raw_faccessat(dirfd, "record", R_OK), -1,
                         EACCES) ||
            !same_result(call_faccessat(dirfd, "record", R_OK, AT_EACCESS),
                         call_raw_faccessat2(dirfd, "record", R_OK,
                                             AT_EACCESS), 0, 0))
            _exit(31);
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 0;
    return 1;
}

int main(void)
{
    char template[] = "/tmp/crabc-x86-access-XXXXXX";
    char record[sizeof(template) + sizeof("/record")];
    char missing[sizeof(template) + sizeof("/missing")];
    char *root = mkdtemp(template);
    int dirfd = -1;
    int recordfd = -1;
    int status = 0;

    if (root == NULL)
        return 2;
    if (snprintf(record, sizeof(record), "%s/record", root) < 0 ||
        snprintf(missing, sizeof(missing), "%s/missing", root) < 0) {
        status = 3;
        goto cleanup;
    }
    dirfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        status = 4;
        goto cleanup;
    }
    /* The owner always has R_OK. The real/effective distinction is tested in
     * a child below, after making the real UID differ from the root owner. */
    recordfd = openat(dirfd, "record", O_CREAT | O_EXCL | O_RDONLY | O_CLOEXEC,
                      0400);
    if (recordfd < 0 || close(recordfd) != 0) {
        status = 5;
        goto cleanup;
    }
    recordfd = -1;
    if (symlinkat("missing-target", dirfd, "dangling") != 0) {
        status = 6;
        goto cleanup;
    }

    if (!same_result(call_access(record, F_OK),
                     call_raw_access(record, F_OK), 0, 0) ||
        !same_result(call_access(record, R_OK),
                     call_raw_access(record, R_OK), 0, 0) ||
        !same_result(call_access(record, F_OK),
                     call_raw_faccessat(AT_FDCWD, record, F_OK), 0, 0) ||
        !same_result(call_access(record, R_OK),
                     call_raw_faccessat(AT_FDCWD, record, R_OK), 0, 0)) {
        status = 10;
        goto cleanup;
    }
    if (!same_result(call_faccessat(dirfd, "record", F_OK, 0),
                     call_raw_faccessat(dirfd, "record", F_OK), 0, 0) ||
        !same_result(call_faccessat(dirfd, "record", R_OK, 0),
                     call_raw_faccessat(dirfd, "record", R_OK), 0, 0)) {
        status = 11;
        goto cleanup;
    }

    if (!same_result(call_access(missing, F_OK),
                     call_raw_access(missing, F_OK), -1, ENOENT) ||
        !same_result(call_access(missing, F_OK),
                     call_raw_faccessat(AT_FDCWD, missing, F_OK), -1,
                     ENOENT) ||
        !same_result(call_faccessat(dirfd, "missing", F_OK, 0),
                     call_raw_faccessat(dirfd, "missing", F_OK), -1, ENOENT)) {
        status = 12;
        goto cleanup;
    }

    /* Legacy faccessat follows the final link; faccessat2 carries the
     * AT_SYMLINK_NOFOLLOW policy that the three-argument syscall cannot. */
    if (!same_result(call_faccessat(dirfd, "dangling", F_OK, 0),
                     call_raw_faccessat(dirfd, "dangling", F_OK), -1, ENOENT) ||
        !same_result(call_faccessat(dirfd, "dangling", F_OK,
                                    AT_SYMLINK_NOFOLLOW),
                     call_raw_faccessat2(dirfd, "dangling", F_OK,
                                         AT_SYMLINK_NOFOLLOW), 0, 0)) {
        status = 13;
        goto cleanup;
    }

    if (!same_result(call_faccessat(dirfd, "record", F_OK, AT_EACCESS),
                     call_raw_faccessat2(dirfd, "record", F_OK, AT_EACCESS),
                     0, 0) || !verify_real_and_effective_ids(dirfd, record)) {
        status = 14;
        goto cleanup;
    }

    if (!same_result(call_access(record, 8), call_raw_access(record, 8),
                     -1, EINVAL) ||
        !same_result(call_access(record, 8),
                     call_raw_faccessat(AT_FDCWD, record, 8), -1, EINVAL) ||
        !same_result(call_faccessat(dirfd, "record", 8, 0),
                     call_raw_faccessat(dirfd, "record", 8), -1, EINVAL) ||
        !same_result(call_faccessat(dirfd, "record", F_OK, 0x400),
                     call_raw_faccessat2(dirfd, "record", F_OK, 0x400),
                     -1, EINVAL)) {
        status = 15;
        goto cleanup;
    }

cleanup:
    if (recordfd >= 0 && close(recordfd) != 0 && status == 0)
        status = 20;
    if (dirfd >= 0) {
        if (unlinkat(dirfd, "dangling", 0) != 0 && errno != ENOENT && status == 0)
            status = 21;
        if (unlinkat(dirfd, "record", 0) != 0 && errno != ENOENT && status == 0)
            status = 22;
        if (close(dirfd) != 0 && status == 0)
            status = 23;
    }
    if (rmdir(root) != 0 && status == 0)
        status = 24;
    if (status != 0)
        return status;

    puts("syscall=21/269/439 access=exists/read+legacy-faccessat "
         "raw-access=match faccessat=relative-exists/read "
         "missing=ENOENT dangling=follow-ENOENT/nofollow-success "
         "eaccess=real-EACCES/effective-success invalid=mode-EINVAL/flags-EINVAL");
    return 0;
}
