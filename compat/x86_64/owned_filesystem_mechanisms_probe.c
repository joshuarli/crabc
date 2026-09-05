#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* The probe deliberately uses the installed public record, rather than an
 * internal Rust mirror.  These are the Linux/x86-64 UAPI offsets consumed by
 * `statx(2)` and retained by the installed header. */
_Static_assert(sizeof(struct statx_timestamp) == 16, "statx timestamp layout");
_Static_assert(sizeof(struct statx) == 256, "statx layout");
_Static_assert(offsetof(struct statx, stx_mask) == 0, "statx mask offset");
_Static_assert(offsetof(struct statx, stx_mode) == 28, "statx mode offset");
_Static_assert(offsetof(struct statx, stx_ino) == 32, "statx inode offset");
_Static_assert(offsetof(struct statx, stx_atime) == 64, "statx atime offset");
_Static_assert(offsetof(struct statx, stx_mtime) == 112, "statx mtime offset");
_Static_assert(offsetof(struct statx, stx_dev_major) == 136, "statx device offset");
_Static_assert(offsetof(struct statx, stx_mnt_id) == 144, "statx mount offset");
_Static_assert(offsetof(struct statx, __pad2) == 184, "statx tail offset");

static int failure_line;

#define CHECK(condition) do { \
    if (!(condition)) { \
        if (!failure_line) failure_line = __LINE__; \
        return -1; \
    } \
} while (0)
#define CHECK_ERR(call, expected) do { \
    errno = 0; \
    CHECK((call) == -1 && errno == (expected)); \
} while (0)

static int make_file(int directory, const char *name, const char *contents, size_t length)
{
    int descriptor = openat(directory, name, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(descriptor >= 0);
    CHECK(write(descriptor, contents, length) == (ssize_t)length);
    CHECK(lseek(descriptor, 0, SEEK_SET) == 0);
    return descriptor;
}

static int filesystem_metadata_and_namespace(int directory)
{
    static const char contents[] = "01234567";
    struct stat metadata;
    struct statx extended;
    int descriptor;
    int path_descriptor;
    uid_t user = getuid();
    gid_t group = getgid();

    descriptor = make_file(directory, "data", contents, sizeof(contents) - 1);
    CHECK(descriptor >= 0);

    errno = E2BIG;
    CHECK(fchmodat(directory, "data", 0640, 0) == 0 && errno == E2BIG);
    CHECK(fstatat(directory, "data", &metadata, 0) == 0);
    CHECK((metadata.st_mode & 0777) == 0640);

    /* Linux 5.10 reaches musl's O_PATH + /proc/self/fd fallback here because
     * fchmodat2 is unavailable.  A regular path succeeds, while the final
     * symlink variant must be rejected without following it. */
    errno = E2BIG;
    CHECK(fchmodat(directory, "data", 0600, AT_SYMLINK_NOFOLLOW) == 0 && errno == E2BIG);
    CHECK(fstatat(directory, "data", &metadata, 0) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);
    CHECK(symlinkat("data", directory, "data-link") == 0);
    CHECK_ERR(fchmodat(directory, "data-link", 0600, AT_SYMLINK_NOFOLLOW), EOPNOTSUPP);
    CHECK_ERR(fchmodat(directory, "data", 0600, 0x40000000), EINVAL);

    /* `lchmod` uses the same source path in the owned runtime.  Its legacy
     * private archive sibling intentionally retains the previous constant
     * unsupported result outside this installed product. */
    errno = E2BIG;
    CHECK(lchmod("/tmp/owned-filesystem/data", 0620) == 0 && errno == E2BIG);
    CHECK(fstatat(directory, "data", &metadata, 0) == 0);
    CHECK((metadata.st_mode & 0777) == 0620);
    CHECK_ERR(lchmod("/tmp/owned-filesystem/data-link", 0600), EOPNOTSUPP);

    /* fchown's direct syscall reports EBADF for O_PATH.  Musl verifies that
     * it is a live descriptor and retries through the procfd pathname. */
    path_descriptor = openat(directory, "data", O_PATH | O_NOFOLLOW);
    CHECK(path_descriptor >= 0);
    errno = E2BIG;
    CHECK(fchown(path_descriptor, user, group) == 0 && errno == E2BIG);
    CHECK(close(path_descriptor) == 0);
    errno = E2BIG;
    CHECK(fchownat(directory, "data", user, group, 0) == 0 && errno == E2BIG);
    errno = E2BIG;
    CHECK(fchownat(directory, "data-link", user, group, AT_SYMLINK_NOFOLLOW) == 0 && errno == E2BIG);
    CHECK_ERR(fchown(-1, user, group), EBADF);
    CHECK_ERR(fchownat(-1, "data", user, group, 0), EBADF);

    CHECK(mknod("/tmp/owned-filesystem/fifo", S_IFIFO | 0600, 0) == 0);
    CHECK(lstat("/tmp/owned-filesystem/fifo", &metadata) == 0 && S_ISFIFO(metadata.st_mode));
    CHECK(mknodat(directory, "fifo-at", S_IFIFO | 0600, 0) == 0);
    CHECK(fstatat(directory, "fifo-at", &metadata, AT_SYMLINK_NOFOLLOW) == 0 && S_ISFIFO(metadata.st_mode));
    CHECK_ERR(mknodat(-1, "missing-parent", S_IFIFO | 0600, 0), EBADF);

    CHECK(make_file(directory, "rename-old", "r", 1) >= 0);
    CHECK(renameat(directory, "rename-old", directory, "rename-new") == 0);
    CHECK(fstatat(directory, "rename-new", &metadata, 0) == 0);
    CHECK_ERR(fstatat(directory, "rename-old", &metadata, 0), ENOENT);
    CHECK_ERR(renameat(-1, "rename-new", directory, "rename-last"), EBADF);

    memset(&extended, 0xa5, sizeof(extended));
    errno = E2BIG;
    CHECK(statx(directory, "data", AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &extended) == 0 && errno == E2BIG);
    CHECK((extended.stx_mask & STATX_BASIC_STATS) == STATX_BASIC_STATS);
    CHECK((extended.stx_mode & S_IFMT) == S_IFREG);
    CHECK((extended.stx_mode & 0777) == 0620);
    CHECK(extended.stx_size == sizeof(contents) - 1);
    CHECK(extended.stx_uid == user && extended.stx_gid == group);
    CHECK_ERR(statx(directory, "missing", 0, STATX_BASIC_STATS, &extended), ENOENT);

    CHECK(close(descriptor) == 0);
    return 0;
}

static int allocation_and_vector_io(int directory)
{
    static const char seed[] = "seed";
    static const char first_write[] = "XY";
    static const char second_write[] = "Z";
    struct stat metadata;
    struct iovec reads[2];
    struct iovec writes[2];
    char first_read[2];
    char second_read[2];
    int descriptor;
    int vector;

    descriptor = make_file(directory, "allocated", seed, sizeof(seed) - 1);
    CHECK(descriptor >= 0);
    CHECK(lseek(descriptor, 2, SEEK_SET) == 2);
    errno = E2BIG;
    CHECK(fallocate(descriptor, 0, 4096, 4096) == 0 && errno == E2BIG);
    CHECK(lseek(descriptor, 0, SEEK_CUR) == 2);
    CHECK(fstat(descriptor, &metadata) == 0 && metadata.st_size >= 8192);
    CHECK_ERR(fallocate(-1, 0, 0, 1), EBADF);
    CHECK_ERR(fallocate(descriptor, 0x40000000, 0, 1), EOPNOTSUPP);
    CHECK(close(descriptor) == 0);

    vector = make_file(directory, "vector", "abcdefgh", 8);
    CHECK(vector >= 0);
    reads[0].iov_base = first_read;
    reads[0].iov_len = sizeof(first_read);
    reads[1].iov_base = second_read;
    reads[1].iov_len = sizeof(second_read);

    CHECK(lseek(vector, 2, SEEK_SET) == 2);
    memset(first_read, 0, sizeof(first_read));
    memset(second_read, 0, sizeof(second_read));
    errno = E2BIG;
    CHECK(preadv2(vector, reads, 2, -1, 0) == 4 && errno == E2BIG);
    CHECK(!memcmp(first_read, "cd", 2) && !memcmp(second_read, "ef", 2));
    CHECK(lseek(vector, 0, SEEK_CUR) == 6);

    CHECK(lseek(vector, 0, SEEK_SET) == 0);
    memset(first_read, 0, sizeof(first_read));
    memset(second_read, 0, sizeof(second_read));
    CHECK(preadv2(vector, reads, 2, 2, 0) == 4);
    CHECK(!memcmp(first_read, "cd", 2) && !memcmp(second_read, "ef", 2));
    CHECK(lseek(vector, 0, SEEK_CUR) == 0);
    CHECK_ERR(preadv2(vector, reads, 1, -2, 0), EINVAL);
    CHECK_ERR(preadv2(-1, reads, 1, 0, 0), EBADF);

    writes[0].iov_base = (void *)first_write;
    writes[0].iov_len = sizeof(first_write) - 1;
    writes[1].iov_base = (void *)second_write;
    writes[1].iov_len = sizeof(second_write) - 1;
    CHECK(lseek(vector, 0, SEEK_SET) == 0);
    errno = E2BIG;
    CHECK(pwritev2(vector, writes, 2, -1, 0) == 3 && errno == E2BIG);
    CHECK(lseek(vector, 0, SEEK_CUR) == 3);
    CHECK(pwritev2(vector, writes, 2, 5, 0) == 3);
    CHECK(lseek(vector, 0, SEEK_CUR) == 3);
    /* A nonzero flag uses the six-word pwritev2 route, including the split
     * signed offset words.  RWF_DSYNC is valid for this regular fixture. */
    CHECK(pwritev2(vector, writes, 1, 8, RWF_DSYNC) == 2);
    CHECK(lseek(vector, 0, SEEK_CUR) == 3);
    CHECK_ERR(pwritev2(vector, writes, 1, -2, 0), EINVAL);
    CHECK_ERR(pwritev2(-1, writes, 1, 0, 0), EBADF);
    CHECK(close(vector) == 0);
    return 0;
}

static int lockf_child_conflict(int descriptor)
{
    int status;
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        errno = 0;
        if (lockf(descriptor, F_TEST, 0) != -1 || errno != EACCES)
            _exit(71);
        errno = 0;
        if (lockf(descriptor, F_TLOCK, 0) != -1 || (errno != EACCES && errno != EAGAIN))
            _exit(72);
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

static int lockf_child_acquire(int descriptor)
{
    int status;
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (lockf(descriptor, F_TLOCK, 0) || lockf(descriptor, F_ULOCK, 0))
            _exit(73);
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

static int lockf_process_cases(int directory)
{
    int descriptor = make_file(directory, "locks", "lock", 4);
    CHECK(descriptor >= 0);
    errno = E2BIG;
    CHECK(lockf(descriptor, F_LOCK, 0) == 0 && errno == E2BIG);
    CHECK(lockf(descriptor, F_TEST, 0) == 0);
    CHECK(lockf_child_conflict(descriptor) == 0);
    CHECK(lockf(descriptor, F_ULOCK, 0) == 0);
    CHECK(lockf_child_acquire(descriptor) == 0);
    CHECK_ERR(lockf(descriptor, 99, 0), EINVAL);
    CHECK(close(descriptor) == 0);
    return 0;
}

static int run_probe(void)
{
    int directory;

    alarm(20);
    CHECK(mkdir("/tmp/owned-filesystem", 0700) == 0);
    directory = open("/tmp/owned-filesystem", O_RDONLY | O_DIRECTORY);
    CHECK(directory >= 0);
    CHECK(filesystem_metadata_and_namespace(directory) == 0);
    CHECK(allocation_and_vector_io(directory) == 0);
    CHECK(lockf_process_cases(directory) == 0);
    CHECK(close(directory) == 0);
    puts("owned-filesystem-mechanisms-ok");
    return 0;
}

int main(void)
{
    int result = run_probe();
    if (result != 0) {
        fprintf(stderr, "owned-filesystem-mechanisms failure at line %d errno %d\n", failure_line, errno);
        return 1;
    }
    return 0;
}
