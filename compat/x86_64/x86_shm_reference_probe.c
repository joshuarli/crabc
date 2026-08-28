/*
 * Pinned-musl/raw Linux/x86-64 POSIX shared-memory reference.
 *
 * `shm_open` and `shm_unlink` are a pinned-musl C/POSIX oracle for the
 * private Rust facade. The raw helpers model that facade's direct Linux
 * boundary: validate a POSIX name, map it to `/dev/shm/<name>`, force only
 * `O_CLOEXEC`, and invoke openat(2)/unlinkat(2). In particular, musl 1.2.6
 * additionally forces O_NOFOLLOW and O_NONBLOCK; that intentional policy
 * difference is observed below rather than treated as an oracle mismatch.
 *
 * This fixture selects neither crabc's C ABI, SysV IPC, mappings, errno/TLS,
 * nor public x86 support.
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
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 &&
                   sizeof(size_t) == 8 && sizeof(off_t) == 8,
               "x86 LP64 scalar widths");
_Static_assert(NAME_MAX == 255, "Linux POSIX shared-memory name limit");
_Static_assert(SYS_fcntl == 72, "x86 fcntl syscall number");
_Static_assert(SYS_openat == 257, "x86 openat syscall number");
_Static_assert(SYS_unlinkat == 263, "x86 unlinkat syscall number");
_Static_assert(AT_FDCWD == -100, "x86 current-directory token");
_Static_assert(O_RDWR == 0x00000002 && O_CREAT == 0x00000040 &&
                   O_EXCL == 0x00000080 && O_NONBLOCK == 0x00000800 &&
                   O_DIRECTORY == 0x00010000 && O_NOFOLLOW == 0x00020000 &&
                   O_CLOEXEC == 0x00080000 && FD_CLOEXEC == 1,
               "x86 shared-memory open and descriptor flags");

enum {
    SHM_MODE = 0600,
    SHM_PREFIX_LENGTH = sizeof("/dev/shm/") - 1,
    SHM_PATH_CAPACITY = SHM_PREFIX_LENGTH + NAME_MAX + 1,
    RAW_CREATE_FLAGS = O_RDWR | O_CREAT | O_EXCL,
    UNIQUE_ATTEMPTS = 128,
};

struct call_result {
    int value;
    int error;
};

/*
 * Mirror `crabc_rs::shm::with_shm_path`: all leading slashes are ignored;
 * the remaining component must be a single, non-special NAME_MAX-sized name.
 * The returned path has enough room for `/dev/shm/`, the name, and its NUL.
 */
static int map_raw_shm_name(const char *input,
                            char output[SHM_PATH_CAPACITY])
{
    const char *name = input;
    size_t length;

    while (*name == '/') name++;
    if (*name == '\0') {
        errno = EINVAL;
        return -1;
    }
    length = strlen(name);
    if (length > NAME_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if ((length == 1 && name[0] == '.') ||
        (length == 2 && name[0] == '.' && name[1] == '.') ||
        strchr(name, '/') != NULL) {
        errno = EINVAL;
        return -1;
    }
    memcpy(output, "/dev/shm/", SHM_PREFIX_LENGTH);
    memcpy(output + SHM_PREFIX_LENGTH, name, length + 1);
    return 0;
}

/*
 * The fixed four-argument x86-64 openat syscall has the mode in its fourth
 * syscall argument (r10 at the raw instruction boundary). `syscall` supplies
 * that register placement while this probe pins the number and argument order.
 */
static struct call_result raw_open(const char *name, int flags, mode_t mode)
{
    char path[SHM_PATH_CAPACITY];
    struct call_result result;

    errno = 0;
    if (map_raw_shm_name(name, path) != 0) {
        result.value = -1;
    } else {
        result.value =
            (int)syscall(SYS_openat, AT_FDCWD, path, flags | O_CLOEXEC, mode);
    }
    result.error = errno;
    return result;
}

static struct call_result raw_unlink(const char *name)
{
    char path[SHM_PATH_CAPACITY];
    struct call_result result;

    errno = 0;
    if (map_raw_shm_name(name, path) != 0) {
        result.value = -1;
    } else {
        result.value = (int)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
    }
    result.error = errno;
    return result;
}

static struct call_result musl_open(const char *name, int flags, mode_t mode)
{
    struct call_result result;

    errno = 0;
    result.value = shm_open(name, flags, mode);
    result.error = errno;
    return result;
}

static struct call_result musl_unlink(const char *name)
{
    struct call_result result;

    errno = 0;
    result.value = shm_unlink(name);
    result.error = errno;
    return result;
}

static int is_error(struct call_result result, int error)
{
    return result.value == -1 && result.error == error;
}

static int expect_raw_open_error(const char *name, int flags, mode_t mode,
                                 int error)
{
    struct call_result result = raw_open(name, flags, mode);

    if (result.value >= 0) (void)close(result.value);
    return is_error(result, error);
}

static int expect_musl_open_error(const char *name, int flags, mode_t mode,
                                  int error)
{
    struct call_result result = musl_open(name, flags, mode);

    if (result.value >= 0) (void)close(result.value);
    return is_error(result, error);
}

static int same_object(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int inspect_descriptor(int fd, int expected_nonblocking,
                              nlink_t expected_links, struct stat *value)
{
    long descriptor_flags = syscall(SYS_fcntl, fd, F_GETFD);
    long status_flags = syscall(SYS_fcntl, fd, F_GETFL);

    return descriptor_flags >= 0 && status_flags >= 0 &&
           (descriptor_flags & FD_CLOEXEC) != 0 &&
           ((status_flags & O_ACCMODE) == O_RDWR) &&
           ((status_flags & O_NONBLOCK) != 0) == expected_nonblocking &&
           fstat(fd, value) == 0 && S_ISREG(value->st_mode) &&
           (value->st_mode & 0777) == SHM_MODE && value->st_size == 0 &&
           value->st_nlink == expected_links;
}

/* Return a created raw descriptor and a collision-resistant private name. */
static int create_unique_raw(char name[NAME_MAX + 1])
{
    unsigned attempt;

    for (attempt = 0; attempt < UNIQUE_ATTEMPTS; attempt++) {
        struct call_result result;
        int length = snprintf(name, NAME_MAX + 1, "crabc-x86-shm-%ld-%u",
                              (long)getpid(), attempt);

        if (length < 0 || length > NAME_MAX) {
            errno = ENAMETOOLONG;
            return -1;
        }
        result = raw_open(name, RAW_CREATE_FLAGS, SHM_MODE);
        if (result.value >= 0) return result.value;
        if (result.error != EEXIST) {
            errno = result.error;
            return -1;
        }
    }
    errno = EEXIST;
    return -1;
}

static int require_writable_shm_tmpfs(void)
{
    struct stat directory;
    struct statfs filesystem;

    if (stat("/dev/shm", &directory) != 0) {
        fprintf(stderr, "POSIX shared-memory reference requires /dev/shm: %s\n",
                strerror(errno));
        return 77;
    }
    if (!S_ISDIR(directory.st_mode)) {
        fprintf(stderr,
                "POSIX shared-memory reference requires /dev/shm to be a directory\n");
        return 77;
    }
    if (statfs("/dev/shm", &filesystem) != 0) {
        fprintf(stderr,
                "POSIX shared-memory reference cannot inspect /dev/shm: %s\n",
                strerror(errno));
        return 77;
    }
    if ((unsigned long)filesystem.f_type != (unsigned long)TMPFS_MAGIC) {
        fprintf(stderr,
                "POSIX shared-memory reference requires /dev/shm tmpfs (f_type=0x%lx)\n",
                (unsigned long)filesystem.f_type);
        return 77;
    }
    if (access("/dev/shm", W_OK | X_OK) != 0) {
        fprintf(stderr,
                "POSIX shared-memory reference requires writable /dev/shm: %s\n",
                strerror(errno));
        return 77;
    }
    return 0;
}

int main(void)
{
    static const char *const invalid_names[] = {
        "", "/", "///", ".", "..", "/.", "/..", "nested/name",
        "/nested/name",
    };
    char base_name[NAME_MAX + 1] = {0};
    char leading_name[NAME_MAX + 4];
    char link_name[NAME_MAX + 1] = {0};
    char leading_link_name[NAME_MAX + 4];
    char link_path[SHM_PATH_CAPACITY];
    char overlong_name[NAME_MAX + 3];
    struct stat raw_initial_stat;
    struct stat musl_initial_stat;
    struct stat raw_leading_stat;
    struct stat raw_nonblocking_stat;
    struct stat raw_link_stat;
    struct stat musl_recreated_stat;
    struct stat raw_recreated_stat;
    mode_t saved_umask;
    const char *failure = NULL;
    int raw_initial_fd = -1;
    int musl_initial_fd = -1;
    int raw_leading_fd = -1;
    int raw_nonblocking_fd = -1;
    int raw_link_fd = -1;
    int musl_recreated_fd = -1;
    int raw_recreated_fd = -1;
    int base_linked = 0;
    int link_linked = 0;
    int umask_changed = 0;
    int status = 0;
    size_t index;

#define FAIL(code, message)             \
    do {                                \
        status = (code);                \
        failure = (message);            \
        goto cleanup;                   \
    } while (0)

    status = require_writable_shm_tmpfs();
    if (status != 0) return status;

    saved_umask = umask(0);
    umask_changed = 1;

    raw_initial_fd = create_unique_raw(base_name);
    if (raw_initial_fd < 0) {
        fprintf(stderr,
                "POSIX shared-memory reference cannot create under /dev/shm: %s\n",
                strerror(errno));
        status = 77;
        goto cleanup;
    }
    base_linked = 1;
    if (snprintf(leading_name, sizeof(leading_name), "///%s", base_name) < 0) {
        FAIL(2, "could not form leading-slash POSIX name");
    }
    if (!inspect_descriptor(raw_initial_fd, 0, 1, &raw_initial_stat)) {
        FAIL(3, "raw creation did not produce a zero-sized mode-0600 CLOEXEC descriptor");
    }
    if (!expect_raw_open_error(base_name, RAW_CREATE_FLAGS, SHM_MODE, EEXIST)) {
        FAIL(4, "raw O_CREAT|O_EXCL collision did not report EEXIST");
    }

    /* musl maps all leading slashes to the same object and adds O_NONBLOCK. */
    {
        struct call_result result = musl_open(leading_name, O_RDWR, 0);
        if (result.value < 0) FAIL(5, "pinned-musl shm_open could not open raw object");
        musl_initial_fd = result.value;
    }
    if (!inspect_descriptor(musl_initial_fd, 1, 1, &musl_initial_stat) ||
        !same_object(&raw_initial_stat, &musl_initial_stat)) {
        FAIL(6, "pinned-musl shared-memory descriptor contract diverged");
    }
    {
        struct call_result result = raw_open(leading_name, O_RDWR, 0);
        if (result.value < 0) FAIL(7, "raw leading-slash normalization failed");
        raw_leading_fd = result.value;
    }
    if (!inspect_descriptor(raw_leading_fd, 0, 1, &raw_leading_stat) ||
        !same_object(&raw_initial_stat, &raw_leading_stat)) {
        FAIL(8, "raw leading-slash descriptor contract diverged");
    }
    {
        struct call_result result = raw_open(base_name, O_RDWR | O_NONBLOCK, 0);
        if (result.value < 0) FAIL(9, "raw caller-supplied O_NONBLOCK failed");
        raw_nonblocking_fd = result.value;
    }
    if (!inspect_descriptor(raw_nonblocking_fd, 1, 1, &raw_nonblocking_stat) ||
        !same_object(&raw_initial_stat, &raw_nonblocking_stat)) {
        FAIL(10, "raw flags were not otherwise direct");
    }

    for (index = 0; index < sizeof(invalid_names) / sizeof(invalid_names[0]);
         index++) {
        if (!expect_raw_open_error(invalid_names[index], O_RDWR, 0, EINVAL) ||
            !expect_musl_open_error(invalid_names[index], O_RDWR, 0, EINVAL)) {
            FAIL(11, "blank, dot, dotdot, or internal-slash name was not EINVAL");
        }
    }
    overlong_name[0] = '/';
    memset(overlong_name + 1, 'x', NAME_MAX + 1);
    overlong_name[NAME_MAX + 2] = '\0';
    if (!expect_raw_open_error(overlong_name, O_RDWR, 0, ENAMETOOLONG) ||
        !expect_musl_open_error(overlong_name, O_RDWR, 0, ENAMETOOLONG)) {
        FAIL(12, "overlong POSIX shared-memory name was not ENAMETOOLONG");
    }

    /*
     * musl's O_NOFOLLOW is not observable in F_GETFL. A relative symlink
     * beneath /dev/shm makes it observable: the direct raw policy follows it
     * unless the caller asks for O_NOFOLLOW, while musl rejects it with ELOOP.
     */
    for (index = 0; index < UNIQUE_ATTEMPTS; index++) {
        int length = snprintf(link_name, sizeof(link_name),
                              "crabc-x86-shm-link-%ld-%zu", (long)getpid(),
                              index);

        if (length < 0 || length > NAME_MAX ||
            map_raw_shm_name(link_name, link_path) != 0) {
            FAIL(13, "could not form private shared-memory symlink name");
        }
        if (symlinkat(base_name, AT_FDCWD, link_path) == 0) {
            link_linked = 1;
            break;
        }
        if (errno != EEXIST) {
            FAIL(14, "could not create shared-memory symlink evidence");
        }
    }
    if (!link_linked) FAIL(15, "could not allocate a unique shared-memory symlink");
    if (snprintf(leading_link_name, sizeof(leading_link_name), "///%s",
                 link_name) < 0) {
        FAIL(16, "could not form leading-slash symlink name");
    }
    {
        struct call_result result = raw_open(link_name, O_RDWR, 0);
        if (result.value < 0) FAIL(17, "raw open did not follow shared-memory symlink");
        raw_link_fd = result.value;
    }
    if (!inspect_descriptor(raw_link_fd, 0, 1, &raw_link_stat) ||
        !same_object(&raw_initial_stat, &raw_link_stat) ||
        !expect_raw_open_error(link_name, O_RDWR | O_NOFOLLOW, 0, ELOOP) ||
        !expect_musl_open_error(leading_link_name, O_RDWR, 0, ELOOP)) {
        FAIL(18, "raw/musl O_NOFOLLOW distinction was not observed");
    }
    if (raw_unlink(leading_link_name).value != 0) {
        FAIL(19, "raw unlink could not remove shared-memory symlink");
    }
    link_linked = 0;

    /* POSIX unlink leaves the old owned descriptors usable while removing its name. */
    if (musl_unlink(leading_name).value != 0) {
        FAIL(20, "pinned-musl shm_unlink failed");
    }
    base_linked = 0;
    if (!inspect_descriptor(raw_initial_fd, 0, 0, &raw_initial_stat) ||
        !inspect_descriptor(musl_initial_fd, 1, 0, &musl_initial_stat) ||
        !inspect_descriptor(raw_leading_fd, 0, 0, &raw_leading_stat) ||
        !inspect_descriptor(raw_nonblocking_fd, 1, 0, &raw_nonblocking_stat) ||
        !inspect_descriptor(raw_link_fd, 0, 0, &raw_link_stat) ||
        !expect_raw_open_error(base_name, O_RDWR, 0, ENOENT)) {
        FAIL(21, "unlink-after-open ownership was not retained");
    }

    /* Recreate through musl, then remove through the raw x86 unlinkat path. */
    {
        struct call_result result =
            musl_open(leading_name, RAW_CREATE_FLAGS, SHM_MODE);
        if (result.value < 0) FAIL(22, "pinned-musl shared-memory recreate failed");
        musl_recreated_fd = result.value;
    }
    base_linked = 1;
    if (!inspect_descriptor(musl_recreated_fd, 1, 1, &musl_recreated_stat) ||
        same_object(&raw_initial_stat, &musl_recreated_stat)) {
        FAIL(23, "recreated shared-memory object did not have a new identity");
    }
    {
        struct call_result result = raw_open(base_name, O_RDWR, 0);
        if (result.value < 0) FAIL(24, "raw open could not observe musl recreation");
        raw_recreated_fd = result.value;
    }
    if (!inspect_descriptor(raw_recreated_fd, 0, 1, &raw_recreated_stat) ||
        !same_object(&musl_recreated_stat, &raw_recreated_stat)) {
        FAIL(25, "raw descriptor did not observe musl recreation");
    }
    if (raw_unlink(leading_name).value != 0) {
        FAIL(26, "raw unlinkat could not remove musl recreation");
    }
    base_linked = 0;
    if (!inspect_descriptor(musl_recreated_fd, 1, 0, &musl_recreated_stat) ||
        !inspect_descriptor(raw_recreated_fd, 0, 0, &raw_recreated_stat)) {
        FAIL(27, "raw unlink-after-open ownership was not retained");
    }

cleanup:
    if (link_linked && raw_unlink(link_name).value != 0 && status == 0) {
        status = 90;
        failure = "cleanup could not unlink shared-memory symlink";
    }
    if (base_linked && raw_unlink(base_name).value != 0 && status == 0) {
        status = 91;
        failure = "cleanup could not unlink shared-memory object";
    }
    if (raw_recreated_fd >= 0 && close(raw_recreated_fd) != 0 && status == 0) {
        status = 92;
        failure = "cleanup could not close raw recreated descriptor";
    }
    if (musl_recreated_fd >= 0 && close(musl_recreated_fd) != 0 && status == 0) {
        status = 93;
        failure = "cleanup could not close musl recreated descriptor";
    }
    if (raw_link_fd >= 0 && close(raw_link_fd) != 0 && status == 0) {
        status = 94;
        failure = "cleanup could not close raw symlink descriptor";
    }
    if (raw_nonblocking_fd >= 0 && close(raw_nonblocking_fd) != 0 && status == 0) {
        status = 95;
        failure = "cleanup could not close raw nonblocking descriptor";
    }
    if (raw_leading_fd >= 0 && close(raw_leading_fd) != 0 && status == 0) {
        status = 96;
        failure = "cleanup could not close raw leading-slash descriptor";
    }
    if (musl_initial_fd >= 0 && close(musl_initial_fd) != 0 && status == 0) {
        status = 97;
        failure = "cleanup could not close musl initial descriptor";
    }
    if (raw_initial_fd >= 0 && close(raw_initial_fd) != 0 && status == 0) {
        status = 98;
        failure = "cleanup could not close raw initial descriptor";
    }
    if (umask_changed) (void)umask(saved_umask);
    if (status != 0) {
        if (failure != NULL)
            fprintf(stderr, "x86 POSIX shared-memory reference: %s\n", failure);
        return status;
    }

    puts("syscalls=fcntl:72,openat:257,unlinkat:263 namespace=dev-shm-tmpfs:name-max255 names=leading-slash-normalized:invalid-EINVAL:overlong-ENAMETOOLONG lifecycle=raw-create:musl-open:musl-unlink-after-open:musl-recreate:raw-unlink-after-open descriptors=mode0600:size0:cloexec flags=raw-cloexec-only:user-nonblock-direct:musl-cloexec-nonblock nofollow=raw-follows-symlink:raw-caller-nofollow-ELOOP:musl-ELOOP c-api-selection=excluded");
    return 0;

#undef FAIL
}
