/*
 * One installed-header workload for the POSIX filesystem composition.
 *
 * `__xstat` and its siblings have no public project declarations. Their four
 * declarations below are the pinned musl 1.2.6 `src/stat/__xstat.c` ABI: the
 * historical version word is accepted and ignored before the ordinary stat
 * entry is reached. Every other spelling comes from the installed headers.
 *
 * The historical pathname APIs intentionally prove only their source contract:
 * `mktemp`, `tmpnam`, and `tempnam` return an unreserved absent pathname. The
 * fixture never treats one as an authority or creates it. File-handle outcomes
 * are likewise kernel/filesystem dependent. A successful handle is validated
 * on the actual execution-root filesystem; an unsupported or permission result
 * remains an explicit contained outcome rather than fabricated success.
 */
#define _GNU_SOURCE 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern int __xstat(int, const char *, struct stat *);
extern int __lxstat(int, const char *, struct stat *);
extern int __fxstat(int, int, struct stat *);
extern int __fxstatat(int, int, const char *, struct stat *, int);

static int failure_line;

#define CHECK(condition) do { \
    if (!(condition)) { \
        failure_line = __LINE__; \
        return -1; \
    } \
} while (0)

#define CHECK_ERR(call, expected) do { \
    errno = 0; \
    CHECK((call) == -1 && errno == (expected)); \
} while (0)

static int ensure_directory(const char *path)
{
    if (mkdir(path, 0700) == 0)
        return 0;
    return errno == EEXIST ? 0 : -1;
}

static int write_file(const char *path, const char *contents)
{
    int descriptor = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    size_t length = strlen(contents);

    if (descriptor < 0)
        return -1;
    if (write(descriptor, contents, length) != (ssize_t)length || close(descriptor) != 0)
        return -1;
    return 0;
}

static int aliases_case(void)
{
    static const char regular[] = "/work/aliases-file";
    static const char link[] = "/work/aliases-link";
    struct stat metadata;
    int descriptor;

    CHECK(ensure_directory("/work") == 0);
    CHECK(write_file(regular, "aliases") == 0);
    unlink(link);
    CHECK(symlink("aliases-file", link) == 0);
    descriptor = open(regular, O_RDONLY);
    CHECK(descriptor >= 0);

    /* Different arbitrary historical selector values take the same current
     * Linux stat ABI. Successful calls retain the unrelated errno sentinel. */
    errno = E2BIG;
    CHECK(__xstat(0, regular, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
          metadata.st_size == 7 && errno == E2BIG);
    errno = E2BIG;
    CHECK(__xstat(0x7fffffff, regular, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
          errno == E2BIG);
    errno = E2BIG;
    CHECK(__lxstat(-1, link, &metadata) == 0 && S_ISLNK(metadata.st_mode) &&
          errno == E2BIG);
    errno = E2BIG;
    CHECK(__fxstat(1234, descriptor, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
          errno == E2BIG);
    errno = E2BIG;
    CHECK(__fxstatat(77, AT_FDCWD, regular, &metadata, 0) == 0 &&
          S_ISREG(metadata.st_mode) && errno == E2BIG);
    CHECK_ERR(__xstat(4, "/work/aliases-missing", &metadata), ENOENT);
    CHECK_ERR(__fxstat(4, -1, &metadata), EBADF);
    CHECK_ERR(__fxstatat(4, -1, "relative-missing", &metadata, 0), EBADF);
    CHECK_ERR(__fxstatat(4, AT_FDCWD, regular, &metadata, 0x40000000), EINVAL);
    CHECK(close(descriptor) == 0);
    puts("aliases ok");
    return 0;
}

static int select_pick(const struct dirent *entry)
{
    return strncmp(entry->d_name, "pick", 4) == 0;
}

static int directory_case(void)
{
    static const char directory[] = "/work/directory";
    struct dirent caller;
    struct dirent *result;
    struct dirent **entries;
    struct dirent first_entry;
    struct dirent second_entry;
    const struct dirent *two;
    const struct dirent *ten;
    char second_name[sizeof(second_entry.d_name)];
    DIR *stream;
    long cursor;
    int count = 0;
    int readdir_result;

    CHECK(ensure_directory("/work") == 0);
    CHECK(ensure_directory(directory) == 0);
    CHECK(write_file("/work/directory/first", "1") == 0);
    CHECK(write_file("/work/directory/second", "2") == 0);
    CHECK(write_file("/work/directory/pick2", "2") == 0);
    CHECK(write_file("/work/directory/pick10", "10") == 0);

    stream = opendir(directory);
    CHECK(stream != NULL);
    errno = 0;
    for (;;) {
        result = (struct dirent *)(uintptr_t)1;
        readdir_result = readdir_r(stream, &caller, &result);
        CHECK(readdir_result == 0);
        if (result == NULL)
            break;
        CHECK(result == &caller && caller.d_name[0] != '\0');
        ++count;
    }
    CHECK(errno == 0 && count == 6);
    CHECK(closedir(stream) == 0);

    /* A tell cookie is opaque, but seeking back to it must replay the next
     * record. This avoids inventing an ordering or numeric-cookie contract. */
    stream = opendir(directory);
    CHECK(stream != NULL);
    CHECK(readdir(stream) != NULL);
    cursor = telldir(stream);
    CHECK(cursor >= 0);
    result = readdir(stream);
    CHECK(result != NULL);
    memcpy(second_name, result->d_name, sizeof(second_name));
    seekdir(stream, cursor);
    result = readdir(stream);
    CHECK(result != NULL && strcmp(result->d_name, second_name) == 0);
    CHECK(closedir(stream) == 0);

    memset(&first_entry, 0, sizeof(first_entry));
    memset(&second_entry, 0, sizeof(second_entry));
    strcpy(first_entry.d_name, "pick2");
    strcpy(second_entry.d_name, "pick10");
    two = &first_entry;
    ten = &second_entry;
    CHECK(alphasort(&two, &ten) > 0);
    CHECK(versionsort(&two, &ten) < 0);

    entries = NULL;
    errno = E2BIG;
    count = scandir(directory, &entries, select_pick, alphasort);
    CHECK(count == 2 && entries != NULL && errno == E2BIG);
    CHECK(strcmp(entries[0]->d_name, "pick10") == 0);
    CHECK(strcmp(entries[1]->d_name, "pick2") == 0);
    free(entries[0]);
    free(entries[1]);
    free(entries);

    /* Musl does not write the result pointer before opendir succeeds. */
    entries = (struct dirent **)(uintptr_t)1;
    CHECK_ERR(scandir("/work/directory-missing", &entries, NULL, alphasort), ENOENT);
    CHECK(entries == (struct dirent **)(uintptr_t)1);
    puts("directory ok");
    return 0;
}

static int traversal_callback_failure;
static int ftw_callback_count;
static int nftw_callback_count;
static int nftw_maximum_level;

static int ftw_visit(const char *path, const struct stat *metadata, int kind)
{
    (void)path;
    if (metadata == NULL || (kind != FTW_D && kind != FTW_F)) {
        traversal_callback_failure = 1;
        return 91;
    }
    ++ftw_callback_count;
    return 0;
}

static int nftw_visit(const char *path, const struct stat *metadata, int kind,
                      struct FTW *walk)
{
    (void)path;
    if (metadata == NULL || walk == NULL || walk->level < 0 ||
        (kind != FTW_D && kind != FTW_F)) {
        traversal_callback_failure = 1;
        return 92;
    }
    if (walk->level > nftw_maximum_level)
        nftw_maximum_level = walk->level;
    ++nftw_callback_count;
    return 0;
}

static int stop_ftw_visit(const char *path, const struct stat *metadata, int kind)
{
    (void)path;
    (void)metadata;
    (void)kind;
    return 37;
}

static int stop_nftw_visit(const char *path, const struct stat *metadata, int kind,
                           struct FTW *walk)
{
    (void)path;
    (void)metadata;
    (void)kind;
    (void)walk;
    return 37;
}

static atomic_int cancellation_ready;
static atomic_int cancellation_release;
static atomic_int cancellation_cleanup;
static atomic_int cancellation_worker_failure;

static void traversal_cleanup(void *ignored)
{
    (void)ignored;
    atomic_store(&cancellation_cleanup, 1);
}

static int blocking_nftw_visit(const char *path, const struct stat *metadata, int kind,
                               struct FTW *walk)
{
    (void)path;
    (void)metadata;
    (void)kind;
    (void)walk;
    atomic_store(&cancellation_ready, 1);
    while (!atomic_load(&cancellation_release))
        atomic_signal_fence(memory_order_seq_cst);
    return 0;
}

static void *traversal_worker(void *ignored)
{
    int result;

    (void)ignored;
    pthread_cleanup_push(traversal_cleanup, NULL);
    result = nftw("/work/traversal", blocking_nftw_visit, 1, FTW_PHYS);
    if (result != 0)
        atomic_store(&cancellation_worker_failure, 1);
    /* nftw restores musl's disabled state before this explicit cancellation
     * point. The test therefore detects a request arriving during the walk
     * without assuming restoration itself delivers it. */
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return (void *)(uintptr_t)1;
}

static int traversal_case(void)
{
    pthread_t worker;
    void *worker_result = NULL;

    CHECK(ensure_directory("/work") == 0);
    CHECK(ensure_directory("/work/traversal") == 0);
    CHECK(ensure_directory("/work/traversal/sub") == 0);
    CHECK(write_file("/work/traversal/root", "root") == 0);
    CHECK(write_file("/work/traversal/sub/leaf", "leaf") == 0);

    traversal_callback_failure = 0;
    ftw_callback_count = 0;
    errno = E2BIG;
    CHECK(ftw("/work/traversal", ftw_visit, 2) == 0 && errno == E2BIG);
    CHECK(traversal_callback_failure == 0 && ftw_callback_count >= 3);

    traversal_callback_failure = 0;
    nftw_callback_count = 0;
    nftw_maximum_level = 0;
    errno = E2BIG;
    CHECK(nftw("/work/traversal", nftw_visit, 2, FTW_PHYS) == 0 && errno == E2BIG);
    CHECK(traversal_callback_failure == 0 && nftw_callback_count >= 4 &&
          nftw_maximum_level >= 2);

    errno = E2BIG;
    CHECK(ftw("/work/traversal", stop_ftw_visit, 1) == 37 && errno == E2BIG);
    errno = E2BIG;
    CHECK(nftw("/work/traversal", stop_nftw_visit, 1, FTW_PHYS) == 37 && errno == E2BIG);

    ftw_callback_count = 0;
    errno = E2BIG;
    CHECK(ftw("/work/traversal-missing", ftw_visit, 0) == 0 && errno == E2BIG &&
          ftw_callback_count == 0);
    nftw_callback_count = 0;
    errno = E2BIG;
    CHECK(nftw("/work/traversal-missing", nftw_visit, 0, FTW_PHYS) == 0 && errno == E2BIG &&
          nftw_callback_count == 0);

    atomic_store(&cancellation_ready, 0);
    atomic_store(&cancellation_release, 0);
    atomic_store(&cancellation_cleanup, 0);
    atomic_store(&cancellation_worker_failure, 0);
    CHECK(pthread_create(&worker, NULL, traversal_worker, NULL) == 0);
    while (!atomic_load(&cancellation_ready))
        atomic_signal_fence(memory_order_seq_cst);
    CHECK(pthread_cancel(worker) == 0);
    atomic_store(&cancellation_release, 1);
    CHECK(pthread_join(worker, &worker_result) == 0);
    CHECK(worker_result == PTHREAD_CANCELED && atomic_load(&cancellation_cleanup) == 1 &&
          atomic_load(&cancellation_worker_failure) == 0);
    puts("traversal ok");
    return 0;
}

static int temporary_case(void)
{
    char malformed[] = "/work/temporary/malformed";
    char generated[] = "/work/temporary/mktemp-XXXXXX";
    char caller_buffer[L_tmpnam];
    char oversized[4096];
    char *static_buffer;
    char *allocated;
    struct stat metadata;

    CHECK(ensure_directory("/work") == 0);
    CHECK(ensure_directory("/work/temporary") == 0);

    errno = 0;
    CHECK(mktemp(malformed) == malformed && malformed[0] == '\0' && errno == EINVAL);
    errno = E2BIG;
    CHECK(mktemp(generated) == generated && strncmp(generated, "/work/temporary/mktemp-", 23) == 0 &&
          strcmp(generated + strlen(generated) - 6, "XXXXXX") != 0 && errno == ENOENT);
    CHECK(lstat(generated, &metadata) == -1 && errno == ENOENT);

    memset(caller_buffer, 0, sizeof(caller_buffer));
    errno = E2BIG;
    CHECK(tmpnam(caller_buffer) == caller_buffer &&
          strncmp(caller_buffer, "/tmp/tmpnam_", 12) == 0 && errno == E2BIG);
    CHECK(lstat(caller_buffer, &metadata) == -1 && errno == ENOENT);
    static_buffer = tmpnam(NULL);
    CHECK(static_buffer != NULL && static_buffer != caller_buffer &&
          strncmp(static_buffer, "/tmp/tmpnam_", 12) == 0);
    CHECK(lstat(static_buffer, &metadata) == -1 && errno == ENOENT);

    allocated = tempnam("/work/temporary", "legacy");
    CHECK(allocated != NULL && strncmp(allocated, "/work/temporary/legacy_", 23) == 0);
    CHECK(lstat(allocated, &metadata) == -1 && errno == ENOENT);
    free(allocated);
    allocated = tempnam(NULL, NULL);
    CHECK(allocated != NULL && strncmp(allocated, "/tmp/temp_", 10) == 0);
    CHECK(lstat(allocated, &metadata) == -1 && errno == ENOENT);
    free(allocated);

    memset(oversized, 'x', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';
    errno = 0;
    CHECK(tempnam(oversized, "x") == NULL && errno == ENAMETOOLONG);

    CHECK(write_file("/work/temporary/lchmod-regular", "regular") == 0);
    unlink("/work/temporary/lchmod-link");
    CHECK(symlink("lchmod-regular", "/work/temporary/lchmod-link") == 0);
    CHECK_ERR(lchmod("/work/temporary/lchmod-link", 0600), EOPNOTSUPP);
    puts("temporary ok");
    return 0;
}

static int acceptable_unsupported(int error)
{
    return error == EOPNOTSUPP || error == ENOSYS || error == EPERM || error == EOVERFLOW;
}

static int acceptable_pointer_error(int error)
{
    return error == EBADF || error == EFAULT || error == EOPNOTSUPP ||
           error == ENOSYS || error == EPERM;
}

static int handles_case(void)
{
    struct {
        struct file_handle header;
        unsigned char bytes[MAX_HANDLE_SZ];
    } storage;
    int mount_id = 0;
    int mount_descriptor = -1;
    int result;
    struct stat expected;
    struct stat reopened;

    CHECK(ensure_directory("/work") == 0);
    CHECK(ensure_directory("/work/handles") == 0);
    CHECK(write_file("/work/handles/source", "handle source") == 0);
    CHECK(chdir("/work/handles") == 0);
    memset(&storage, 0, sizeof(storage));
    storage.header.handle_bytes = MAX_HANDLE_SZ;

    errno = E2BIG;
    result = name_to_handle_at(AT_FDCWD, "source", &storage.header, &mount_id, 0);
    if (result == 0) {
        CHECK(mount_id > 0 && storage.header.handle_bytes > 0 &&
              storage.header.handle_bytes <= MAX_HANDLE_SZ && storage.header.handle_type > 0);
        CHECK_ERR(name_to_handle_at(-1, "source", &storage.header, &mount_id, 0), EBADF);
        mount_descriptor = open(".", O_PATH | O_DIRECTORY);
        CHECK(mount_descriptor >= 0);
        errno = E2BIG;
        result = open_by_handle_at(mount_descriptor, &storage.header, O_RDONLY);
        if (result >= 0) {
            CHECK(fstat(result, &reopened) == 0 && stat("source", &expected) == 0 &&
                  reopened.st_dev == expected.st_dev && reopened.st_ino == expected.st_ino);
            CHECK(close(result) == 0);
            puts("handles supported");
        } else {
            CHECK(errno == EPERM || errno == EACCES || errno == EBADF || errno == EFAULT);
            puts("handles permission-limited");
        }
        CHECK(close(mount_descriptor) == 0);
    } else {
        CHECK(acceptable_unsupported(errno));
        puts("handles unavailable");
    }

    /* The raw syscall wrapper never turns caller pointer/descriptor errors
     * into a policy layer. On filesystems without handles, their supported
     * error happens first and remains an allowed observed outcome. */
    errno = 0;
    CHECK(name_to_handle_at(AT_FDCWD, NULL, &storage.header, &mount_id, 0) == -1 &&
          acceptable_pointer_error(errno));
    errno = 0;
    CHECK(name_to_handle_at(AT_FDCWD, "source", NULL, &mount_id, 0) == -1 &&
          acceptable_pointer_error(errno));
    errno = 0;
    CHECK(open_by_handle_at(-1, NULL, O_RDONLY) == -1 && acceptable_pointer_error(errno));
    CHECK(chdir("/") == 0);
    return 0;
}

static int run_case(const char *name)
{
    if (strcmp(name, "aliases") == 0)
        return aliases_case();
    if (strcmp(name, "directory") == 0)
        return directory_case();
    if (strcmp(name, "traversal") == 0)
        return traversal_case();
    if (strcmp(name, "temporary") == 0)
        return temporary_case();
    if (strcmp(name, "handles") == 0)
        return handles_case();
    errno = EINVAL;
    return -1;
}

int main(int argc, char **argv)
{
    int result;

    if (argc != 2) {
        fprintf(stderr, "usage: %s CASE\n", argv[0]);
        return 2;
    }
    alarm(20);
    result = run_case(argv[1]);
    if (result != 0) {
        fprintf(stderr, "owned-posix-filesystem failure at line %d errno %d\n", failure_line, errno);
        return 1;
    }
    return 0;
}
