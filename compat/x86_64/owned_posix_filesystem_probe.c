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
    static const char relative_directory[] = "/work/aliases-dir";
    struct stat metadata;
    int descriptor;
    int directory_descriptor;

    CHECK(ensure_directory("/work") == 0);
    CHECK(write_file(regular, "aliases") == 0);
    unlink(link);
    CHECK(symlink("aliases-file", link) == 0);
    CHECK(ensure_directory(relative_directory) == 0);
    CHECK(write_file("/work/aliases-dir/relative", "relative") == 0);
    unlink("/work/aliases-dir/relative-link");
    CHECK(symlink("relative", "/work/aliases-dir/relative-link") == 0);
    descriptor = open(regular, O_RDONLY);
    CHECK(descriptor >= 0);
    directory_descriptor = open(relative_directory, O_RDONLY | O_DIRECTORY);
    CHECK(directory_descriptor >= 0);

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
    /* The historical alias must pass a real directory fd and relative
     * pathname through ordinary `fstatat`, including no-follow semantics. */
    errno = E2BIG;
    CHECK(__fxstatat(-7, directory_descriptor, "relative", &metadata, 0) == 0 &&
          S_ISREG(metadata.st_mode) && metadata.st_size == 8 && errno == E2BIG);
    errno = E2BIG;
    CHECK(__fxstatat(4096, directory_descriptor, "relative-link", &metadata,
                    AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(metadata.st_mode) &&
          errno == E2BIG);
    CHECK_ERR(__xstat(4, "/work/aliases-missing", &metadata), ENOENT);
    CHECK_ERR(__fxstat(4, -1, &metadata), EBADF);
    CHECK_ERR(__fxstatat(4, -1, "relative-missing", &metadata, 0), EBADF);
    CHECK_ERR(__fxstatat(4, AT_FDCWD, regular, &metadata, 0x40000000), EINVAL);
    CHECK(close(descriptor) == 0);
    CHECK(close(directory_descriptor) == 0);
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

/* `walk` calls a directory callback before recursing through that directory's
 * raw `readdir` order. The filesystem may choose either root sibling first,
 * but a chosen directory's descendant must complete before its next sibling.
 * Keep a bounded callback transcript so this workload proves that source
 * invariant instead of treating an arbitrary callback count as a traversal
 * contract. */
#define TRAVERSAL_RECORD_CAPACITY 8
#define TRAVERSAL_PATH_CAPACITY 64

struct traversal_record {
    char path[TRAVERSAL_PATH_CAPACITY];
    int kind;
    int level;
};

static struct traversal_record ftw_records[TRAVERSAL_RECORD_CAPACITY];
static struct traversal_record nftw_records[TRAVERSAL_RECORD_CAPACITY];
static int ftw_record_count;
static int nftw_record_count;

static int record_traversal(struct traversal_record *records, int *count,
                            const char *path, int kind, int level)
{
    size_t length;

    if (*count >= TRAVERSAL_RECORD_CAPACITY)
        return -1;
    length = strlen(path);
    if (length >= sizeof(records[*count].path))
        return -1;
    memcpy(records[*count].path, path, length + 1);
    records[*count].kind = kind;
    records[*count].level = level;
    ++*count;
    return 0;
}

static int record_position(const struct traversal_record *records, int count,
                           const char *path, int kind, int level)
{
    int index;

    for (index = 0; index < count; ++index) {
        if (strcmp(records[index].path, path) == 0 && records[index].kind == kind &&
            (level < 0 || records[index].level == level))
            return index;
    }
    return -1;
}

static int validate_preorder_transcript(const struct traversal_record *records, int count,
                                        int has_levels)
{
    int root;
    int subdirectory;
    int leaf;
    int root_file;

    /* The deterministic fixture has exactly four nodes. Its two legal raw
     * directory orders are root/sub/leaf/root-file and
     * root/root-file/sub/leaf. Neither the directory API nor musl sorts them. */
    if (count != 4)
        return -1;
    root = record_position(records, count, "/work/traversal", FTW_D, has_levels ? 0 : -1);
    subdirectory = record_position(records, count, "/work/traversal/sub", FTW_D,
                                   has_levels ? 1 : -1);
    leaf = record_position(records, count, "/work/traversal/sub/leaf", FTW_F,
                           has_levels ? 2 : -1);
    root_file = record_position(records, count, "/work/traversal/root", FTW_F,
                                has_levels ? 1 : -1);
    if (root != 0 || subdirectory < 0 || leaf < 0 || root_file < 0 ||
        subdirectory >= leaf)
        return -1;
    if (subdirectory < root_file)
        return leaf < root_file ? 0 : -1;
    return root_file < subdirectory ? 0 : -1;
}

static int ftw_visit(const char *path, const struct stat *metadata, int kind)
{
    if (metadata == NULL || (kind != FTW_D && kind != FTW_F)) {
        traversal_callback_failure = 1;
        return 91;
    }
    if (record_traversal(ftw_records, &ftw_record_count, path, kind, -1) != 0) {
        traversal_callback_failure = 1;
        return 91;
    }
    return 0;
}

static int nftw_visit(const char *path, const struct stat *metadata, int kind,
                      struct FTW *walk)
{
    if (metadata == NULL || walk == NULL || walk->level < 0 ||
        (kind != FTW_D && kind != FTW_F)) {
        traversal_callback_failure = 1;
        return 92;
    }
    if (record_traversal(nftw_records, &nftw_record_count, path, kind,
                         walk->level) != 0) {
        traversal_callback_failure = 1;
        return 92;
    }
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
    memset(ftw_records, 0, sizeof(ftw_records));
    ftw_record_count = 0;
    errno = E2BIG;
    CHECK(ftw("/work/traversal", ftw_visit, 2) == 0 && errno == E2BIG);
    CHECK(traversal_callback_failure == 0 &&
          validate_preorder_transcript(ftw_records, ftw_record_count, 0) == 0);

    traversal_callback_failure = 0;
    memset(nftw_records, 0, sizeof(nftw_records));
    nftw_record_count = 0;
    errno = E2BIG;
    CHECK(nftw("/work/traversal", nftw_visit, 2, FTW_PHYS) == 0 && errno == E2BIG);
    CHECK(traversal_callback_failure == 0 &&
          validate_preorder_transcript(nftw_records, nftw_record_count, 1) == 0);

    errno = E2BIG;
    CHECK(ftw("/work/traversal", stop_ftw_visit, 1) == 37 && errno == E2BIG);
    errno = E2BIG;
    CHECK(nftw("/work/traversal", stop_nftw_visit, 1, FTW_PHYS) == 37 && errno == E2BIG);

    ftw_record_count = 0;
    errno = E2BIG;
    CHECK(ftw("/work/traversal-missing", ftw_visit, 0) == 0 && errno == E2BIG &&
          ftw_record_count == 0);
    nftw_record_count = 0;
    errno = E2BIG;
    CHECK(nftw("/work/traversal-missing", nftw_visit, 0, FTW_PHYS) == 0 && errno == E2BIG &&
          nftw_record_count == 0);

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

static int handles_case(void)
{
    struct {
        struct file_handle header;
        unsigned char bytes[MAX_HANDLE_SZ];
    } storage;
    struct {
        struct file_handle header;
        unsigned char bytes[MAX_HANDLE_SZ];
    } missing_storage;
    struct {
        struct file_handle header;
        unsigned char bytes[MAX_HANDLE_SZ];
    } invalid_descriptor_storage;
    int mount_id = 0;
    int missing_mount_id = 0;
    int invalid_descriptor_mount_id = 0;
    int mount_descriptor = -1;
    int name_result;
    int name_errno;
    int missing_result;
    int missing_errno;
    int invalid_descriptor_result;
    int invalid_descriptor_errno;
    int open_result = -2;
    int open_errno = -2;
    int invalid_open_result = -2;
    int invalid_open_errno = -2;
    struct stat expected;
    struct stat reopened;

    CHECK(ensure_directory("/work") == 0);
    CHECK(ensure_directory("/work/handles") == 0);
    CHECK(write_file("/work/handles/source", "handle source") == 0);
    CHECK(chdir("/work/handles") == 0);
    memset(&storage, 0, sizeof(storage));
    storage.header.handle_bytes = MAX_HANDLE_SZ;
    memset(&missing_storage, 0, sizeof(missing_storage));
    missing_storage.header.handle_bytes = MAX_HANDLE_SZ;
    memset(&invalid_descriptor_storage, 0, sizeof(invalid_descriptor_storage));
    invalid_descriptor_storage.header.handle_bytes = MAX_HANDLE_SZ;

    errno = E2BIG;
    name_result = name_to_handle_at(AT_FDCWD, "source", &storage.header, &mount_id, 0);
    name_errno = errno;
    CHECK(name_result == 0 || name_result == -1);
    errno = E2BIG;
    missing_result = name_to_handle_at(AT_FDCWD, "missing", &missing_storage.header,
                                        &missing_mount_id, 0);
    missing_errno = errno;
    CHECK(missing_result == -1);
    errno = E2BIG;
    invalid_descriptor_result = name_to_handle_at(-1, "source",
                                                    &invalid_descriptor_storage.header,
                                                    &invalid_descriptor_mount_id, 0);
    invalid_descriptor_errno = errno;
    CHECK(invalid_descriptor_result == -1);

    if (name_result == 0) {
        CHECK(mount_id > 0 && storage.header.handle_bytes > 0 &&
              storage.header.handle_bytes <= MAX_HANDLE_SZ && storage.header.handle_type > 0);
        mount_descriptor = open(".", O_PATH | O_DIRECTORY);
        CHECK(mount_descriptor >= 0);
        errno = E2BIG;
        open_result = open_by_handle_at(mount_descriptor, &storage.header, O_RDONLY);
        open_errno = errno;
        if (open_result >= 0) {
            CHECK(fstat(open_result, &reopened) == 0 && stat("source", &expected) == 0 &&
                  reopened.st_dev == expected.st_dev && reopened.st_ino == expected.st_ino);
            CHECK(close(open_result) == 0);
        } else {
            CHECK(open_result == -1);
        }
        /* This is an actual kernel-produced handle with a deliberately bad
         * mount descriptor. The transcript preserves the raw negative result
         * and errno instead of compressing it into an "unsupported" bucket. */
        errno = E2BIG;
        invalid_open_result = open_by_handle_at(-1, &storage.header, O_RDONLY);
        invalid_open_errno = errno;
        CHECK(invalid_open_result == -1);
        CHECK(close(mount_descriptor) == 0);
    }

    /* Every call uses the valid non-null pathname and caller-owned storage
     * required by `file_handles.rs`. The stdout comparison is deliberately
     * exact: filesystem support and authority can vary, but it cannot hide a
     * different raw syscall return or errno between the oracle and product. */
    printf("handles raw name=%d errno=%d missing=%d errno=%d bad-dirfd=%d errno=%d "
           "open=%d errno=%d bad-open=%d errno=%d\n",
           name_result, name_errno, missing_result, missing_errno,
           invalid_descriptor_result, invalid_descriptor_errno,
           open_result, open_errno, invalid_open_result, invalid_open_errno);
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
