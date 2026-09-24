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
#include <limits.h>
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

/* ---- Wider frozen-mapping edges ------------------------------------------
 *
 * The cases below print exact transcripts rather than pass/fail bits wherever
 * the observed value is itself the contract (comparator signs, traversal
 * records, raw errno words), so the runner's stdout comparison against pinned
 * musl is the judge. Raw readdir order is filesystem-owned; traversal
 * transcripts are therefore sorted before printing and their ordering
 * invariants are checked separately against the unsorted callback sequence. */

static int sign_of(int value)
{
    return (value > 0) - (value < 0);
}

static int comparator_case(void)
{
    static const char *const pairs[][2] = {
        {"a", "b"}, {"b", "a"}, {"abc", "abc"}, {"", "a"}, {"a", ""},
        {"\xff", "a"}, {"a", "\x80"}, {"A", "a"}, {"item9", "item10"},
        {"item10", "item9"}, {"a01", "a1"}, {"a1", "a01"}, {"a0", "a00"},
        {"a00", "a0"}, {"000", "00"}, {"1.01", "1.010"}, {"1.002", "1.01"},
        {"a09", "a1"}, {"a9", "a09"}, {"jan", "jan1"}, {"x2y", "x10y"},
        {"x012", "x0112"}, {"0", "00"}, {"9", "10"}, {"abc9", "abc9a"},
    };
    struct dirent left;
    struct dirent right;
    const struct dirent *left_pointer = &left;
    const struct dirent *right_pointer = &right;
    size_t index;

    for (index = 0; index < sizeof(pairs) / sizeof(pairs[0]); ++index) {
        memset(&left, 0, sizeof(left));
        memset(&right, 0, sizeof(right));
        strcpy(left.d_name, pairs[index][0]);
        strcpy(right.d_name, pairs[index][1]);
        printf("compare %zu alpha=%d version=%d\n", index,
               sign_of(alphasort(&left_pointer, &right_pointer)),
               sign_of(versionsort(&left_pointer, &right_pointer)));
    }
    return 0;
}

static int reject_all(const struct dirent *entry)
{
    (void)entry;
    return 0;
}

static int select_versioned(const struct dirent *entry)
{
    return entry->d_name[0] == 'v';
}

static int directory_edges_case(void)
{
    static const char directory[] = "/work/directory-edges";
    static const char *const versioned[] = {"v10", "v9", "v09", "v1.2", "v1.10", "v0"};
    struct dirent caller;
    struct dirent *result;
    struct dirent **entries;
    struct stat metadata;
    long cookies[16];
    char names[16][sizeof(caller.d_name)];
    DIR *stream;
    size_t index;
    int count;
    int replay;

    CHECK(ensure_directory("/work") == 0);
    CHECK(ensure_directory(directory) == 0);
    for (index = 0; index < sizeof(versioned) / sizeof(versioned[0]); ++index) {
        char path[64];
        snprintf(path, sizeof(path), "%s/%s", directory, versioned[index]);
        CHECK(write_file(path, versioned[index]) == 0);
    }
    CHECK(ensure_directory("/work/directory-edges/vdir") == 0);

    /* A fresh and a rewound stream both report the initial cookie; readdir_r
     * leaves a caller errno untouched on every success and at the end. */
    stream = opendir(directory);
    CHECK(stream != NULL);
    CHECK(telldir(stream) == 0);
    count = 0;
    for (;;) {
        errno = E2BIG;
        CHECK(readdir_r(stream, &caller, &result) == 0 && errno == E2BIG);
        if (result == NULL)
            break;
        CHECK(result == &caller && count < 16);
        CHECK(caller.d_reclen >= offsetof(struct dirent, d_name) + strlen(caller.d_name) + 1);
        memcpy(names[count], caller.d_name, sizeof(names[count]));
        cookies[count] = telldir(stream);
        ++count;
    }
    CHECK(count == 9);
    /* Every telldir cookie replays exactly the following record. */
    for (replay = 0; replay + 1 < count; ++replay) {
        seekdir(stream, cookies[replay]);
        CHECK(telldir(stream) == cookies[replay]);
        errno = E2BIG;
        CHECK(readdir_r(stream, &caller, &result) == 0 && result == &caller &&
              errno == E2BIG && strcmp(caller.d_name, names[replay + 1]) == 0);
    }
    seekdir(stream, cookies[count - 1]);
    CHECK(readdir_r(stream, &caller, &result) == 0 && result == NULL);
    rewinddir(stream);
    CHECK(telldir(stream) == 0);
    CHECK(readdir_r(stream, &caller, &result) == 0 && result == &caller &&
          strcmp(caller.d_name, names[0]) == 0);
    CHECK(closedir(stream) == 0);

    /* Selector-owned zero results still publish a null vector and zero. */
    entries = (struct dirent **)(uintptr_t)1;
    errno = E2BIG;
    CHECK(scandir(directory, &entries, reject_all, alphasort) == 0 &&
          entries == NULL && errno == E2BIG);

    /* No comparator: every record, including dot entries, in raw order. */
    entries = NULL;
    count = scandir(directory, &entries, NULL, NULL);
    CHECK(count == 9 && entries != NULL);
    for (replay = 0; replay < count; ++replay) {
        CHECK(strcmp(entries[replay]->d_name, names[replay]) == 0);
        free(entries[replay]);
    }
    free(entries);

    /* The versionsort comparator through scandir, with copied record fields. */
    entries = NULL;
    count = scandir(directory, &entries, select_versioned, versionsort);
    CHECK(count == 7 && entries != NULL);
    printf("scandir versionsort");
    for (replay = 0; replay < count; ++replay) {
        char path[64];
        snprintf(path, sizeof(path), "%s/%s", directory, entries[replay]->d_name);
        CHECK(lstat(path, &metadata) == 0 && metadata.st_ino == entries[replay]->d_ino);
        CHECK(entries[replay]->d_type ==
              (S_ISDIR(metadata.st_mode) ? DT_DIR : DT_REG));
        printf(" %s", entries[replay]->d_name);
        free(entries[replay]);
    }
    printf("\n");
    free(entries);
    count = scandir(directory, &entries, select_versioned, alphasort);
    CHECK(count == 7);
    printf("scandir alphasort");
    for (replay = 0; replay < count; ++replay) {
        printf(" %s", entries[replay]->d_name);
        free(entries[replay]);
    }
    printf("\n");
    free(entries);

    /* A non-directory path fails in opendir before the result is written. */
    CHECK(write_file("/work/directory-edges-file", "x") == 0);
    entries = (struct dirent **)(uintptr_t)1;
    CHECK_ERR(scandir("/work/directory-edges-file", &entries, NULL, NULL), ENOTDIR);
    CHECK(entries == (struct dirent **)(uintptr_t)1);
    puts("directory edges ok");
    return 0;
}

/* Musl serializes readdir_r on one stream through the DIR lock, so
 * concurrent readers partition the stream: each record is returned to
 * exactly one reader. */
#define SHARED_FILES 1200
#define SHARED_READERS 4
#define SHARED_ROUNDS 12

static atomic_int shared_seen[SHARED_FILES + 2];
static atomic_int shared_start;
static atomic_int shared_failure;

static void *shared_reader(void *argument)
{
    DIR *stream = argument;
    struct dirent caller;
    struct dirent *result;
    int error;

    while (!atomic_load(&shared_start))
        atomic_signal_fence(memory_order_seq_cst);
    for (;;) {
        error = readdir_r(stream, &caller, &result);
        if (error != 0) {
            atomic_store(&shared_failure, 1000 + error);
            break;
        }
        if (result == NULL)
            break;
        if (strcmp(caller.d_name, ".") == 0) {
            atomic_fetch_add(&shared_seen[SHARED_FILES], 1);
        } else if (strcmp(caller.d_name, "..") == 0) {
            atomic_fetch_add(&shared_seen[SHARED_FILES + 1], 1);
        } else {
            char *end;
            long value = strtol(caller.d_name + 1, &end, 10);
            if (caller.d_name[0] != 'f' || *end != '\0' || value < 0 ||
                value >= SHARED_FILES) {
                atomic_store(&shared_failure, 2);
                break;
            }
            atomic_fetch_add(&shared_seen[value], 1);
        }
    }
    return NULL;
}

static int directory_threads_case(void)
{
    static const char directory[] = "/work/directory-threads";
    pthread_t readers[SHARED_READERS];
    DIR *stream;
    int index;
    int round;

    CHECK(ensure_directory("/work") == 0);
    CHECK(ensure_directory(directory) == 0);
    for (index = 0; index < SHARED_FILES; ++index) {
        char path[64];
        int descriptor;
        snprintf(path, sizeof(path), "%s/f%d", directory, index);
        descriptor = open(path, O_CREAT | O_WRONLY, 0600);
        CHECK(descriptor >= 0 && close(descriptor) == 0);
    }
    for (round = 0; round < SHARED_ROUNDS; ++round) {
        stream = opendir(directory);
        CHECK(stream != NULL);
        for (index = 0; index < SHARED_FILES + 2; ++index)
            atomic_store(&shared_seen[index], 0);
        atomic_store(&shared_start, 0);
        atomic_store(&shared_failure, 0);
        for (index = 0; index < SHARED_READERS; ++index)
            CHECK(pthread_create(&readers[index], NULL, shared_reader, stream) == 0);
        atomic_store(&shared_start, 1);
        for (index = 0; index < SHARED_READERS; ++index)
            CHECK(pthread_join(readers[index], NULL) == 0);
        CHECK(atomic_load(&shared_failure) == 0);
        for (index = 0; index < SHARED_FILES + 2; ++index)
            CHECK(atomic_load(&shared_seen[index]) == 1);
        CHECK(closedir(stream) == 0);
    }
    puts("directory threads ok");
    return 0;
}

#define WALK_CAPACITY 64

struct walk_record {
    char path[160];
    int kind;
    int level;
    int base;
    unsigned type;
    int entry_errno;
};

static struct walk_record walk_records[WALK_CAPACITY];
static int walk_count;
static int walk_overflow;
static int walk_stop_kind;

static int walk_visit(const char *path, const struct stat *metadata, int kind,
                      struct FTW *walk)
{
    struct walk_record *record;

    if (walk_count >= WALK_CAPACITY || strlen(path) >= sizeof(record->path)) {
        walk_overflow = 1;
        return 93;
    }
    record = &walk_records[walk_count++];
    strcpy(record->path, path);
    record->kind = kind;
    record->level = walk->level;
    record->base = walk->base;
    record->type = kind == FTW_NS ? 0 : (unsigned)(metadata->st_mode & S_IFMT) >> 12;
    record->entry_errno = errno;
    errno = E2BIG;
    if (walk_stop_kind != 0 && kind == walk_stop_kind)
        return -5;
    return 0;
}

static int legacy_walk_visit(const char *path, const struct stat *metadata, int kind)
{
    struct FTW walk = {0, -1};

    /* Musl's ftw forwards to nftw with FTW_PHYS; its base and level remain
     * invisible to a three-argument callback. */
    walk.base = (int)(strrchr(path, '/') ? strrchr(path, '/') - path + 1 : 0);
    return walk_visit(path, metadata, kind, &walk);
}

static int compare_walk_records(const void *left, const void *right)
{
    const struct walk_record *a = left;
    const struct walk_record *b = right;
    int order = strcmp(a->path, b->path);

    return order != 0 ? order : a->kind - b->kind;
}

static int is_path_prefix(const char *parent, const char *child)
{
    size_t length = strlen(parent);

    return strncmp(parent, child, length) == 0 && child[length] == '/';
}

/* Pre-order requires each directory callback before its descendants; FTW_DEPTH
 * requires it after them. Both require path + base to name the basename. */
static int check_walk_order(int depth_first)
{
    int parent;
    int child;

    for (parent = 0; parent < walk_count; ++parent) {
        const struct walk_record *record = &walk_records[parent];
        if (record->base < 0 || record->base > (int)strlen(record->path))
            return -1;
        for (child = 0; child < walk_count; ++child) {
            if (!is_path_prefix(record->path, walk_records[child].path))
                continue;
            if (depth_first ? child > parent : child < parent)
                return -1;
        }
    }
    return 0;
}

static int print_walk(const char *label, int result, int result_errno, int depth_first)
{
    int index;

    if (walk_overflow || check_walk_order(depth_first) != 0)
        return -1;
    qsort(walk_records, (size_t)walk_count, sizeof(walk_records[0]), compare_walk_records);
    printf("walk %s result=%d errno=%d count=%d\n", label, result, result_errno, walk_count);
    for (index = 0; index < walk_count; ++index) {
        const struct walk_record *record = &walk_records[index];
        printf("  %s kind=%d level=%d base=%d type=%o errno=%d\n", record->path,
               record->kind, record->level, record->base, record->type,
               record->entry_errno);
    }
    return 0;
}

static int run_walk(const char *label, const char *path, int fd_limit, int flags)
{
    int result;
    int result_errno;

    walk_count = 0;
    walk_overflow = 0;
    errno = E2BIG;
    result = nftw(path, walk_visit, fd_limit, flags);
    result_errno = errno;
    return print_walk(label, result, result_errno, (flags & FTW_DEPTH) != 0);
}

static int run_legacy_walk(const char *label, const char *path, int fd_limit)
{
    int result;
    int result_errno;

    walk_count = 0;
    walk_overflow = 0;
    errno = E2BIG;
    result = ftw(path, legacy_walk_visit, fd_limit);
    result_errno = errno;
    return print_walk(label, result, result_errno, 0);
}

static int traversal_flags_case(void)
{
    char long_path[PATH_MAX + 2];

    /* /work/walk: a regular file, a directory holding a file, a symlink back
     * to its parent, and a dangling symlink, plus a symlink to that directory
     * and an empty nested directory. */
    CHECK(ensure_directory("/work") == 0);
    CHECK(ensure_directory("/work/walk") == 0);
    CHECK(ensure_directory("/work/walk/d") == 0);
    CHECK(ensure_directory("/work/walk/d/e") == 0);
    CHECK(write_file("/work/walk/a", "a") == 0);
    CHECK(write_file("/work/walk/d/f", "f") == 0);
    unlink("/work/walk/d/loop");
    CHECK(symlink("..", "/work/walk/d/loop") == 0);
    unlink("/work/walk/d/dangle");
    CHECK(symlink("missing", "/work/walk/d/dangle") == 0);
    unlink("/work/walk/s");
    CHECK(symlink("d", "/work/walk/s") == 0);
    unlink("/work/walk-dangle");
    CHECK(symlink("walk-missing", "/work/walk-dangle") == 0);

    CHECK(run_walk("follow", "/work/walk", 16, 0) == 0);
    CHECK(run_walk("physical", "/work/walk", 16, FTW_PHYS) == 0);
    CHECK(run_walk("depth", "/work/walk", 16, FTW_DEPTH) == 0);
    CHECK(run_walk("depth-physical", "/work/walk/", 16, FTW_DEPTH | FTW_PHYS) == 0);
    CHECK(run_walk("mount", "/work/walk", 16, FTW_MOUNT | FTW_PHYS) == 0);
    CHECK(run_walk("one-descriptor", "/work/walk", 1, FTW_PHYS) == 0);
    CHECK(run_walk("two-descriptors", "/work/walk", 2, FTW_PHYS) == 0);
    CHECK(run_legacy_walk("ftw", "/work/walk", 16) == 0);
    CHECK(run_walk("regular-root", "/work/walk/a", 4, 0) == 0);
    CHECK(run_walk("dangling-root", "/work/walk-dangle", 4, 0) == 0);
    CHECK(run_walk("dangling-root-physical", "/work/walk-dangle", 4, FTW_PHYS) == 0);
    CHECK(run_walk("missing-root", "/work/walk-missing", 4, 0) == 0);
    CHECK(run_legacy_walk("ftw-missing-root", "/work/walk-missing", 4) == 0);
    CHECK(run_walk("not-directory", "/work/walk/a/x", 4, FTW_PHYS) == 0);
    walk_stop_kind = FTW_SL;
    CHECK(run_walk("callback-stop", "/work/walk", 16, FTW_PHYS) == 0);
    walk_stop_kind = 0;

    memset(long_path, 'x', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = '\0';
    CHECK(run_walk("overlong", long_path, 4, 0) == 0);
    long_path[PATH_MAX] = '\0';
    CHECK(run_walk("kernel-overlong", long_path, 4, 0) == 0);
    puts("traversal flags ok");
    return 0;
}

/* Unreadable directories and unsearchable parents are only observable
 * without DAC override, so this child drops to an unprivileged identity. */
static int traversal_permissions_case(void)
{
    CHECK(ensure_directory("/work") == 0);
    CHECK(chmod("/work", 0755) == 0);
    CHECK(ensure_directory("/work/perm") == 0);
    CHECK(chmod("/work/perm", 0755) == 0);
    CHECK(ensure_directory("/work/perm/closed") == 0);
    CHECK(write_file("/work/perm/closed/hidden", "h") == 0);
    CHECK(chmod("/work/perm/closed", 0000) == 0);
    CHECK(ensure_directory("/work/perm/list-only") == 0);
    CHECK(write_file("/work/perm/list-only/entry", "e") == 0);
    CHECK(chmod("/work/perm/list-only", 0444) == 0);
    CHECK(write_file("/work/perm/visible", "v") == 0);
    CHECK(chmod("/work/perm/visible", 0644) == 0);
    CHECK(setgid(65534) == 0 && setuid(65534) == 0);
    CHECK(access("/work/perm/closed", R_OK) == -1);
    CHECK(run_walk("permissions", "/work/perm", 8, FTW_PHYS) == 0);
    CHECK(run_walk("permissions-depth", "/work/perm", 8, FTW_PHYS | FTW_DEPTH) == 0);
    /* At an exhausted descriptor budget musl closes even a failed open. */
    CHECK(run_walk("permissions-one-descriptor", "/work/perm", 1, FTW_PHYS) == 0);
    CHECK(run_walk("unsearchable-root-child", "/work/perm/list-only/entry", 8, 0) == 0);
    puts("traversal permissions ok");
    return 0;
}

static int legacy_edges_case(void)
{
    char empty[] = "";
    char five[] = "/work/legacy/XXXXX";
    char infix[] = "/work/legacy/XXXXXXa";
    char seven[] = "/work/legacy/tXXXXXXX";
    char not_directory[] = "/work/legacy/regular/XXXXXX";
    char missing_parent[] = "/work/legacy/missing/XXXXXX";
    char boundary[PATH_MAX + 8];
    size_t directory_length;
    char *name;
    struct stat metadata;

    CHECK(ensure_directory("/work") == 0);
    CHECK(ensure_directory("/work/legacy") == 0);
    CHECK(write_file("/work/legacy/regular", "r") == 0);

    errno = 0;
    CHECK(mktemp(empty) == empty && empty[0] == '\0' && errno == EINVAL);
    errno = 0;
    CHECK(mktemp(five) == five && five[0] == '\0' && errno == EINVAL);
    errno = 0;
    CHECK(mktemp(infix) == infix && infix[0] == '\0' && errno == EINVAL);
    errno = 0;
    CHECK(mktemp(seven) == seven && strncmp(seven, "/work/legacy/tX", 15) == 0 &&
          strchr(seven + 15, 'X') == NULL && errno == ENOENT);
    errno = 0;
    CHECK(mktemp(not_directory) == not_directory && not_directory[0] == '\0' &&
          errno == ENOTDIR);
    errno = 0;
    CHECK(mktemp(missing_parent) == missing_parent &&
          strncmp(missing_parent, "/work/legacy/missing/", 21) == 0 &&
          strcmp(missing_parent + 21, "XXXXXX") != 0 && errno == ENOENT);

    /* Every candidate below a regular file resolves to ENOTDIR, so tempnam
     * exhausts its attempts without publishing an errno. */
    errno = E2BIG;
    CHECK(tempnam("/work/legacy/regular", "p") == NULL && errno == E2BIG);
    name = tempnam("/work/legacy", "");
    CHECK(name != NULL && strncmp(name, "/work/legacy/_", 14) == 0 && strlen(name) == 20);
    free(name);
    name = tempnam("", "p");
    CHECK(name != NULL && strncmp(name, "/p_", 3) == 0 && strlen(name) == 9);
    free(name);

    /* dir + '/' + pfx + '_' + six bytes: 4095 fits PATH_MAX, 4096 does not. */
    strcpy(boundary, "/work/legacy");
    directory_length = strlen(boundary);
    while (directory_length + 1 + 1 + 1 + 6 < PATH_MAX - 1) {
        memcpy(boundary + directory_length, "/.", 2);
        directory_length += 2;
    }
    if (directory_length + 1 + 1 + 1 + 6 != PATH_MAX - 1) {
        boundary[directory_length++] = '/';
    }
    boundary[directory_length] = '\0';
    CHECK(directory_length + 1 + 1 + 1 + 6 == PATH_MAX - 1);
    name = tempnam(boundary, "p");
    CHECK(name != NULL && strlen(name) == PATH_MAX - 1);
    free(name);
    boundary[directory_length] = '/';
    boundary[directory_length + 1] = '\0';
    errno = 0;
    CHECK(tempnam(boundary, "p") == NULL && errno == ENAMETOOLONG);

    /* The inherited lchmod path changes a regular file and reports absence. */
    CHECK(chmod("/work/legacy/regular", 0600) == 0);
    errno = E2BIG;
    CHECK(lchmod("/work/legacy/regular", 0640) == 0 && errno == E2BIG);
    CHECK(stat("/work/legacy/regular", &metadata) == 0 &&
          (metadata.st_mode & 07777) == 0640);
    CHECK_ERR(lchmod("/work/legacy/lchmod-missing", 0600), ENOENT);
    CHECK_ERR(lchmod("/work/legacy/regular/child", 0600), ENOTDIR);
    puts("legacy edges ok");
    return 0;
}

static int handle_edges_case(void)
{
    struct {
        struct file_handle header;
        unsigned char bytes[MAX_HANDLE_SZ];
    } storage;
    int mount_id = -7;
    int result;
    int result_errno;
    unsigned required;
    int descriptor;

    CHECK(ensure_directory("/work") == 0);
    CHECK(write_file("/work/handle-edges", "edges") == 0);

    /* A zero-capacity handle reports the required capacity with EOVERFLOW. */
    memset(&storage, 0, sizeof(storage));
    storage.header.handle_bytes = 0;
    errno = E2BIG;
    result = name_to_handle_at(AT_FDCWD, "/work/handle-edges", &storage.header, &mount_id, 0);
    result_errno = errno;
    required = storage.header.handle_bytes;
    printf("handle zero-capacity result=%d errno=%d sized=%d\n", result, result_errno,
           required > 0 && required <= MAX_HANDLE_SZ);

    memset(&storage, 0, sizeof(storage));
    storage.header.handle_bytes = MAX_HANDLE_SZ + 1;
    errno = E2BIG;
    result = name_to_handle_at(AT_FDCWD, "/work/handle-edges", &storage.header, &mount_id, 0);
    printf("handle oversized result=%d errno=%d\n", result, errno);

    memset(&storage, 0, sizeof(storage));
    storage.header.handle_bytes = MAX_HANDLE_SZ;
    errno = E2BIG;
    result = name_to_handle_at(AT_FDCWD, "/work/handle-edges", &storage.header, &mount_id,
                               0x40000000);
    printf("handle bad-flags result=%d errno=%d\n", result, errno);

    descriptor = open("/work/handle-edges", O_RDONLY);
    CHECK(descriptor >= 0);
    memset(&storage, 0, sizeof(storage));
    storage.header.handle_bytes = MAX_HANDLE_SZ;
    errno = E2BIG;
    result = name_to_handle_at(descriptor, "", &storage.header, &mount_id, AT_EMPTY_PATH);
    printf("handle empty-path result=%d errno=%d\n", result, errno);
    CHECK(close(descriptor) == 0);

    memset(&storage, 0, sizeof(storage));
    storage.header.handle_bytes = MAX_HANDLE_SZ + 1;
    errno = E2BIG;
    result = open_by_handle_at(AT_FDCWD, &storage.header, O_RDONLY);
    printf("handle open-oversized result=%d errno=%d\n", result, errno);
    return 0;
}

static int alias_edges_case(void)
{
    struct stat metadata;
    struct stat expected;
    int path_descriptor;

    CHECK(ensure_directory("/work") == 0);
    CHECK(write_file("/work/alias-edges", "alias edges") == 0);
    unlink("/work/alias-edges-link");
    CHECK(symlink("alias-edges", "/work/alias-edges-link") == 0);
    unlink("/work/alias-edges-loop");
    CHECK(symlink("alias-edges-loop", "/work/alias-edges-loop") == 0);
    CHECK(stat("/work/alias-edges", &expected) == 0);

    /* __xstat follows a final symlink; __lxstat reports the link itself. */
    CHECK(__xstat(1, "/work/alias-edges-link", &metadata) == 0 &&
          metadata.st_ino == expected.st_ino && metadata.st_size == 11);
    CHECK(__lxstat(1, "/work/alias-edges-link", &metadata) == 0 &&
          S_ISLNK(metadata.st_mode) && metadata.st_size == 11);
    CHECK_ERR(__xstat(1, "/work/alias-edges-loop", &metadata), ELOOP);
    CHECK(__lxstat(1, "/work/alias-edges-loop", &metadata) == 0 && S_ISLNK(metadata.st_mode));
    CHECK_ERR(__xstat(1, "", &metadata), ENOENT);
    CHECK_ERR(__lxstat(1, "/work/alias-edges/child", &metadata), ENOTDIR);

    /* O_PATH descriptors and AT_EMPTY_PATH reach the same inode. */
    path_descriptor = open("/work/alias-edges", O_PATH);
    CHECK(path_descriptor >= 0);
    CHECK(__fxstat(3, path_descriptor, &metadata) == 0 && metadata.st_ino == expected.st_ino);
    CHECK(__fxstatat(3, path_descriptor, "", &metadata, AT_EMPTY_PATH) == 0 &&
          metadata.st_ino == expected.st_ino);
    CHECK_ERR(__fxstatat(3, path_descriptor, "", &metadata, 0), ENOENT);
    CHECK_ERR(__fxstatat(3, path_descriptor, "x", &metadata, 0), ENOTDIR);
    CHECK(close(path_descriptor) == 0);
    CHECK_ERR(__fxstat(3, AT_FDCWD, &metadata), EBADF);
    CHECK(chdir("/work") == 0);
    CHECK(__fxstatat(3, AT_FDCWD, "alias-edges-link", &metadata, AT_SYMLINK_NOFOLLOW) == 0 &&
          S_ISLNK(metadata.st_mode));
    CHECK(chdir("/") == 0);
    puts("alias edges ok");
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
    if (strcmp(name, "comparators") == 0)
        return comparator_case();
    if (strcmp(name, "directory-edges") == 0)
        return directory_edges_case();
    if (strcmp(name, "directory-threads") == 0)
        return directory_threads_case();
    if (strcmp(name, "traversal-flags") == 0)
        return traversal_flags_case();
    if (strcmp(name, "traversal-permissions") == 0)
        return traversal_permissions_case();
    if (strcmp(name, "legacy-edges") == 0)
        return legacy_edges_case();
    if (strcmp(name, "handle-edges") == 0)
        return handle_edges_case();
    if (strcmp(name, "alias-edges") == 0)
        return alias_edges_case();
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
