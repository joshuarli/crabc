/* Native Linux/x86-64 static directory-stream C ABI fixture.
 *
 * One project-header C body first runs through pinned musl 1.2.6 and then
 * through the selected freestanding crabc archive. It specifies a bounded
 * `DIR`/`dirent` slice: stream ownership, close-on-exec transfer, validated
 * readdir cursor/rewind behavior, readdir_r copying, C-locale alphasort, and
 * raw getdents/posix_getdents framing and errno behavior. It deliberately
 * does not select scandir, versionsort, C allocation, stdio, loader, CRT,
 * sysroot, family completion, promotion, or public x86 support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

enum {
    CRABC_DIRECTORY_BUFFER_SIZE = 4096,
    CRABC_DIRECTORY_NAME_MAX = 255,
    CRABC_LINUX_DIRENT64_HEADER_SIZE = 19,
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct dirent) == 280 && _Alignof(struct dirent) == 8 &&
    offsetof(struct dirent, d_ino) == 0 && offsetof(struct dirent, d_off) == 8 &&
    offsetof(struct dirent, d_reclen) == 16 && offsetof(struct dirent, d_type) == 18 &&
    offsetof(struct dirent, d_name) == 19,
    "x86 dirent ABI");
_Static_assert(SYS_fstat == 5 && SYS_lseek == 8 && SYS_mmap == 9 &&
    SYS_munmap == 11 && SYS_fcntl == 72 && SYS_getdents64 == 217 &&
    SYS_openat == 257,
    "x86 selected directory syscall numbers");
_Static_assert(O_DIRECTORY == 0x00010000 && O_CLOEXEC == 0x00080000 &&
    O_PATH == 0x00200000 && F_GETFD == 1 && FD_CLOEXEC == 1,
    "x86 directory descriptor flags");
_Static_assert(CRABC_TYPE_IS(__typeof__(&opendir), DIR *(*)(const char *)) &&
    CRABC_TYPE_IS(__typeof__(&fdopendir), DIR *(*)(int)) &&
    CRABC_TYPE_IS(__typeof__(&closedir), int (*)(DIR *)) &&
    CRABC_TYPE_IS(__typeof__(&dirfd), int (*)(DIR *)) &&
    CRABC_TYPE_IS(__typeof__(&readdir), struct dirent *(*)(DIR *)) &&
    CRABC_TYPE_IS(__typeof__(&readdir_r),
        int (*)(DIR *, struct dirent *, struct dirent **)) &&
    CRABC_TYPE_IS(__typeof__(&rewinddir), void (*)(DIR *)) &&
    CRABC_TYPE_IS(__typeof__(&seekdir), void (*)(DIR *, long)) &&
    CRABC_TYPE_IS(__typeof__(&telldir), long (*)(DIR *)) &&
    CRABC_TYPE_IS(__typeof__(&alphasort),
        int (*)(const struct dirent **, const struct dirent **)) &&
    CRABC_TYPE_IS(__typeof__(&getdents), int (*)(int, struct dirent *, size_t)) &&
    CRABC_TYPE_IS(__typeof__(&posix_getdents),
        ssize_t (*)(int, void *, size_t, int)),
    "selected directory declarations");

static int expect_error(int result, int error)
{
    return result == -1 && errno == error;
}

static int expect_ssize_error(ssize_t result, int error)
{
    return result == -1 && errno == error;
}

static size_t string_length(const char *string)
{
    size_t length = 0;

    while (string[length] != '\0') ++length;
    return length;
}

static int strings_equal(const char *left, const char *right)
{
    size_t index = 0;

    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int name_matches(const char *name, size_t name_limit, const char *wanted)
{
    size_t index = 0;

    while (index < name_limit && name[index] != '\0' && wanted[index] != '\0') {
        if (name[index] != wanted[index]) return 0;
        ++index;
    }
    return index < name_limit && name[index] == '\0' && wanted[index] == '\0';
}

static int copy_name(char destination[CRABC_DIRECTORY_NAME_MAX + 1],
    const char *source)
{
    size_t index;

    for (index = 0; index < CRABC_DIRECTORY_NAME_MAX; ++index) {
        destination[index] = source[index];
        if (source[index] == '\0') return 1;
    }
    destination[CRABC_DIRECTORY_NAME_MAX] = '\0';
    return source[CRABC_DIRECTORY_NAME_MAX] == '\0';
}

static void make_long_name(char name[CRABC_DIRECTORY_NAME_MAX + 1])
{
    size_t index;

    for (index = 0; index < CRABC_DIRECTORY_NAME_MAX; ++index) name[index] = 'n';
    name[CRABC_DIRECTORY_NAME_MAX] = '\0';
}

static void make_long_path(char path[sizeof("directory/") + CRABC_DIRECTORY_NAME_MAX],
    const char name[CRABC_DIRECTORY_NAME_MAX + 1])
{
    size_t index;

    for (index = 0; index < sizeof("directory/") - 1; ++index) path[index] = "directory/"[index];
    for (index = 0; index <= CRABC_DIRECTORY_NAME_MAX; ++index) {
        path[sizeof("directory/") - 1 + index] = name[index];
    }
}

static int create_file(const char *path)
{
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    if (descriptor < 0) return 0;
    return close(descriptor) == 0;
}

static int check_readdir_stream(const char *long_name)
{
    DIR *directory = NULL;
    struct dirent *entry;
    char expected_after_cookie[CRABC_DIRECTORY_NAME_MAX + 1];
    int saw_alpha = 0;
    int saw_beta = 0;
    int saw_long = 0;
    long cookie;
    int status = 0;

    directory = opendir("directory");
    if (directory == NULL || dirfd(directory) < 0 ||
        (fcntl(dirfd(directory), F_GETFD) & FD_CLOEXEC) == 0) {
        status = 1;
        goto cleanup;
    }
    entry = readdir(directory);
    if (entry == NULL) {
        status = 2;
        goto cleanup;
    }
    cookie = telldir(directory);
    if (cookie < 0) {
        status = 3;
        goto cleanup;
    }
    entry = readdir(directory);
    if (entry == NULL || !copy_name(expected_after_cookie, entry->d_name)) {
        status = 4;
        goto cleanup;
    }
    seekdir(directory, cookie);
    entry = readdir(directory);
    if (entry == NULL || !strings_equal(entry->d_name, expected_after_cookie)) {
        status = 5;
        goto cleanup;
    }
    rewinddir(directory);
    errno = E2BIG;
    while ((entry = readdir(directory)) != NULL) {
        if (strings_equal(entry->d_name, "alpha")) saw_alpha = 1;
        if (strings_equal(entry->d_name, "beta")) saw_beta = 1;
        if (strings_equal(entry->d_name, long_name)) saw_long = 1;
    }
    if (errno != E2BIG || !saw_alpha || !saw_beta || !saw_long) {
        status = 6;
        goto cleanup;
    }

cleanup:
    if (directory != NULL && closedir(directory) != 0 && status == 0) status = 7;
    return status;
}

static int check_readdir_r(const char *long_name)
{
    DIR *directory = NULL;
    struct dirent copied;
    struct dirent *result = NULL;
    int saw_long = 0;
    int status = 0;

    directory = opendir("directory");
    if (directory == NULL) {
        status = 1;
        goto cleanup;
    }
    errno = E2BIG;
    for (;;) {
        int result_code = readdir_r(directory, &copied, &result);

        if (result_code != 0) {
            status = 2;
            goto cleanup;
        }
        if (result == NULL) break;
        if (strings_equal(result->d_name, long_name)) saw_long = 1;
    }
    if (errno != E2BIG || !saw_long) status = 3;

cleanup:
    if (directory != NULL && closedir(directory) != 0 && status == 0) status = 4;
    return status;
}

static int check_fdopendir(void)
{
    DIR *directory = NULL;
    int descriptor = -1;
    int status = 0;

    descriptor = open("directory", O_RDONLY | O_DIRECTORY);
    if (descriptor < 0 || (fcntl(descriptor, F_GETFD) & FD_CLOEXEC) != 0) {
        status = 1;
        goto cleanup;
    }
    directory = fdopendir(descriptor);
    if (directory == NULL || dirfd(directory) != descriptor ||
        (fcntl(descriptor, F_GETFD) & FD_CLOEXEC) == 0 || readdir(directory) == NULL) {
        status = 2;
        goto cleanup;
    }
    if (closedir(directory) != 0) {
        directory = NULL;
        status = 3;
        goto cleanup;
    }
    directory = NULL;
    descriptor = -1;

    descriptor = open("directory/alpha", O_RDONLY | O_CLOEXEC);
    errno = 0;
    if (descriptor < 0 || fdopendir(descriptor) != NULL || errno != ENOTDIR) {
        status = 4;
        goto cleanup;
    }
    if (close(descriptor) != 0) {
        descriptor = -1;
        status = 5;
        goto cleanup;
    }
    descriptor = -1;

    descriptor = open("directory", O_PATH | O_CLOEXEC);
    errno = 0;
    if (descriptor < 0 || fdopendir(descriptor) != NULL || errno != EBADF) {
        status = 6;
        goto cleanup;
    }

cleanup:
    if (directory != NULL && closedir(directory) != 0 && status == 0) status = 7;
    if (descriptor >= 0 && close(descriptor) != 0 && status == 0) status = 8;
    return status;
}

static int scan_raw_records(const unsigned char *buffer, size_t length,
    const char *long_name)
{
    size_t offset = 0;
    int saw_alpha = 0;
    int saw_beta = 0;
    int saw_long = 0;

    while (offset < length) {
        const struct dirent *entry;
        size_t name_limit;
        size_t name_length;
        size_t index;

        if (length - offset < CRABC_LINUX_DIRENT64_HEADER_SIZE || offset % 8 != 0)
            return 0;
        entry = (const struct dirent *)(const void *)(buffer + offset);
        if (entry->d_reclen < CRABC_LINUX_DIRENT64_HEADER_SIZE ||
            entry->d_reclen > length - offset || entry->d_reclen % 8 != 0)
            return 0;
        name_limit = entry->d_reclen - CRABC_LINUX_DIRENT64_HEADER_SIZE;
        for (name_length = 0; name_length < name_limit; ++name_length) {
            if (entry->d_name[name_length] == '\0') break;
        }
        if (name_length == name_limit || name_length > CRABC_DIRECTORY_NAME_MAX)
            return 0;
        if (name_matches(entry->d_name, name_limit, "alpha")) saw_alpha = 1;
        if (name_matches(entry->d_name, name_limit, "beta")) saw_beta = 1;
        if (name_matches(entry->d_name, name_limit, long_name)) saw_long = 1;
        for (index = 0; index < name_length; ++index) {
            if (entry->d_name[index] == '\0') return 0;
        }
        offset += entry->d_reclen;
    }
    return offset == length && saw_alpha && saw_beta && saw_long;
}

static int check_getdents(const char *long_name)
{
    struct dirent records[CRABC_DIRECTORY_BUFFER_SIZE / sizeof(struct dirent) + 1];
    int descriptor = -1;
    int result;
    int status = 0;

    descriptor = open("directory", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    errno = 0;
    if (descriptor < 0 || !expect_error(getdents(descriptor, records, 1), EINVAL)) {
        status = 1;
        goto cleanup;
    }
    if (close(descriptor) != 0) {
        descriptor = -1;
        status = 2;
        goto cleanup;
    }
    descriptor = open("directory", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    result = getdents(descriptor, records, sizeof(records));
    if (descriptor < 0 || result <= 0 ||
        !scan_raw_records((const unsigned char *)(const void *)records,
            (size_t)result, long_name)) {
        status = 3;
        goto cleanup;
    }
    if (close(descriptor) != 0) {
        descriptor = -1;
        status = 4;
        goto cleanup;
    }
    descriptor = open("directory", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    errno = 0;
    if (descriptor < 0 || !expect_ssize_error(
            posix_getdents(descriptor, records, sizeof(records), 1), EOPNOTSUPP)) {
        status = 5;
        goto cleanup;
    }
    result = (int)posix_getdents(descriptor, records, sizeof(records), 0);
    if (result <= 0 || !scan_raw_records((const unsigned char *)(const void *)records,
            (size_t)result, long_name)) {
        status = 6;
        goto cleanup;
    }

cleanup:
    if (descriptor >= 0 && close(descriptor) != 0 && status == 0) status = 7;
    return status;
}

static int check_alphasort(void)
{
    struct dirent alpha;
    struct dirent beta;
    const struct dirent *left = &alpha;
    const struct dirent *right = &beta;

    alpha.d_name[0] = 'a';
    alpha.d_name[1] = 'l';
    alpha.d_name[2] = 'p';
    alpha.d_name[3] = 'h';
    alpha.d_name[4] = 'a';
    alpha.d_name[5] = '\0';
    beta.d_name[0] = 'b';
    beta.d_name[1] = 'e';
    beta.d_name[2] = 't';
    beta.d_name[3] = 'a';
    beta.d_name[4] = '\0';
    return alphasort(&left, &right) < 0 && alphasort(&right, &left) > 0 &&
        alphasort(&left, &left) == 0;
}

int crabc_x86_64_directory_streams_probe(void)
{
    char long_name[CRABC_DIRECTORY_NAME_MAX + 1];
    char long_path[sizeof("directory/") + CRABC_DIRECTORY_NAME_MAX];
    int status = 0;

    make_long_name(long_name);
    make_long_path(long_path, long_name);
    if (mkdir("directory", 0700) != 0) {
        status = 1;
        goto cleanup;
    }
    if (!create_file("directory/alpha") || !create_file("directory/beta") ||
        !create_file(long_path)) {
        status = 2;
        goto cleanup;
    }
    if ((status = check_readdir_stream(long_name)) != 0) {
        status += 10;
        goto cleanup;
    }
    if ((status = check_readdir_r(long_name)) != 0) {
        status += 20;
        goto cleanup;
    }
    if ((status = check_fdopendir()) != 0) {
        status += 30;
        goto cleanup;
    }
    if ((status = check_getdents(long_name)) != 0) {
        status += 40;
        goto cleanup;
    }
    if (!check_alphasort()) {
        status = 51;
        goto cleanup;
    }

cleanup:
    if (unlink(long_path) != 0 && errno != ENOENT && status == 0) status = 60;
    if (unlink("directory/beta") != 0 && errno != ENOENT && status == 0) status = 61;
    if (unlink("directory/alpha") != 0 && errno != ENOENT && status == 0) status = 62;
    if (rmdir("directory") != 0 && errno != ENOENT && status == 0) status = 63;
    return status;
}

#ifndef CRABC_DIRECTORY_STREAMS_FREESTANDING
int main(void)
{
    return crabc_x86_64_directory_streams_probe();
}
#endif
