/*
 * Pinned-musl/raw Linux/x86-64 directory-record reference.
 *
 * `DIR` and `struct dirent` are used here only as the pinned-musl oracle for
 * the private Rust getdents64 boundary. This fixture selects no crabc C
 * directory API, C errno/TLS contract, installed header, or public x86 ABI.
 */
#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(sizeof(size_t) == 8, "x86 size_t width");
_Static_assert(sizeof(off_t) == 8, "x86 off_t width");
_Static_assert(SYS_lseek == 8, "x86 lseek syscall number");
_Static_assert(SYS_getdents64 == 217, "x86 getdents64 syscall number");
_Static_assert(SYS_openat == 257, "x86 openat syscall number");
_Static_assert(AT_FDCWD == -100, "x86 current-directory token");
_Static_assert(O_DIRECTORY == 0x00010000, "x86 O_DIRECTORY value");
_Static_assert(O_CLOEXEC == 0x00080000, "x86 O_CLOEXEC value");

enum {
    LINUX_DIRENT64_HEADER_SIZE = 19,
    DIRECTORY_BUFFER_SIZE = 4096,
    MAX_ENTRY_NAME_SIZE = 255,
};

struct raw_summary {
    int saw_first;
    int saw_second;
    int saw_long;
    int have_cursor;
    int64_t cursor;
    char resume_name[MAX_ENTRY_NAME_SIZE + 1];
};

static int is_name(const unsigned char *name, size_t length, const char *wanted)
{
    size_t wanted_length = strlen(wanted);
    return length == wanted_length && memcmp(name, wanted, length) == 0;
}

static int copy_name(char destination[MAX_ENTRY_NAME_SIZE + 1],
                     const unsigned char *name, size_t length)
{
    if (length > MAX_ENTRY_NAME_SIZE) return 0;
    memcpy(destination, name, length);
    destination[length] = '\0';
    return 1;
}

/* Validates private Linux `linux_dirent64` framing without casting a record. */
static int summarize_raw_records(const unsigned char *buffer, size_t length,
                                 const char *long_name,
                                 struct raw_summary *summary)
{
    size_t offset = 0;
    int previous_valid = 0;
    int64_t previous_cookie = 0;

    memset(summary, 0, sizeof(*summary));
    while (offset < length) {
        const unsigned char *record = buffer + offset;
        const unsigned char *name;
        const unsigned char *terminator;
        uint16_t record_length;
        int64_t cookie;
        size_t name_length;

        if (length - offset < LINUX_DIRENT64_HEADER_SIZE) return 0;
        memcpy(&record_length, record + 16, sizeof(record_length));
        memcpy(&cookie, record + 8, sizeof(cookie));
        if (record_length <= LINUX_DIRENT64_HEADER_SIZE ||
            record_length > length - offset || record_length % 8 != 0) {
            return 0;
        }
        name = record + LINUX_DIRENT64_HEADER_SIZE;
        terminator = memchr(name, '\0', record_length - LINUX_DIRENT64_HEADER_SIZE);
        if (terminator == NULL) return 0;
        name_length = (size_t)(terminator - name);
        if (previous_valid && !summary->have_cursor) {
            summary->have_cursor = 1;
            summary->cursor = previous_cookie;
            if (!copy_name(summary->resume_name, name, name_length)) return 0;
        }
        if (is_name(name, name_length, "first")) summary->saw_first = 1;
        if (is_name(name, name_length, "second")) summary->saw_second = 1;
        if (is_name(name, name_length, long_name)) summary->saw_long = 1;
        previous_valid = 1;
        previous_cookie = cookie;
        offset += record_length;
    }
    return offset == length && previous_valid;
}

static int raw_getdents(int fd, unsigned char buffer[DIRECTORY_BUFFER_SIZE],
                        const char *long_name, struct raw_summary *summary)
{
    long result = syscall(SYS_getdents64, fd, buffer, DIRECTORY_BUFFER_SIZE);
    return result > 0 && summarize_raw_records(buffer, (size_t)result, long_name, summary);
}

static int raw_has_name(int fd, unsigned char buffer[DIRECTORY_BUFFER_SIZE],
                        const char *long_name, const char *wanted)
{
    struct raw_summary summary;
    size_t offset;
    long result = syscall(SYS_getdents64, fd, buffer, DIRECTORY_BUFFER_SIZE);

    if (result <= 0 || !summarize_raw_records(buffer, (size_t)result, long_name, &summary)) {
        return 0;
    }
    if (strcmp(wanted, "first") == 0) return summary.saw_first;
    if (strcmp(wanted, "second") == 0) return summary.saw_second;
    if (strcmp(wanted, long_name) == 0) return summary.saw_long;
    for (offset = 0; offset < (size_t)result;) {
        const unsigned char *record = buffer + offset;
        const unsigned char *name = record + LINUX_DIRENT64_HEADER_SIZE;
        const unsigned char *terminator;
        uint16_t record_length;

        memcpy(&record_length, record + 16, sizeof(record_length));
        terminator = memchr(name, '\0', record_length - LINUX_DIRENT64_HEADER_SIZE);
        if (terminator == NULL) return 0;
        if (is_name(name, (size_t)(terminator - name), wanted)) return 1;
        offset += record_length;
    }
    return 0;
}

static int musl_directory_oracle(const char *root, const char *long_name)
{
    DIR *directory = NULL;
    DIR *transferred = NULL;
    struct dirent *entry;
    char expected_after_cursor[MAX_ENTRY_NAME_SIZE + 1];
    int transferred_fd = -1;
    int saw_first = 0;
    int saw_second = 0;
    int saw_long = 0;
    long cursor;
    int result = 0;

    directory = opendir(root);
    if (directory == NULL || dirfd(directory) < 0) {
        result = 1;
        goto cleanup;
    }
    entry = readdir(directory);
    if (entry == NULL) {
        result = 2;
        goto cleanup;
    }
    cursor = telldir(directory);
    if (cursor < 0) {
        result = 3;
        goto cleanup;
    }
    entry = readdir(directory);
    if (entry == NULL || strlen(entry->d_name) > MAX_ENTRY_NAME_SIZE ||
        !copy_name(expected_after_cursor, (const unsigned char *)entry->d_name,
                   strlen(entry->d_name))) {
        result = 4;
        goto cleanup;
    }
    seekdir(directory, cursor);
    entry = readdir(directory);
    if (entry == NULL || strcmp(entry->d_name, expected_after_cursor) != 0) {
        result = 5;
        goto cleanup;
    }
    rewinddir(directory);
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "first") == 0) saw_first = 1;
        if (strcmp(entry->d_name, "second") == 0) saw_second = 1;
        if (strcmp(entry->d_name, long_name) == 0) saw_long = 1;
    }
    if (errno != 0 || !saw_first || !saw_second || !saw_long) {
        result = 6;
        goto cleanup;
    }
    if (closedir(directory) != 0) {
        directory = NULL;
        result = 7;
        goto cleanup;
    }
    directory = NULL;

    transferred_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (transferred_fd < 0 || (transferred = fdopendir(transferred_fd)) == NULL) {
        result = 8;
        goto cleanup;
    }
    if (dirfd(transferred) != transferred_fd || readdir(transferred) == NULL) {
        result = 9;
        goto cleanup;
    }
    if (closedir(transferred) != 0) {
        transferred = NULL;
        result = 10;
        goto cleanup;
    }
    transferred = NULL;
    transferred_fd = -1;

cleanup:
    if (transferred != NULL && closedir(transferred) != 0 && result == 0) result = 11;
    if (directory != NULL && closedir(directory) != 0 && result == 0) result = 12;
    if (transferred != NULL) transferred_fd = -1;
    if (transferred_fd >= 0 && close(transferred_fd) != 0 && result == 0) result = 13;
    return result == 0;
}

int main(void)
{
    char template[] = "/tmp/crabc-x86-directory-XXXXXX";
    char long_name[MAX_ENTRY_NAME_SIZE + 1];
    unsigned char buffer[DIRECTORY_BUFFER_SIZE];
    struct raw_summary summary;
    int root_fd = -1;
    int file_fd = -1;
    int raw_fd = -1;
    int small_fd = -1;
    int status = 0;
    long result;

    memset(long_name, 'n', MAX_ENTRY_NAME_SIZE);
    long_name[MAX_ENTRY_NAME_SIZE] = '\0';
    if (mkdtemp(template) == NULL) return 2;
    root_fd = open(template, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) {
        status = 3;
        goto cleanup;
    }
    for (const char *name = "first"; name != NULL; name = NULL) {
        file_fd = openat(root_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (file_fd < 0 || close(file_fd) != 0) {
            file_fd = -1;
            status = 4;
            goto cleanup;
        }
        file_fd = -1;
    }
    for (const char *name = "second"; name != NULL; name = NULL) {
        file_fd = openat(root_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (file_fd < 0 || close(file_fd) != 0) {
            file_fd = -1;
            status = 5;
            goto cleanup;
        }
        file_fd = -1;
    }
    file_fd = openat(root_fd, long_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (file_fd < 0 || close(file_fd) != 0) {
        file_fd = -1;
        status = 6;
        goto cleanup;
    }
    file_fd = -1;

    if (!musl_directory_oracle(template, long_name)) {
        status = 7;
        goto cleanup;
    }
    file_fd = openat(root_fd, "first", O_RDONLY | O_CLOEXEC);
    if (file_fd < 0) {
        status = 8;
        goto cleanup;
    }
    errno = 0;
    result = syscall(SYS_getdents64, file_fd, buffer, sizeof(buffer));
    if (result != -1 || errno != ENOTDIR) {
        status = 9;
        goto cleanup;
    }
    if (close(file_fd) != 0) {
        file_fd = -1;
        status = 10;
        goto cleanup;
    }
    file_fd = -1;

    small_fd = (int)syscall(SYS_openat, AT_FDCWD, template,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (small_fd < 0) {
        status = 11;
        goto cleanup;
    }
    errno = 0;
    result = syscall(SYS_getdents64, small_fd, buffer, 1);
    if (result != -1 || errno != EINVAL) {
        status = 12;
        goto cleanup;
    }
    if (close(small_fd) != 0) {
        small_fd = -1;
        status = 13;
        goto cleanup;
    }
    small_fd = -1;

    raw_fd = (int)syscall(SYS_openat, AT_FDCWD, template,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (raw_fd < 0 || !raw_getdents(raw_fd, buffer, long_name, &summary) ||
        !summary.saw_first || !summary.saw_second || !summary.saw_long ||
        !summary.have_cursor) {
        status = 14;
        goto cleanup;
    }
    if (syscall(SYS_lseek, raw_fd, summary.cursor, SEEK_SET) < 0 ||
        !raw_has_name(raw_fd, buffer, long_name, summary.resume_name)) {
        status = 15;
        goto cleanup;
    }
    if (syscall(SYS_lseek, raw_fd, 0, SEEK_SET) < 0 ||
        !raw_getdents(raw_fd, buffer, long_name, &summary) || !summary.saw_first ||
        !summary.saw_second || !summary.saw_long) {
        status = 16;
        goto cleanup;
    }

cleanup:
    if (raw_fd >= 0 && close(raw_fd) != 0 && status == 0) status = 17;
    if (small_fd >= 0 && close(small_fd) != 0 && status == 0) status = 18;
    if (file_fd >= 0 && close(file_fd) != 0 && status == 0) status = 19;
    if (root_fd >= 0) {
        if (unlinkat(root_fd, long_name, 0) != 0 && errno != ENOENT && status == 0) status = 20;
        if (unlinkat(root_fd, "second", 0) != 0 && errno != ENOENT && status == 0) status = 21;
        if (unlinkat(root_fd, "first", 0) != 0 && errno != ENOENT && status == 0) status = 22;
        if (close(root_fd) != 0 && status == 0) status = 23;
    }
    if (rmdir(template) != 0 && status == 0) status = 24;
    if (status != 0) return status;
    puts("syscalls=getdents64:217,lseek:8,openat:257 linux_dirent64=ino:u64@0,off:i64@8,reclen:u16@16,type:u8@18,name@19 raw=framing:small-buffer:cursor:rewind:enotdir musl=opendir:fdopendir:dirfd:readdir:telldir:seekdir:rewinddir c-api-selection=excluded");
    return 0;
}
