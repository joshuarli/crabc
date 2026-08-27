/* Pinned-musl Linux/x86-64 readlinkat(2) behavior reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires little-endian x86-64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

struct guarded_buffer {
    unsigned char value[64];
    unsigned char trailing[16];
};

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer size");
_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t size");
_Static_assert(sizeof(ssize_t) == 8, "x86 LP64 ssize_t size");
_Static_assert(SYS_readlinkat == 267, "x86 readlinkat syscall number");

static long direct_readlinkat(int dirfd, const char *path, char *buffer,
                              size_t length)
{
    return syscall(SYS_readlinkat, dirfd, path, buffer, length);
}

static int buffer_is_unchanged(const struct guarded_buffer *buffer)
{
    size_t index;

    for (index = 0; index < sizeof(buffer->value); ++index) {
        if (buffer->value[index] != 0xa5)
            return 0;
    }
    for (index = 0; index < sizeof(buffer->trailing); ++index) {
        if (buffer->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int unwritten_suffix_is_unchanged(const struct guarded_buffer *buffer,
                                         size_t length)
{
    if (length > sizeof(buffer->value))
        return 0;
    for (size_t index = length; index < sizeof(buffer->value); ++index) {
        if (buffer->value[index] != 0xa5)
            return 0;
    }
    for (size_t index = 0; index < sizeof(buffer->trailing); ++index) {
        if (buffer->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int returned_prefix_is_exact(const struct guarded_buffer *buffer,
                                    const unsigned char *expected,
                                    size_t length)
{
    return length <= sizeof(buffer->value) &&
           memcmp(buffer->value, expected, length) == 0 &&
           memchr(buffer->value, '\0', length) == NULL;
}

int main(void)
{
    static const unsigned char target[] = "target-value";
    static const char short_target[] = "tar";
    char template[] = "/tmp/crabc-x86-readlinkat-XXXXXX";
    char *root = mkdtemp(template);
    struct guarded_buffer musl_full;
    struct guarded_buffer direct_full;
    struct guarded_buffer musl_short;
    struct guarded_buffer direct_short;
    struct guarded_buffer musl_zero;
    struct guarded_buffer direct_zero;
    struct guarded_buffer musl_missing;
    struct guarded_buffer direct_missing;
    struct guarded_buffer musl_regular;
    struct guarded_buffer direct_regular;
    int dirfd = -1;
    int regular_fd = -1;
    ssize_t musl_length;
    long direct_length;
    int status = 0;

    if (root == NULL)
        return 2;
    dirfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        status = 3;
        goto cleanup;
    }
    regular_fd = openat(dirfd, "regular", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
                        0600);
    if (regular_fd < 0 || close(regular_fd) != 0) {
        status = 4;
        goto cleanup;
    }
    regular_fd = -1;
    if (symlinkat((const char *)target, dirfd, "link") != 0) {
        status = 5;
        goto cleanup;
    }

    memset(&musl_full, 0xa5, sizeof(musl_full));
    errno = 0;
    musl_length = readlinkat(dirfd, "link", (char *)musl_full.value,
                             sizeof(musl_full.value));
    if (musl_length != (ssize_t)(sizeof(target) - 1) ||
        !returned_prefix_is_exact(&musl_full, target, sizeof(target) - 1) ||
        !unwritten_suffix_is_unchanged(&musl_full, sizeof(target) - 1)) {
        status = 10;
        goto cleanup;
    }

    memset(&direct_full, 0xa5, sizeof(direct_full));
    errno = 0;
    direct_length = direct_readlinkat(dirfd, "link", (char *)direct_full.value,
                                      sizeof(direct_full.value));
    if (direct_length != musl_length ||
        !returned_prefix_is_exact(&direct_full, target, sizeof(target) - 1) ||
        !unwritten_suffix_is_unchanged(&direct_full, sizeof(target) - 1) ||
        memcmp(&musl_full, &direct_full, sizeof(musl_full)) != 0) {
        status = 11;
        goto cleanup;
    }

    memset(&musl_short, 0xa5, sizeof(musl_short));
    errno = 0;
    musl_length = readlinkat(dirfd, "link", (char *)musl_short.value, 3);
    if (musl_length != 3 ||
        !returned_prefix_is_exact(&musl_short, (const unsigned char *)short_target, 3) ||
        !unwritten_suffix_is_unchanged(&musl_short, 3)) {
        status = 12;
        goto cleanup;
    }

    memset(&direct_short, 0xa5, sizeof(direct_short));
    errno = 0;
    direct_length = direct_readlinkat(dirfd, "link", (char *)direct_short.value, 3);
    if (direct_length != musl_length ||
        !returned_prefix_is_exact(&direct_short, (const unsigned char *)short_target, 3) ||
        !unwritten_suffix_is_unchanged(&direct_short, 3) ||
        memcmp(&musl_short, &direct_short, sizeof(musl_short)) != 0) {
        status = 13;
        goto cleanup;
    }

    memset(&musl_zero, 0xa5, sizeof(musl_zero));
    errno = 0;
    musl_length = readlinkat(dirfd, "link", (char *)musl_zero.value, 0);
    if (musl_length != 0 || !buffer_is_unchanged(&musl_zero)) {
        status = 20;
        goto cleanup;
    }

    memset(&direct_zero, 0xa5, sizeof(direct_zero));
    errno = 0;
    direct_length = direct_readlinkat(dirfd, "link", (char *)direct_zero.value, 0);
    if (direct_length != -1 || errno != EINVAL ||
        !buffer_is_unchanged(&direct_zero)) {
        status = 21;
        goto cleanup;
    }

    memset(&musl_missing, 0xa5, sizeof(musl_missing));
    errno = 0;
    if (readlinkat(dirfd, "missing", (char *)musl_missing.value,
                   sizeof(musl_missing.value)) != -1 || errno != ENOENT ||
        !buffer_is_unchanged(&musl_missing)) {
        status = 30;
        goto cleanup;
    }

    memset(&direct_missing, 0xa5, sizeof(direct_missing));
    errno = 0;
    if (direct_readlinkat(dirfd, "missing", (char *)direct_missing.value,
                          sizeof(direct_missing.value)) != -1 || errno != ENOENT ||
        !buffer_is_unchanged(&direct_missing)) {
        status = 31;
        goto cleanup;
    }

    memset(&musl_regular, 0xa5, sizeof(musl_regular));
    errno = 0;
    if (readlinkat(dirfd, "regular", (char *)musl_regular.value,
                   sizeof(musl_regular.value)) != -1 || errno != EINVAL ||
        !buffer_is_unchanged(&musl_regular)) {
        status = 40;
        goto cleanup;
    }

    memset(&direct_regular, 0xa5, sizeof(direct_regular));
    errno = 0;
    if (direct_readlinkat(dirfd, "regular", (char *)direct_regular.value,
                          sizeof(direct_regular.value)) != -1 || errno != EINVAL ||
        !buffer_is_unchanged(&direct_regular)) {
        status = 41;
        goto cleanup;
    }

cleanup:
    if (regular_fd >= 0 && close(regular_fd) != 0 && status == 0)
        status = 50;
    if (dirfd >= 0) {
        if (unlinkat(dirfd, "link", 0) != 0 && errno != ENOENT && status == 0)
            status = 51;
        if (unlinkat(dirfd, "regular", 0) != 0 && errno != ENOENT && status == 0)
            status = 52;
        if (close(dirfd) != 0 && status == 0)
            status = 53;
    }
    if (rmdir(root) != 0 && errno != ENOENT && status == 0)
        status = 54;
    if (status != 0)
        return status;
    puts("syscall=267 full=exact-no-nul short=truncated zero=musl-empty/raw-EINVAL missing=ENOENT regular=EINVAL");
    return 0;
}
