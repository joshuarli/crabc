/* Pinned-musl Linux/x86-64 fcntl status-flags behavior reference. */

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
#include <unistd.h>

_Static_assert(SYS_fcntl == 72, "x86 fcntl syscall number");
_Static_assert(F_GETFD == 1 && F_SETFD == 2 && FD_CLOEXEC == 1,
               "x86 descriptor flag commands and value");
_Static_assert(F_GETFL == 3, "F_GETFL command");
_Static_assert(F_SETFL == 4, "F_SETFL command");
_Static_assert(O_RDONLY == 0 && O_WRONLY == 1 && O_RDWR == 2,
               "fcntl access mode values");
_Static_assert(O_ACCMODE == 0x00200003,
               "x86 fcntl access mode mask");
_Static_assert(O_APPEND == 0x00000400 && O_NONBLOCK == 0x00000800,
               "x86 mutable status flag values");
_Static_assert(O_CREAT == 0x00000040 && O_EXCL == 0x00000080 &&
               O_TRUNC == 0x00000200 && O_CLOEXEC == 0x00080000,
               "x86 creation and descriptor flag values");
_Static_assert(O_ASYNC == 0x00002000 && O_DIRECT == 0x00004000 &&
               O_NOATIME == 0x00040000 && O_SYNC == 0x00101000,
               "x86 additional status flag values");

struct result {
    int value;
    int error;
};

static struct result libc_getfl(int fd)
{
    struct result result;

    errno = 0;
    result.value = fcntl(fd, F_GETFL);
    result.error = errno;
    return result;
}

static struct result raw_getfl(int fd)
{
    struct result result;

    errno = 0;
    result.value = (int)syscall(SYS_fcntl, fd, F_GETFL, 0L);
    result.error = errno;
    return result;
}

static struct result libc_setfl(int fd, int flags)
{
    struct result result;

    errno = 0;
    result.value = fcntl(fd, F_SETFL, flags);
    result.error = errno;
    return result;
}

static struct result raw_setfl(int fd, int flags)
{
    struct result result;

    errno = 0;
    result.value = (int)syscall(SYS_fcntl, fd, F_SETFL, flags);
    result.error = errno;
    return result;
}

static struct result libc_getfd(int fd)
{
    struct result result;

    errno = 0;
    result.value = fcntl(fd, F_GETFD);
    result.error = errno;
    return result;
}

static struct result raw_getfd(int fd)
{
    struct result result;

    errno = 0;
    result.value = (int)syscall(SYS_fcntl, fd, F_GETFD, 0L);
    result.error = errno;
    return result;
}

static struct result libc_setfd(int fd, int flags)
{
    struct result result;

    errno = 0;
    result.value = fcntl(fd, F_SETFD, flags);
    result.error = errno;
    return result;
}

static int same_result(struct result left, struct result right, int value,
                       int error)
{
    if (left.value != value || right.value != value ||
        left.value != right.value)
        return 0;
    if (value < 0 &&
        (left.error != error || right.error != error ||
         left.error != right.error))
        return 0;
    return 1;
}

static int has_result(struct result result, int value, int error)
{
    if (result.value != value)
        return 0;
    if (value < 0 && result.error != error)
        return 0;
    return 1;
}

int main(void)
{
    char template[] = "/tmp/crabc-x86-fcntl-status-XXXXXX";
    int fd = -1;
    int duplicate = -1;
    int original;
    int requested;
    int changed;
    int status = 0;
    struct result libc_result;
    struct result raw_result;

    fd = mkstemp(template);
    if (fd < 0)
        return 2;
    if (unlink(template) != 0) {
        status = 3;
        goto cleanup;
    }

    /* F_GETFL reports access/status state, not the creation-time O_* bits. */
    libc_result = libc_getfl(fd);
    raw_result = raw_getfl(fd);
    if (!same_result(libc_result, raw_result, libc_result.value, 0)) {
        status = 10;
        goto cleanup;
    }
    original = libc_result.value;
    if ((original & O_ACCMODE) != O_RDWR ||
        (original & (O_CREAT | O_EXCL | O_TRUNC)) != 0) {
        status = 11;
        goto cleanup;
    }

    duplicate = dup(fd);
    if (duplicate < 0) {
        status = 12;
        goto cleanup;
    }

    /* FD_CLOEXEC is descriptor-local and must survive F_SETFL on its alias. */
    if (!has_result(libc_setfd(duplicate, FD_CLOEXEC), 0, 0)) {
        status = 13;
        goto cleanup;
    }
    if (!same_result(libc_getfd(fd), raw_getfd(fd), 0, 0) ||
        !same_result(libc_getfd(duplicate), raw_getfd(duplicate),
                     FD_CLOEXEC, 0)) {
        status = 14;
        goto cleanup;
    }

    /* F_SETFL changes the open file description; a dup sees the change. */
    /* Ask for O_WRONLY too: F_SETFL must retain the original O_RDWR mode. */
    requested = (original & ~O_ACCMODE) | O_WRONLY | O_APPEND | O_NONBLOCK |
                O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC;
    changed = original | O_APPEND | O_NONBLOCK;

    /* A musl call must mutate the state that raw F_GETFL observes. */
    if (!has_result(libc_setfl(duplicate, requested), 0, 0)) {
        status = 15;
        goto cleanup;
    }
    if (!same_result(libc_getfl(fd), raw_getfl(fd), changed, 0) ||
        !same_result(libc_getfl(duplicate), raw_getfl(duplicate), changed, 0) ||
        (changed & O_ACCMODE) != O_RDWR ||
        !same_result(libc_getfd(fd), raw_getfd(fd), 0, 0) ||
        !same_result(libc_getfd(duplicate), raw_getfd(duplicate),
                     FD_CLOEXEC, 0)) {
        status = 16;
        goto cleanup;
    }

    /* A raw call must restore the state that musl F_GETFL observes. */
    if (!has_result(raw_setfl(fd, original), 0, 0)) {
        status = 17;
        goto cleanup;
    }
    if (!same_result(libc_getfl(fd), raw_getfl(fd), original, 0) ||
        !same_result(libc_getfl(duplicate), raw_getfl(duplicate), original, 0) ||
        !same_result(libc_getfd(fd), raw_getfd(fd), 0, 0) ||
        !same_result(libc_getfd(duplicate), raw_getfd(duplicate),
                     FD_CLOEXEC, 0)) {
        status = 18;
        goto cleanup;
    }

    /* Exercise raw mutation again, then musl's exact restoration. */
    if (!has_result(raw_setfl(duplicate, requested), 0, 0)) {
        status = 19;
        goto cleanup;
    }
    if (!same_result(libc_getfl(fd), raw_getfl(fd), changed, 0) ||
        !same_result(libc_getfl(duplicate), raw_getfl(duplicate), changed, 0) ||
        !same_result(libc_getfd(fd), raw_getfd(fd), 0, 0) ||
        !same_result(libc_getfd(duplicate), raw_getfd(duplicate),
                     FD_CLOEXEC, 0)) {
        status = 20;
        goto cleanup;
    }
    if (!has_result(libc_setfl(fd, original), 0, 0)) {
        status = 21;
        goto cleanup;
    }
    if (!same_result(libc_getfl(fd), raw_getfl(fd), original, 0) ||
        !same_result(libc_getfl(duplicate), raw_getfl(duplicate), original, 0) ||
        !same_result(libc_getfd(fd), raw_getfd(fd), 0, 0) ||
        !same_result(libc_getfd(duplicate), raw_getfd(duplicate),
                     FD_CLOEXEC, 0)) {
        status = 22;
        goto cleanup;
    }

    if (!same_result(libc_getfl(-1), raw_getfl(-1), -1, EBADF) ||
        !same_result(libc_setfl(-1, original), raw_setfl(-1, original), -1, EBADF)) {
        status = 23;
        goto cleanup;
    }

cleanup:
    /* This is best-effort so a setup failure cannot leave a named temp file. */
    (void)unlink(template);
    if (duplicate >= 0 && close(duplicate) != 0 && status == 0)
        status = 30;
    if (fd >= 0 && close(fd) != 0 && status == 0)
        status = 31;
    if (status != 0)
        return status;

    puts("syscall=72 commands=F_GETFL-3/F_SETFL-4 "
         "access=immutable-O_RDWR creation=excluded status=shared-open-description "
         "fd-cloexec=per-descriptor mutation=append+nonblock restoration=exact invalid=EBADF");
    return 0;
}
