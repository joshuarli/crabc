/* Pinned-musl Linux/x86-64 fcntl(F_GETLK) behavior reference. */

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(struct flock) == 32, "x86 struct flock size");
_Static_assert(_Alignof(struct flock) == 8, "x86 struct flock alignment");
_Static_assert(offsetof(struct flock, l_type) == 0, "x86 flock l_type offset");
_Static_assert(offsetof(struct flock, l_whence) == 2, "x86 flock l_whence offset");
_Static_assert(offsetof(struct flock, l_start) == 8, "x86 flock l_start offset");
_Static_assert(offsetof(struct flock, l_len) == 16, "x86 flock l_len offset");
_Static_assert(offsetof(struct flock, l_pid) == 24, "x86 flock l_pid offset");
_Static_assert(F_GETLK == 5, "x86 F_GETLK command");
_Static_assert(SYS_fcntl == 72, "x86 fcntl syscall number");

static int child_observes_lock(int fd, pid_t parent)
{
    struct flock query = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
        .l_pid = 0,
    };
    if (fcntl(fd, F_GETLK, &query) != 0)
        return 10;
    if (query.l_type != F_WRLCK || query.l_whence != SEEK_SET ||
        query.l_start != 0 || query.l_len != 0 || query.l_pid != parent)
        return 11;
    return 0;
}

int main(void)
{
    char path[128];
    if (snprintf(path, sizeof(path), "/tmp/crabc-x86-fcntl-getlk-%ld",
                 (long)getpid()) < 0)
        return 1;
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0)
        return 2;
    int status = 0;
    if (unlink(path) != 0) {
        status = 3;
        goto cleanup;
    }

    struct flock query = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
        .l_pid = 0,
    };
    if (fcntl(fd, F_GETLK, &query) != 0 || query.l_type != F_UNLCK) {
        status = 4;
        goto cleanup;
    }

    struct flock held = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
        .l_pid = 0,
    };
    if (fcntl(fd, F_SETLK, &held) != 0) {
        status = 5;
        goto cleanup;
    }

    errno = 0;
    if (fcntl(-1, F_GETLK, &query) != -1 || errno != EBADF) {
        status = 6;
        goto cleanup;
    }

    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) {
        status = 7;
        goto cleanup;
    }
    if (child == 0)
        _exit(child_observes_lock(fd, parent));

    int wait_status;
    if (waitpid(child, &wait_status, 0) != child ||
        !WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0) {
        status = 8;
        goto cleanup;
    }

    held.l_type = F_UNLCK;
    if (fcntl(fd, F_SETLK, &held) != 0)
        status = 9;

cleanup:
    if (close(fd) != 0 && status == 0)
        status = 10;
    if (status != 0)
        return status;
    puts("unlocked=none conflict=write-parent-pid errors=preserved");
    return 0;
}
