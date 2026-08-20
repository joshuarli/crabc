#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int ownership_ok_or_denied(int result)
{
    return result == 0 || (result == -1 && errno == EPERM);
}

int main(void)
{
    char path[] = "/tmp/crabc-m4-admin-kernel-XXXXXX";
    const char missing[] = "/tmp/crabc-m4-admin-kernel-missing";
    uid_t uid = getuid();
    gid_t gid = getgid();
    int fd = -1;
    int result = 1;

    /* A missing path must reach the kernel and report ENOENT. */
    errno = 0;
    if (chown(missing, uid, gid) != -1 || errno != ENOENT)
        goto cleanup;
    errno = 0;
    if (lchown(missing, uid, gid) != -1 || errno != ENOENT)
        goto cleanup;
    errno = 0;
    if (fchownat(AT_FDCWD, missing, uid, gid, 0) != -1 || errno != ENOENT)
        goto cleanup;

    fd = mkstemp(path);
    if (fd < 0)
        goto cleanup;

    /* Same-ID ownership changes are unprivileged on Linux.  A restricted
     * test runner may still deny them; preserve that permission boundary. */
    errno = 0;
    if (!ownership_ok_or_denied(chown(path, uid, gid)))
        goto cleanup;
    errno = 0;
    if (!ownership_ok_or_denied(fchown(fd, uid, gid)))
        goto cleanup;
    errno = 0;
    if (!ownership_ok_or_denied(fchownat(AT_FDCWD, path, uid, gid, 0)))
        goto cleanup;
    errno = 0;
    if (!ownership_ok_or_denied(lchown(path, uid, gid)))
        goto cleanup;

    errno = 0;
    if (fchown(-1, uid, gid) != -1 || errno != EBADF)
        goto cleanup;

    /* -1 is the Linux query sentinel, so these calls do not mutate the
     * process credentials while proving the historical return-value ABI. */
    if (setfsuid((uid_t)-1) < 0 || setfsgid((gid_t)-1) < 0)
        goto cleanup;

    errno = 0;
    if (chroot(missing) != -1 ||
        (errno != ENOENT && errno != EPERM && errno != ENOSYS))
        goto cleanup;

    result = 0;

cleanup:
    if (fd >= 0)
        close(fd);
    unlink(path);
    if (result == 0)
        puts("m4 admin kernel exports ok");
    return result;
}
