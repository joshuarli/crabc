#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern pid_t wait4(pid_t, int *, int, struct rusage *);
extern pid_t wait3(int *, int, struct rusage *);
extern pid_t gettid(void);
extern pid_t _Fork(void);
extern int renameat2(int, const char *, int, const char *, unsigned int);

static const char *const missing = "/tmp/crabc-m4-syscall-missing";

int main(void)
{
    char path[] = "/tmp/crabc-m4-syscall-XXXXXX";
    char hard[256] = { 0 };
    char renamed[256] = { 0 };
    char final[256] = { 0 };
    char link[256] = { 0 };
    char dir[256] = { 0 };
    char linkbuf[256];
    struct stat st;
    struct rusage usage;
    int fd = -1;
    int status;
    pid_t child;
    ssize_t n;
    int result = 1;

    fd = mkstemp(path);
    if (fd < 0)
        return 10;
    if (snprintf(hard, sizeof hard, "%s.hard", path) < 0 ||
        snprintf(renamed, sizeof renamed, "%s.renamed", path) < 0 ||
        snprintf(final, sizeof final, "%s.final", path) < 0 ||
        snprintf(link, sizeof link, "%s.link", path) < 0 ||
        snprintf(dir, sizeof dir, "%s.dir", path) < 0)
        goto cleanup;
    if (fchmodat(AT_FDCWD, path, 0600, 0) != 0)
        goto cleanup;
    if (stat(path, &st) != 0 || (st.st_mode & 0777) != 0600)
        goto cleanup;

    if (linkat(AT_FDCWD, path, AT_FDCWD, hard, 0) != 0)
        goto cleanup;
    if (symlinkat(path, AT_FDCWD, link) != 0)
        goto cleanup;
    n = readlinkat(AT_FDCWD, link, linkbuf, sizeof linkbuf - 1);
    if (n != (ssize_t)strlen(path))
        goto cleanup;
    linkbuf[n] = '\0';
    if (strcmp(linkbuf, path) != 0)
        goto cleanup;

    if (renameat(AT_FDCWD, hard, AT_FDCWD, renamed) != 0)
        goto cleanup;
    if (renameat2(AT_FDCWD, renamed, AT_FDCWD, final, 0) != 0)
        goto cleanup;
    if (stat(final, &st) != 0 || (st.st_mode & 0777) != 0600)
        goto cleanup;
    if (unlinkat(AT_FDCWD, final, 0) != 0)
        goto cleanup;
    final[0] = '\0';

    if (mkdirat(AT_FDCWD, dir, 0700) != 0)
        goto cleanup;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
        goto cleanup;
    if (unlinkat(AT_FDCWD, dir, AT_REMOVEDIR) != 0)
        goto cleanup;
    dir[0] = '\0';
    if (unlinkat(AT_FDCWD, missing, 0) != -1 || errno != ENOENT)
        goto cleanup;

    if (gettid() <= 0 || gettid() != getpid())
        goto cleanup;

    child = _Fork();
    if (child < 0)
        goto cleanup;
    if (child == 0)
        _exit(7);
    memset(&usage, 0, sizeof usage);
    if (wait4(child, &status, 0, &usage) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 7)
        goto cleanup;

    child = _Fork();
    if (child < 0)
        goto cleanup;
    if (child == 0)
        _exit(9);
    memset(&usage, 0, sizeof usage);
    if (wait3(&status, 0, &usage) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 9)
        goto cleanup;

    result = 0;

cleanup:
    if (fd >= 0)
        close(fd);
    if (path[0]) unlink(path);
    if (final[0]) unlink(final);
    if (renamed[0]) unlink(renamed);
    if (hard[0]) unlink(hard);
    if (link[0]) unlink(link);
    if (dir[0]) unlinkat(AT_FDCWD, dir, AT_REMOVEDIR);
    if (result == 0)
        puts("m4 syscall exports ok");
    return result;
}
