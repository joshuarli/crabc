#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char path_template[] = "/tmp/crabc-ofd-lock-XXXXXX";

static int fail(const char *operation, char *path, int first, int second, int third)
{
    fprintf(stderr, "%s: %s\n", operation, strerror(errno));
    if (third >= 0) close(third);
    if (second >= 0) close(second);
    if (first >= 0) close(first);
    unlink(path);
    return 1;
}

int main(void)
{
    char path[sizeof path_template];
    struct flock lock = { .l_type = F_RDLCK, .l_whence = SEEK_SET,
                          .l_start = 0, .l_len = 1, .l_pid = 0 };
    struct flock outcome = { .l_type = F_WRLCK, .l_whence = SEEK_SET,
                             .l_start = 0, .l_len = 1, .l_pid = 0 };
    int first = -1;
    int duplicate = -1;
    int reopened = -1;

    strcpy(path, path_template);
    first = mkstemp(path);
    if (first < 0)
        return fail("mkstemp", path, first, duplicate, reopened);

    if (fcntl(first, F_OFD_SETLK, &lock) < 0)
        return fail("F_OFD_SETLK", path, first, duplicate, reopened);

    duplicate = dup(first);
    if (duplicate < 0 || fcntl(duplicate, F_OFD_SETLK, &lock) < 0)
        return fail("duplicate OFD lock", path, first, duplicate, reopened);

    reopened = open(path, O_RDWR);
    if (reopened < 0)
        return fail("reopen", path, first, duplicate, reopened);

    errno = 0;
    if (fcntl(reopened, F_OFD_SETLK,
              &(struct flock){ .l_type = F_WRLCK, .l_whence = SEEK_SET,
                               .l_start = 0, .l_len = 1, .l_pid = 0 }) != -1 ||
        errno != EAGAIN)
        return fail("conflicting OFD lock", path, first, duplicate, reopened);

    if (fcntl(reopened, F_OFD_GETLK, &outcome) < 0)
        return fail("F_OFD_GETLK", path, first, duplicate, reopened);
    if (outcome.l_type != F_RDLCK)
        return fail("F_OFD_GETLK result", path, first, duplicate, reopened);

    lock.l_type = F_UNLCK;
    if (fcntl(duplicate, F_OFD_SETLK, &lock) < 0)
        return fail("F_OFD_SETLK unlock", path, first, duplicate, reopened);
    outcome.l_type = F_WRLCK;
    /* Linux reports a conflicting OFD lock with l_pid == -1.  The next
       F_OFD_GETLK request must supply the input flock ABI, whose l_pid is
       zero; otherwise the kernel rejects the request with EINVAL. */
    outcome.l_pid = 0;
    if (fcntl(reopened, F_OFD_GETLK, &outcome) < 0 ||
        outcome.l_type != F_UNLCK)
        return fail("F_OFD_GETLK unlocked result", path, first, duplicate, reopened);

    close(reopened);
    close(duplicate);
    close(first);
    unlink(path);
    puts("ofd lock ok");
    return 0;
}
