#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    const char *path = "/tmp/crabc-m5-dup-exports";
    int fd, duplicate;

    unlink(path);
    fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0)
        return 1;

    if (dup2(fd, fd) != fd)
        return 2;
    errno = 0;
    if (dup3(fd, fd, 0) != -1 || errno != EINVAL)
        return 3;

    duplicate = dup(fd);
    if (duplicate < 0 || duplicate == fd)
        return 4;
    if (dup3(fd, duplicate, O_CLOEXEC) != duplicate)
        return 5;
    if ((fcntl(duplicate, F_GETFD) & FD_CLOEXEC) == 0)
        return 6;
    if (fcntl(duplicate, F_SETFD, 0) != 0)
        return 7;
    if (fcntl(duplicate, F_GETFD) & FD_CLOEXEC)
        return 8;

    close(duplicate);
    close(fd);
    unlink(path);
    puts("m5 dup exports ok");
    return 0;
}
