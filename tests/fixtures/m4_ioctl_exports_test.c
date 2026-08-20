#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void)
{
    int pipefd[2];
    int available = -1;

    if (pipe(pipefd) != 0)
        return 1;
    if (write(pipefd[1], "abc", 3) != 3)
        return 2;
    if (ioctl(pipefd[0], FIONREAD, &available) != 0 || available != 3)
        return 3;

    errno = 0;
    if (ioctl(-1, FIONREAD, &available) != -1 || errno != EBADF)
        return 4;
    close(pipefd[0]);
    close(pipefd[1]);
    puts("m4 ioctl ok");
    return 0;
}
