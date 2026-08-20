#include <errno.h>
#include <stdio.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    int pipefd[2];
    fd_set set;
    struct timeval zero = { 0, 0 };
    struct timeval one_second = { 1, 0 };
    const struct timespec pselect_zero = { 0, 0 };
    char byte = 's';

    if (pipe(pipefd) != 0)
        return 1;

    FD_ZERO(&set);
    FD_SET(pipefd[0], &set);
    if (select(pipefd[0] + 1, &set, NULL, NULL, &zero) != 0 ||
        FD_ISSET(pipefd[0], &set))
        return 2;

    if (write(pipefd[1], &byte, 1) != 1)
        return 3;
    FD_ZERO(&set);
    FD_SET(pipefd[0], &set);
    if (select(pipefd[0] + 1, &set, NULL, NULL, &one_second) != 1 ||
        !FD_ISSET(pipefd[0], &set))
        return 4;
    if (read(pipefd[0], &byte, 1) != 1)
        return 5;

    FD_ZERO(&set);
    FD_SET(pipefd[0], &set);
    if (pselect(pipefd[0] + 1, &set, NULL, NULL, &pselect_zero, NULL) != 0 ||
        FD_ISSET(pipefd[0], &set))
        return 6;
    errno = 0;
    if (select(-1, NULL, NULL, NULL, &zero) != -1 || errno != EINVAL)
        return 7;

    close(pipefd[0]);
    close(pipefd[1]);
    puts("m4 select exports ok");
    return 0;
}
