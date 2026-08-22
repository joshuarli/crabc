#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <sys/select.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    int pipefd[2];
    fd_set set;
    struct timeval zero = { 0, 0 };
    struct timeval one_second = { 0, 1000001 };
    const struct timespec pselect_zero = { 0, 0 };
    struct timeval invalid_select = { 0, -1 };
    struct timeval overflow_select = { LONG_MAX, 1000000 };
    const struct timespec invalid_pselect = { 0, 1000000000L };
    struct timeval before;
    struct timespec before_pselect;
    sigset_t empty_mask;
    char byte = 's';

    if (pipe(pipefd) != 0)
        return 1;

    FD_ZERO(&set);
    FD_SET(pipefd[0], &set);
    before = zero;
    if (select(pipefd[0] + 1, &set, NULL, NULL, &zero) != 0 ||
        memcmp(&zero, &before, sizeof(zero)) != 0 ||
        FD_ISSET(pipefd[0], &set))
        return 2;

    if (write(pipefd[1], &byte, 1) != 1)
        return 3;
    FD_ZERO(&set);
    FD_SET(pipefd[0], &set);
    before = one_second;
    if (select(pipefd[0] + 1, &set, NULL, NULL, &one_second) != 1 ||
        memcmp(&one_second, &before, sizeof(one_second)) != 0 ||
        !FD_ISSET(pipefd[0], &set))
        return 4;
    if (read(pipefd[0], &byte, 1) != 1)
        return 5;

    FD_ZERO(&set);
    FD_SET(pipefd[0], &set);
    if (sigemptyset(&empty_mask) != 0)
        return 6;
    before_pselect = pselect_zero;
    if (pselect(pipefd[0] + 1, &set, NULL, NULL, &pselect_zero, &empty_mask) != 0 ||
        memcmp(&pselect_zero, &before_pselect, sizeof(pselect_zero)) != 0 ||
        FD_ISSET(pipefd[0], &set))
        return 7;
    errno = 0;
    if (select(-1, NULL, NULL, NULL, &zero) != -1 || errno != EINVAL)
        return 8;
    errno = 0;
    before = invalid_select;
    if (select(0, NULL, NULL, NULL, &invalid_select) != -1 || errno != EINVAL ||
        memcmp(&invalid_select, &before, sizeof(invalid_select)) != 0)
        return 9;
    errno = 0;
    before_pselect = invalid_pselect;
    if (pselect(0, NULL, NULL, NULL, &invalid_pselect, &empty_mask) != -1 ||
        errno != EINVAL || memcmp(&invalid_pselect, &before_pselect, sizeof(invalid_pselect)) != 0)
        return 10;
    errno = 0;
    before = overflow_select;
    if (select(0, NULL, NULL, NULL, &overflow_select) != -1 || errno != EINVAL ||
        memcmp(&overflow_select, &before, sizeof(overflow_select)) != 0)
        return 11;

    close(pipefd[0]);
    close(pipefd[1]);
    puts("m4 select exports ok");
    return 0;
}
