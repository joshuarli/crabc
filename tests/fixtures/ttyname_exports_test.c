#include <errno.h>
#include <pty.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char name[64];
    char small[2];
    int master;
    int slave;
    int pipefd[2];
    char *legacy;

    if (openpty(&master, &slave, NULL, NULL, NULL) != 0)
        return 1;
    if (ttyname_r(slave, name, sizeof name) != 0 ||
        strncmp(name, "/dev/pts/", 9) != 0)
        return 2;
    legacy = ttyname(slave);
    if (!legacy || strcmp(legacy, name) != 0)
        return 3;
    if (ttyname_r(slave, small, sizeof small) != ERANGE)
        return 4;
    if (pipe(pipefd) != 0)
        return 5;
    errno = 0;
    if (ttyname_r(pipefd[0], name, sizeof name) != ENOTTY || errno != ENOTTY)
        return 6;
    errno = 0;
    if (ttyname(-1) != NULL || errno != EBADF)
        return 7;
    close(pipefd[0]);
    close(pipefd[1]);
    close(slave);
    close(master);
    puts("c-abi ttyname exports ok");
    return 0;
}
