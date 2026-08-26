/* Pinned-musl Linux/x86-64 poll behavior reference. */
#define _GNU_SOURCE 1

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int pipe_fds[2];
    struct pollfd fd;
    char byte;

    if (pipe(pipe_fds) != 0)
        return 10;
    fd.fd = pipe_fds[0];
    fd.events = POLLIN;
    fd.revents = 0;
    if (poll(&fd, 1, 0) != 0 || fd.revents != 0)
        return 11;
    if (write(pipe_fds[1], "x", 1) != 1)
        return 12;
    if (poll(&fd, 1, 0) != 1 || !(fd.revents & POLLIN))
        return 13;
    if (read(pipe_fds[0], &byte, 1) != 1)
        return 14;
    close(pipe_fds[1]);
    fd.revents = 0;
    if (poll(&fd, 1, 0) != 1 || !(fd.revents & POLLHUP))
        return 15;
    close(pipe_fds[0]);
    printf("poll=0,1,1 revents=0x0,pollin,pollhup\n");
    return 0;
}
