#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stropts.h>
#include <termios.h>
#include <unistd.h>

int main(void)
{
    struct winsize ws;
    struct termios tio;
    int master = -1;
    int nullfd = -1;
    int ok = 1;

    master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC, 0);
    if (master < 0)
        return 10;

    if (tcgetwinsize(master, &ws) != 0)
        ok = 0;
    ws.ws_row = 37;
    ws.ws_col = 91;
    ws.ws_xpixel = 640;
    ws.ws_ypixel = 480;
    if (tcsetwinsize(master, &ws) != 0)
        ok = 0;
    ws.ws_row = ws.ws_col = ws.ws_xpixel = ws.ws_ypixel = 0;
    if (tcgetwinsize(master, &ws) != 0 ||
        ws.ws_row != 37 || ws.ws_col != 91 ||
        ws.ws_xpixel != 640 || ws.ws_ypixel != 480)
        ok = 0;

    if (tcgetattr(master, &tio) != 0)
        ok = 0;
    if (cfsetspeed(&tio, B38400) != 0 ||
        cfgetospeed(&tio) != B38400 || cfgetispeed(&tio) != B0)
        ok = 0;
    errno = 0;
    if (cfsetspeed(&tio, (speed_t)~0U) != -1 || errno != EINVAL)
        ok = 0;

    if (tcsendbreak(master, 123) != 0)
        ok = 0;
    errno = 0;
    if (isastream(master) != 0 || errno != 0)
        ok = 0;
    errno = 0;
    if (isastream(-1) != -1 || errno != EBADF)
        ok = 0;

    nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC, 0);
    if (nullfd < 0)
        ok = 0;
    else {
        errno = 0;
        if (tcgetwinsize(nullfd, &ws) != -1 || errno != ENOTTY)
            ok = 0;
        errno = 0;
        if (tcsetwinsize(nullfd, &ws) != -1 || errno != ENOTTY)
            ok = 0;
        errno = 0;
        if (tcsendbreak(nullfd, 0) != -1 || errno != ENOTTY)
            ok = 0;
        errno = 0;
        if (isastream(nullfd) != 0 || errno != 0)
            ok = 0;
    }

    if (nullfd >= 0)
        close(nullfd);
    close(master);
    if (ok)
        puts("c-abi terminal extended exports ok");
    return ok ? 0 : 1;
}
