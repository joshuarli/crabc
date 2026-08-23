#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

extern void cfmakeraw(struct termios *);

static int check_raw(const struct termios *t)
{
    if (t->c_iflag & (IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR |
                      IGNCR | ICRNL | IXON))
        return 0;
    if (t->c_oflag & OPOST)
        return 0;
    if (t->c_lflag & (ECHO | ECHONL | ICANON | ISIG | IEXTEN))
        return 0;
    if ((t->c_cflag & CSIZE) != CS8 || (t->c_cflag & PARENB))
        return 0;
    return t->c_cc[VMIN] == 1 && t->c_cc[VTIME] == 0;
}

int main(void)
{
    struct termios tio;
    struct termios changed;
    struct termios raw;
    int master = -1;
    int nullfd = -1;
    int ok = 1;

    /* The PTY master is a controlled tty descriptor; no slave setup is
     * needed for termios ioctl coverage. */
    master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC, 0);
    if (master < 0)
        return 10;
    if (tcgetattr(master, &tio) != 0)
        ok = 0;
    changed = tio;
    if (cfsetispeed(&changed, B9600) != 0 ||
        cfsetospeed(&changed, B19200) != 0 ||
        cfgetispeed(&changed) != B9600 ||
        cfgetospeed(&changed) != B19200)
        ok = 0;
    if (cfsetospeed(&changed, (speed_t)~0U) != -1 || errno != EINVAL)
        ok = 0;
    if (tcsetattr(master, 3, &changed) != -1 || errno != EINVAL)
        ok = 0;
    if (tcsetattr(master, TCSANOW, &changed) != 0)
        ok = 0;
    if (tcgetattr(master, &tio) != 0 ||
        cfgetispeed(&tio) != B9600 || cfgetospeed(&tio) != B19200)
        ok = 0;

    raw = tio;
    raw.c_iflag |= IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON;
    raw.c_oflag |= OPOST;
    raw.c_lflag |= ECHO | ECHONL | ICANON | ISIG | IEXTEN;
    raw.c_cflag |= CSIZE | PARENB;
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 99;
    cfmakeraw(&raw);
    if (!check_raw(&raw))
        ok = 0;

    if (tcdrain(master) != 0 || tcflush(master, TCIOFLUSH) != 0 ||
        tcflow(master, TCOON) != 0)
        ok = 0;

    nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC, 0);
    if (nullfd < 0)
        ok = 0;
    else {
        /* Process-group/session ioctls must report ENOTTY on a non-tty; this
         * exercises the failure paths without changing the caller's tty. */
        if (tcgetpgrp(nullfd) != -1 || errno != ENOTTY)
            ok = 0;
        if (tcsetpgrp(nullfd, getpid()) != -1 || errno != ENOTTY)
            ok = 0;
        if (tcgetsid(nullfd) != -1 || errno != ENOTTY)
            ok = 0;
    }

    if (nullfd >= 0)
        close(nullfd);
    close(master);
    if (ok)
        puts("c-abi terminal exports ok");
    return ok ? 0 : 1;
}
