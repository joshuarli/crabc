#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int pty_path(const char *path)
{
    return path && strncmp(path, "/dev/pts/", 9) == 0;
}

static int pair_roundtrip(int master, int slave, const char *message)
{
    char got[32];
    size_t length = strlen(message);
    ssize_t written = write(slave, message, length);
    if (written != (ssize_t)length)
        return 0;
    ssize_t read_count = read(master, got, sizeof got);
    return read_count == (ssize_t)length && memcmp(got, message, length) == 0;
}

int main(void)
{
    int master = -1;
    int slave = -1;
    int openpty_master = -1;
    int openpty_slave = -1;
    int forkpty_master = -1;
    int status = 0;
    int ok = 1;
    char path[64];
    char openpty_path[64];
    char forkpty_path[64];
    char short_path[4];

    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0)
        ok = 0;

    errno = 0;
    if (ptsname_r(master, short_path, sizeof short_path) != ERANGE)
        ok = 0;
    if (ptsname_r(master, path, sizeof path) != 0 || !pty_path(path))
        ok = 0;
    if (!ptsname(master) || strcmp(ptsname(master), path) != 0)
        ok = 0;

    slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC, 0);
    if (slave < 0 || !isatty(master) || !isatty(slave))
        ok = 0;
    if (master >= 0 && slave >= 0 && !pair_roundtrip(master, slave, "pair"))
        ok = 0;

    errno = 0;
    if (grantpt(slave) != -1 || errno != ENOTTY)
        ok = 0;
    errno = 0;
    if (ptsname(-1) != NULL || errno != EBADF)
        ok = 0;

    if (openpty(&openpty_master, &openpty_slave, openpty_path, NULL, NULL) != 0 ||
        !pty_path(openpty_path) ||
        !pair_roundtrip(openpty_master, openpty_slave, "openpty"))
        ok = 0;

    pid_t child = forkpty(&forkpty_master, forkpty_path, NULL, NULL);
    if (child < 0) {
        ok = 0;
    } else if (child == 0) {
        const char message[] = "forkpty";
        _exit(write(STDOUT_FILENO, message, sizeof message - 1) ==
                (ssize_t)(sizeof message - 1) ? 0 : 111);
    } else {
        char got[16];
        ssize_t count = read(forkpty_master, got, sizeof got);
        if (!pty_path(forkpty_path) || count != 7 || memcmp(got, "forkpty", 7) != 0)
            ok = 0;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            ok = 0;
    }

    if (forkpty_master >= 0)
        close(forkpty_master);
    if (openpty_slave >= 0)
        close(openpty_slave);
    if (openpty_master >= 0)
        close(openpty_master);
    if (slave >= 0)
        close(slave);
    if (master >= 0)
        close(master);

    if (ok)
        puts("c-abi pty interfaces ok");
    return ok ? 0 : 1;
}
