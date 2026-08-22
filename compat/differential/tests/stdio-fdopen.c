#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char path[] = "/tmp/crabc-differential-stdio-fdopen";

static int fail(const char *name)
{
    fputs(name, stderr);
    fputc('\n', stderr);
    unlink(path);
    return 1;
}

int main(void)
{
    char tail[5] = {0};
    int fd;
    FILE *stream;

    unlink(path);
    fd = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0 || fcntl(fd, F_GETFD) != FD_CLOEXEC)
        return fail("open-cloexec");

    stream = fdopen(fd, "w+");
    if (!stream) {
        close(fd);
        return fail("fdopen");
    }
    if (fputs("crabc", stream) < 0 || fflush(stream) != 0 ||
        fseek(stream, 0, SEEK_SET) != 0)
        return fail("write-seek");
    if (fgetc(stream) != 'c' || ungetc('C', stream) != 'C' ||
        fgetc(stream) != 'C')
        return fail("ungetc");
    if (fread(tail, 1, 4, stream) != 4 || memcmp(tail, "rabc", 4) != 0)
        return fail("read-tail");
    if (fclose(stream) != 0)
        return fail("fclose");

    errno = 0;
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
        return fail("descriptor-ownership");
    if (unlink(path) != 0)
        return fail("unlink");

    printf("stdio-fdopen: errno=%d ok\n", errno);
    return 0;
}
