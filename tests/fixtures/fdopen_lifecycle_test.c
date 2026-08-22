/*
 * fdopen owns the FILE object and its private buffer, but not the descriptor
 * passed by the caller. Exercise both buffered directions repeatedly and
 * reuse the allocation path across many stream lifetimes.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int write_round(const char *path, unsigned int round)
{
    unsigned char bytes[1024];
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    FILE *stream;

    if (fd < 0)
        return 1;
    stream = fdopen(fd, "w+");
    if (stream == NULL) {
        close(fd);
        return 2;
    }

    for (unsigned int index = 0; index < sizeof(bytes); ++index)
        bytes[index] = (unsigned char)(round + index);
    if (fwrite(bytes, 1, sizeof(bytes), stream) != sizeof(bytes)
            || fflush(stream) != 0 || fseek(stream, 511, SEEK_SET) != 0)
        return 3;
    if (fgetc(stream) != (int)(unsigned char)(round + 511)
            || ungetc((unsigned char)(round + 511), stream)
                != (int)(unsigned char)(round + 511)
            || fgetc(stream) != (int)(unsigned char)(round + 511))
        return 4;
    return fclose(stream) == 0 ? 0 : 5;
}

static int read_round(const char *path, unsigned int round)
{
    unsigned char bytes[1024];
    int fd = open(path, O_RDONLY);
    FILE *stream;

    if (fd < 0)
        return 1;
    stream = fdopen(fd, "r");
    if (stream == NULL) {
        close(fd);
        return 2;
    }
    if (fread(bytes, 1, sizeof(bytes), stream) != sizeof(bytes))
        return 3;
    for (unsigned int index = 0; index < sizeof(bytes); ++index) {
        if (bytes[index] != (unsigned char)(round + index))
            return 4;
    }
    return fclose(stream) == 0 ? 0 : 5;
}

/* fopen parses the mode to choose open flags, then fdopen must give the same
 * mode the matching FILE direction and suffix behavior. Exercise the suffixes
 * that alter observable descriptor or stream state across that handoff. */
static int mode_round(const char *path)
{
    FILE *stream;
    int fd;
    char bytes[3] = {0};

    if (unlink(path) != 0)
        return 1;
    stream = fopen(path, "wex");
    if (stream == NULL)
        return 2;
    if (fcntl(fileno(stream), F_GETFD) != FD_CLOEXEC || fputs("a", stream) < 0
            || fclose(stream) != 0)
        return 3;

    stream = fopen(path, "a+e");
    if (stream == NULL)
        return 4;
    if (fcntl(fileno(stream), F_GETFD) != FD_CLOEXEC || fputs("b", stream) < 0
            || fflush(stream) != 0 || fseek(stream, 0, SEEK_SET) != 0
            || fread(bytes, 1, 2, stream) != 2 || memcmp(bytes, "ab", 2) != 0
            || fclose(stream) != 0)
        return 5;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return 6;
    stream = fdopen(fd, "re");
    if (stream == NULL) {
        close(fd);
        return 7;
    }
    if (fcntl(fd, F_GETFD) != FD_CLOEXEC || fclose(stream) != 0)
        return 8;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 1;
    for (unsigned int round = 0; round < 513; ++round) {
        int status = write_round(argv[1], round);
        if (status != 0)
            return 10 + status;
        status = read_round(argv[1], round);
        if (status != 0)
            return 20 + status;
    }
    const int mode_status = mode_round(argv[1]);
    if (mode_status != 0)
        return 30 + mode_status;
    if (unlink(argv[1]) != 0)
        return 3;
    puts("fdopen lifecycle ok");
    return 0;
}
