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
    if (unlink(argv[1]) != 0)
        return 3;
    puts("fdopen lifecycle ok");
    return 0;
}
