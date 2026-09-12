/*
 * Exercise musl 1.2.6's weak-public/strong-internal stdio alias boundary.
 *
 * The application owns strong public fdopen, fseeko, and ftello definitions.
 * Pinned musl binds its own fopen, fseek, and ftell paths through hidden
 * __fdopen, __fseeko, and __ftello, so those internal calls must remain
 * usable without entering the application overrides.  A static archive with
 * a strong public definition fails to link this valid program before that
 * boundary is restored.
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static int public_fdopen_calls;
static int public_fseeko_calls;
static int public_ftello_calls;

FILE *fdopen(int descriptor, const char *mode)
{
    (void)descriptor;
    (void)mode;
    ++public_fdopen_calls;
    return (FILE *)(uintptr_t)0x1234;
}

int fseeko(FILE *stream, off_t offset, int whence)
{
    (void)stream;
    (void)offset;
    (void)whence;
    ++public_fseeko_calls;
    return -1;
}

off_t ftello(FILE *stream)
{
    (void)stream;
    ++public_ftello_calls;
    return -1;
}

int main(int argc, char **argv)
{
    FILE *stream;
    int descriptor;

    if (argc != 2)
        return 10;
    stream = fopen(argv[1], "w+");
    if (!stream || public_fdopen_calls != 0)
        return 11;
    if (fputs("alias", stream) == EOF || fflush(stream) == EOF)
        return 12;
    if (fseek(stream, 0, SEEK_SET) != 0 || public_fseeko_calls != 0)
        return 13;
    if (ftell(stream) != 0 || public_ftello_calls != 0)
        return 14;
    if (fclose(stream) != 0)
        return 15;

    descriptor = open(argv[1], O_RDONLY);
    if (descriptor < 0)
        return 16;
    if (fdopen(descriptor, "r") != (FILE *)(uintptr_t)0x1234
        || public_fdopen_calls != 1)
        return 17;
    if (fseeko(NULL, 7, SEEK_CUR) != -1 || public_fseeko_calls != 1)
        return 18;
    if (ftello(NULL) != -1 || public_ftello_calls != 1)
        return 19;
    if (close(descriptor) != 0 || unlink(argv[1]) != 0)
        return 20;
    puts("owned-stdio-alias-override-ok");
    return 0;
}
