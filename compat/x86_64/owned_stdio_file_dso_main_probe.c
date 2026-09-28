/* Open and close one pathname FILE in the executable while its linked DSO
 * performs buffered I/O. The descriptor must remain live during the handoff
 * and become EBADF after the owning executable closes the stream.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "owned_stdio_file_dso_probe.h"

int main(int argc, char **argv)
{
    static const char expected[] = "buffered!";
    char buffer[64];
    char observed[sizeof(expected)];
    FILE *stream;
    int descriptor, reader, result;

    if (argc != 2)
        return 1;
    if (unlink(argv[1]) != 0 && errno != ENOENT)
        return 2;
    stream = fopen(argv[1], "w+");
    if (stream == NULL)
        return 3;
    descriptor = fileno(stream);
    if (descriptor < 0 || fcntl(descriptor, F_GETFD) < 0 ||
        setvbuf(stream, buffer, _IOFBF, sizeof(buffer)) != 0)
        return 4;
    errno = EDOM;
    result = crabc_file_dso_transfer(stream, descriptor, &errno);
    if (result != 0)
        return 40 + result;
    if (errno != ERANGE || fileno(stream) != descriptor ||
        fcntl(descriptor, F_GETFD) < 0)
        return 5;
    if (fclose(stream) != 0)
        return 6;
    errno = 0;
    if (fcntl(descriptor, F_GETFD) != -1 || errno != EBADF)
        return 7;
    reader = open(argv[1], O_RDONLY);
    if (reader < 0)
        return 8;
    result = read(reader, observed, sizeof(expected) - 1);
    if (close(reader) != 0 || result != sizeof(expected) - 1 ||
        memcmp(observed, expected, sizeof(expected) - 1) != 0)
        return 9;
    if (unlink(argv[1]) != 0)
        return 10;
    if (write(STDOUT_FILENO, "stdio-file-dso-ok\n", 18) != 18)
        return 11;
    return 0;
}
