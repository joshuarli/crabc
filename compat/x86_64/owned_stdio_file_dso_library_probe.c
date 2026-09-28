/* Operate on a FILE owned by the executable without assuming ownership
 * of the stream or descriptor. Buffered bytes must reach the kernel only
 * when this image flushes them; both images share the same errno slot.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "owned_stdio_file_dso_probe.h"

int crabc_file_dso_transfer(FILE *stream, int descriptor, int *main_errno)
{
    static const char payload[] = "buffered";
    char observed[sizeof(payload)];
    struct stat state;

    if (stream == NULL || main_errno != &errno || errno != EDOM)
        return 1;
    if (fileno(stream) != descriptor || fcntl(descriptor, F_GETFD) < 0)
        return 2;
    if (fwrite(payload, 1, sizeof(payload) - 1, stream) != sizeof(payload) - 1)
        return 3;
    if (fstat(descriptor, &state) != 0 || state.st_size != 0)
        return 4;
    if (fflush(stream) != 0 || fstat(descriptor, &state) != 0 ||
        state.st_size != sizeof(payload) - 1)
        return 5;
    if (fseek(stream, 0, SEEK_SET) != 0 ||
        fread(observed, 1, sizeof(payload) - 1, stream) != sizeof(payload) - 1 ||
        memcmp(observed, payload, sizeof(payload) - 1) != 0)
        return 6;
    if (fseek(stream, 0, SEEK_END) != 0 || fputc('!', stream) != '!')
        return 7;
    if (fflush(stream) != 0 || fstat(descriptor, &state) != 0 ||
        state.st_size != sizeof(payload))
        return 8;
    errno = ERANGE;
    return 0;
}
