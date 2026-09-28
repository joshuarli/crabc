/* Open and close one pathname FILE in the executable while its linked DSO
 * performs buffered I/O. The descriptor must remain live during the handoff
 * and become EBADF after the owning executable closes the stream.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "owned_stdio_file_dso_probe.h"

static ssize_t cookie_read(void *opaque, char *buffer, size_t count)
{
    struct crabc_cookie_state *state = opaque;
    size_t remaining = state->length - state->position;
    if (count > remaining)
        count = remaining;
    memcpy(buffer, state->data + state->position, count);
    state->position += count;
    state->reads++;
    return (ssize_t)count;
}

static ssize_t cookie_write(void *opaque, const char *buffer, size_t count)
{
    struct crabc_cookie_state *state = opaque;
    if (count > sizeof(state->data) - state->position)
        return -1;
    memcpy(state->data + state->position, buffer, count);
    state->position += count;
    if (state->position > state->length)
        state->length = state->position;
    state->writes++;
    return (ssize_t)count;
}

static int cookie_seek(void *opaque, off_t *offset, int whence)
{
    struct crabc_cookie_state *state = opaque;
    int64_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ?
        (int64_t)state->position : whence == SEEK_END ? (int64_t)state->length : -1;
    int64_t target = base + *offset;
    if (base < 0 || target < 0 || target > (int64_t)sizeof(state->data))
        return -1;
    state->position = (size_t)target;
    state->seeks++;
    *offset = target;
    return 0;
}

static int cookie_close(void *opaque)
{
    ((struct crabc_cookie_state *)opaque)->closes++;
    return 0;
}

static int cookie_dso_roundtrip(void)
{
    struct crabc_cookie_state state = {0};
    cookie_io_functions_t functions = {
        cookie_read, cookie_write, cookie_seek, cookie_close
    };
    char buffer[64];
    FILE *stream = fopencookie(&state, "w+", functions);
    int result;

    if (stream == NULL || setvbuf(stream, buffer, _IOFBF, sizeof(buffer)) != 0)
        return 1;
    errno = EDOM;
    result = crabc_cookie_dso_transfer(stream, &state, &errno);
    if (result != 0)
        return 10 + result;
    if (errno != ERANGE || state.closes != 0)
        return 2;
    if (fclose(stream) != 0)
        return 3;
    if (state.closes != 1 || state.length != 7 ||
        memcmp(state.data, "cookie!", 7) != 0 || state.writes < 2 ||
        state.reads < 1 || state.seeks < 2)
        return 4;
    return 0;
}

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
    result = cookie_dso_roundtrip();
    if (result != 0)
        return 60 + result;
    if (write(STDOUT_FILENO, "stdio-file-dso-cookie-ok\n", 25) != 25)
        return 11;
    return 0;
}
