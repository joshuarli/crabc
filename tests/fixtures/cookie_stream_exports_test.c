#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct cookie_state {
    char bytes[32];
    size_t length;
    size_t position;
    int reads;
    int writes;
    int seeks;
    int closes;
};

static ssize_t cookie_read(void *opaque, char *buffer, size_t length)
{
    struct cookie_state *state = opaque;
    size_t available = state->length - state->position;
    if (length > available)
        length = available;
    if (length) {
        memcpy(buffer, state->bytes + state->position, length);
        state->position += length;
    }
    state->reads++;
    return (ssize_t)length;
}

static ssize_t cookie_write(void *opaque, const char *buffer, size_t length)
{
    struct cookie_state *state = opaque;
    if (length > sizeof state->bytes - state->position) {
        errno = ENOSPC;
        return -1;
    }
    if (length)
        memcpy(state->bytes + state->position, buffer, length);
    state->position += length;
    if (state->position > state->length)
        state->length = state->position;
    state->writes++;
    return (ssize_t)length;
}

static int cookie_seek(void *opaque, off_t *offset, int whence)
{
    struct cookie_state *state = opaque;
    off_t base = whence == SEEK_SET ? 0 :
        whence == SEEK_CUR ? (off_t)state->position : (off_t)state->length;
    off_t target = base + *offset;
    if (target < 0 || target > (off_t)sizeof state->bytes) {
        errno = EINVAL;
        return -1;
    }
    state->position = (size_t)target;
    *offset = target;
    state->seeks++;
    return 0;
}

static int cookie_close(void *opaque)
{
    ((struct cookie_state *)opaque)->closes++;
    return 0;
}

static ssize_t failing_write(void *opaque, const char *buffer, size_t length)
{
    (void)opaque;
    (void)buffer;
    (void)length;
    errno = EIO;
    return -1;
}

int main(void)
{
    struct cookie_state state = {0};
    cookie_io_functions_t io = {
        .read = cookie_read,
        .write = cookie_write,
        .seek = cookie_seek,
        .close = cookie_close,
    };
    FILE *stream;
    char output[4] = {0};

    errno = 0;
    if (fopencookie(&state, "x", io) != NULL || errno != EINVAL)
        return 1;
    stream = fopencookie(&state, "w+", io);
    if (!stream || fputs("abc", stream) < 0 || fseek(stream, 0, SEEK_SET) != 0 ||
        fread(output, 1, 3, stream) != 3 || memcmp(output, "abc", 3) != 0 ||
        state.writes < 1 || state.reads < 1 || state.seeks < 1 || fclose(stream) != 0 ||
        state.closes != 1)
        return 2;

    io.write = failing_write;
    io.close = NULL;
    stream = fopencookie(NULL, "w", io);
    if (!stream || fputs("x", stream) < 0 || fflush(stream) != -1 || errno != EIO ||
        !ferror(stream))
        return 3;
    (void)fclose(stream);

    puts("c-abi cookie stream exports ok");
    return 0;
}
