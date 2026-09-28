/* Open and close one pathname FILE in the executable while its linked DSO
 * performs buffered I/O. The descriptor must remain live during the handoff
 * and become EBADF after the owning executable closes the stream.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>
#include "owned_stdio_file_dso_probe.h"

static ssize_t cookie_read(void *opaque, char *buffer, size_t count)
{
    struct crabc_cookie_state *state = opaque;
    size_t remaining = state->position < state->length ?
        state->length - state->position : 0;
    state->reads++;
    if (remaining == 0)
        return 0;
    if (count > remaining)
        count = remaining;
    memcpy(buffer, state->data + state->position, count);
    state->position += count;
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
    /* Bound the offset before addition so an extreme seek cannot overflow. */
    if (base < 0 || *offset < -base ||
        *offset > (int64_t)sizeof(state->data) - base)
        return -1;
    int64_t target = base + *offset;
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
    if (fseek(stream, 12, SEEK_SET) != 0 || fgetc(stream) != EOF ||
        !feof(stream) || state.position != 12 || state.length != 7)
        return 5;
    if (fseek(stream, LONG_MAX, SEEK_END) == 0 || state.position != 12)
        return 6;
    if (fclose(stream) != 0)
        return 3;
    if (state.closes != 1 || state.length != 7 ||
        memcmp(state.data, "cookie!", 7) != 0 || state.writes < 2 ||
        state.reads < 1 || state.seeks < 2)
        return 4;
    return 0;
}

static int reverse_cookie_dso_roundtrip(void)
{
    char buffer[64], observed[7];
    FILE *stream;

    errno = EDOM;
    stream = crabc_cookie_dso_open(&errno);
    if (stream == NULL || errno != ERANGE ||
        setvbuf(stream, buffer, _IOFBF, sizeof(buffer)) != 0)
        return 1;
    if (fwrite("reverse", 1, 7, stream) != 7)
        return 2;
    errno = EILSEQ;
    if (crabc_cookie_dso_check(CRABC_COOKIE_DSO_BUFFERED, &errno) != 0 ||
        errno != EAGAIN)
        return 3;
    if (fflush(stream) != 0)
        return 4;
    errno = EILSEQ;
    if (crabc_cookie_dso_check(CRABC_COOKIE_DSO_FLUSHED, &errno) != 0 ||
        errno != EAGAIN)
        return 5;
    if (fseek(stream, 0, SEEK_SET) != 0 ||
        fread(observed, 1, 7, stream) != 7 ||
        memcmp(observed, "reverse", 7) != 0)
        return 6;
    if (fseek(stream, 0, SEEK_END) != 0 || fputc('!', stream) != '!' ||
        fflush(stream) != 0)
        return 7;
    if (fclose(stream) != 0)
        return 8;
    errno = EILSEQ;
    if (crabc_cookie_dso_check(CRABC_COOKIE_DSO_CLOSED, &errno) != 0 ||
        errno != EAGAIN)
        return 9;
    return 0;
}

static int wide_dso_roundtrip(const char *path)
{
    static const unsigned char expected[] = {0xe2, 0x82, 0xac};
    unsigned char observed[4];
    FILE *stream;
    int descriptor, reader, count, result;

    if (setlocale(LC_CTYPE, "C.UTF-8") == NULL)
        return 1;
    stream = fopen(path, "w+");
    if (stream == NULL || fwide(stream, 0) != 0)
        return 2;
    descriptor = fileno(stream);
    if (descriptor < 0)
        return 3;
    errno = EDOM;
    result = crabc_file_dso_write_wide(stream, &errno);
    if (result != 0)
        return 10 + result;
    if (errno != ERANGE || fwide(stream, 0) <= 0)
        return 4;
    if (fseek(stream, 0, SEEK_SET) != 0 || fwide(stream, 0) <= 0 ||
        fgetwc(stream) != 0x20ac || fgetwc(stream) != WEOF ||
        !feof(stream) || ferror(stream) != 0)
        return 5;
    if (fclose(stream) != 0)
        return 6;
    errno = 0;
    if (fcntl(descriptor, F_GETFD) != -1 || errno != EBADF)
        return 7;
    reader = open(path, O_RDONLY);
    if (reader < 0)
        return 8;
    count = read(reader, observed, sizeof(observed));
    if (close(reader) != 0 || count != sizeof(expected) ||
        memcmp(observed, expected, sizeof(expected)) != 0)
        return 9;
    if (unlink(path) != 0)
        return 20;
    return 0;
}

static int prepare_dso_exit_stream(const char *path)
{
    char stream_path[PATH_MAX], marker_path[PATH_MAX];
    int stream_length, marker_length, result;

    stream_length = snprintf(stream_path, sizeof(stream_path), "%s.exit", path);
    marker_length = snprintf(marker_path, sizeof(marker_path), "%s.fini", path);
    if (stream_length < 0 || marker_length < 0 ||
        (size_t)stream_length >= sizeof(stream_path) ||
        (size_t)marker_length >= sizeof(marker_path))
        return 1;
    errno = EDOM;
    result = crabc_file_dso_buffer_exit(stream_path, marker_path, &errno);
    if (result != 0 || errno != ERANGE)
        return 2;
    return 0;
}

static int reopen_dso_roundtrip(const char *path)
{
    static const char old_bytes[] = "beforetail";
    static const char new_bytes[] = "replacement!";
    char old_path[PATH_MAX], new_path[PATH_MAX], buffer[64], observed[32];
    struct stat state;
    FILE *stream;
    int old_length, new_length, descriptor, reader, result;

    old_length = snprintf(old_path, sizeof(old_path), "%s.old", path);
    new_length = snprintf(new_path, sizeof(new_path), "%s.new", path);
    if (old_length < 0 || new_length < 0 ||
        (size_t)old_length >= sizeof(old_path) ||
        (size_t)new_length >= sizeof(new_path))
        return 1;
    stream = fopen(old_path, "w");
    if (stream == NULL || setvbuf(stream, buffer, _IOFBF, sizeof(buffer)) != 0)
        return 2;
    descriptor = fileno(stream);
    if (descriptor < 0 || fwrite("before", 1, 6, stream) != 6 ||
        fwide(stream, 0) >= 0 || fstat(descriptor, &state) != 0 ||
        state.st_size != 0)
        return 3;
    if (fgetc(stream) != EOF || !ferror(stream) || feof(stream) ||
        fstat(descriptor, &state) != 0 || state.st_size != 6)
        return 4;
    if (fwrite("tail", 1, 4, stream) != 4 || !ferror(stream) ||
        fstat(descriptor, &state) != 0 || state.st_size != 6)
        return 5;
    errno = EDOM;
    result = crabc_file_dso_reopen(stream, new_path, &errno);
    if (result != 0 || errno != ERANGE)
        return 10 + result;
    if (fwide(stream, 0) != 0 || ferror(stream) || feof(stream) ||
        fcntl(fileno(stream), F_GETFD) < 0)
        return 20;
    if (fwrite(new_bytes, 1, sizeof(new_bytes) - 1, stream) !=
        sizeof(new_bytes) - 1 || fseek(stream, 0, SEEK_SET) != 0 ||
        fread(observed, 1, sizeof(new_bytes) - 1, stream) !=
        sizeof(new_bytes) - 1 ||
        memcmp(observed, new_bytes, sizeof(new_bytes) - 1) != 0)
        return 21;
    descriptor = fileno(stream);
    if (fclose(stream) != 0)
        return 22;
    errno = 0;
    if (fcntl(descriptor, F_GETFD) != -1 || errno != EBADF)
        return 23;
    reader = open(old_path, O_RDONLY);
    if (reader < 0)
        return 24;
    result = read(reader, observed, sizeof(observed));
    if (close(reader) != 0 || result != sizeof(old_bytes) - 1 ||
        memcmp(observed, old_bytes, sizeof(old_bytes) - 1) != 0)
        return 25;
    reader = open(new_path, O_RDONLY);
    if (reader < 0)
        return 26;
    result = read(reader, observed, sizeof(observed));
    if (close(reader) != 0 || result != sizeof(new_bytes) - 1 ||
        memcmp(observed, new_bytes, sizeof(new_bytes) - 1) != 0)
        return 27;
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
    result = reverse_cookie_dso_roundtrip();
    if (result != 0)
        return 80 + result;
    result = wide_dso_roundtrip(argv[1]);
    if (result != 0)
        return 100 + result;
    result = prepare_dso_exit_stream(argv[1]);
    if (result != 0)
        return 130 + result;
    result = reopen_dso_roundtrip(argv[1]);
    if (result != 0)
        return 160 + result;
    if (write(STDOUT_FILENO, "stdio-file-dso-reopen-ok\n", 25) != 25)
        return 11;
    return 0;
}
