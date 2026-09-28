/* Operate on a FILE owned by the executable without assuming ownership
 * of the stream or descriptor. Buffered bytes must reach the kernel only
 * when this image flushes them; both images share the same errno slot.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>
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

int crabc_cookie_dso_transfer(FILE *stream, const struct crabc_cookie_state *state,
                              int *main_errno)
{
    char observed[6];

    if (stream == NULL || state == NULL || main_errno != &errno || errno != EDOM)
        return 1;
    if (fwrite("cookie", 1, 6, stream) != 6)
        return 2;
    if (state->writes != 0 || state->length != 0)
        return 3;
    if (fflush(stream) != 0 || state->writes < 1 || state->length != 6 ||
        memcmp(state->data, "cookie", 6) != 0)
        return 4;
    if (fseek(stream, 0, SEEK_SET) != 0 || fread(observed, 1, 6, stream) != 6 ||
        memcmp(observed, "cookie", 6) != 0)
        return 5;
    if (fseek(stream, 0, SEEK_END) != 0 || fputc('!', stream) != '!')
        return 6;
    if (fflush(stream) != 0 || state->length != 7 ||
        memcmp(state->data, "cookie!", 7) != 0)
        return 7;
    errno = ERANGE;
    return 0;
}

/* These callbacks and their state remain in the DSO until main closes FILE. */
static struct crabc_cookie_state reverse_state;

static ssize_t reverse_cookie_read(void *opaque, char *buffer, size_t count)
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

static ssize_t reverse_cookie_write(void *opaque, const char *buffer, size_t count)
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

static int reverse_cookie_seek(void *opaque, off_t *offset, int whence)
{
    struct crabc_cookie_state *state = opaque;
    int64_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ?
        (int64_t)state->position : whence == SEEK_END ? (int64_t)state->length : -1;
    if (base < 0 || *offset < -base ||
        *offset > (int64_t)sizeof(state->data) - base)
        return -1;
    state->position = (size_t)(base + *offset);
    state->seeks++;
    *offset = state->position;
    return 0;
}

static int reverse_cookie_close(void *opaque)
{
    ((struct crabc_cookie_state *)opaque)->closes++;
    return 0;
}

FILE *crabc_cookie_dso_open(int *main_errno)
{
    cookie_io_functions_t functions = {
        reverse_cookie_read, reverse_cookie_write,
        reverse_cookie_seek, reverse_cookie_close
    };
    FILE *stream;

    if (main_errno != &errno || errno != EDOM)
        return NULL;
    memset(&reverse_state, 0, sizeof(reverse_state));
    stream = fopencookie(&reverse_state, "w+", functions);
    if (stream != NULL)
        errno = ERANGE;
    return stream;
}

int crabc_cookie_dso_check(enum crabc_cookie_dso_stage stage, int *main_errno)
{
    int valid;

    if (main_errno != &errno || errno != EILSEQ)
        return 1;
    if (stage == CRABC_COOKIE_DSO_BUFFERED)
        valid = reverse_state.writes == 0 && reverse_state.length == 0 &&
            reverse_state.closes == 0;
    else if (stage == CRABC_COOKIE_DSO_FLUSHED)
        valid = reverse_state.writes >= 1 && reverse_state.length == 7 &&
            memcmp(reverse_state.data, "reverse", 7) == 0 &&
            reverse_state.closes == 0;
    else if (stage == CRABC_COOKIE_DSO_CLOSED)
        valid = reverse_state.writes >= 2 && reverse_state.reads >= 1 &&
            reverse_state.seeks >= 2 && reverse_state.closes == 1 &&
            reverse_state.length == 8 &&
            memcmp(reverse_state.data, "reverse!", 8) == 0;
    else
        return 2;
    errno = EAGAIN;
    return valid ? 0 : 3;
}

int crabc_file_dso_write_wide(FILE *stream, int *main_errno)
{
    if (stream == NULL || main_errno != &errno || errno != EDOM ||
        fwide(stream, 0) != 0)
        return 1;
    if (fwide(stream, 1) <= 0 || fwide(stream, -1) <= 0 ||
        fputwc((wchar_t)0x20ac, stream) != 0x20ac || fflush(stream) != 0)
        return 2;
    errno = ERANGE;
    return 0;
}

static FILE *exit_stream;
static char exit_buffer[64];
static char exit_marker_path[PATH_MAX];

int crabc_file_dso_buffer_exit(const char *stream_path, const char *marker_path,
                               int *main_errno)
{
    static const char payload[] = "dso-exit-once\n";
    struct stat state;
    size_t length;

    if (stream_path == NULL || marker_path == NULL ||
        main_errno != &errno || errno != EDOM)
        return 1;
    length = strlen(marker_path);
    if (length >= sizeof(exit_marker_path))
        return 2;
    memcpy(exit_marker_path, marker_path, length + 1);
    exit_stream = fopen(stream_path, "w");
    if (exit_stream == NULL ||
        setvbuf(exit_stream, exit_buffer, _IOFBF, sizeof(exit_buffer)) != 0)
        return 3;
    if (fwrite(payload, 1, sizeof(payload) - 1, exit_stream) !=
        sizeof(payload) - 1)
        return 4;
    if (fstat(fileno(exit_stream), &state) != 0 || state.st_size != 0)
        return 5;
    errno = ERANGE;
    return 0;
}

/* Record the descriptor's state before ordinary-exit stream flushing. */
__attribute__((destructor)) static void record_exit_stream_finalizer(void)
{
    static const char before[] = "fini-before-flush:fd-live\n";
    static const char other[] = "fini-after-or-dead\n";
    struct stat state;
    const char *message;
    int marker;

    if (exit_stream == NULL)
        return;
    message = fstat(fileno(exit_stream), &state) == 0 && state.st_size == 0 &&
        fcntl(fileno(exit_stream), F_GETFD) >= 0 ? before : other;
    marker = open(exit_marker_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (marker < 0)
        return;
    write(marker, message, strlen(message));
    close(marker);
}
