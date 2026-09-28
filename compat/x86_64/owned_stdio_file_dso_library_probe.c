/* Operate on a FILE owned by the executable without assuming ownership
 * of the stream or descriptor. Buffered bytes must reach the kernel only
 * when this image flushes them; both images share the same errno slot.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
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

int crabc_file_dso_reopen(FILE *stream, const char *replacement_path,
                          int *main_errno)
{
    if (stream == NULL || replacement_path == NULL || main_errno != &errno ||
        errno != EDOM || fwide(stream, 0) >= 0 || !ferror(stream) || feof(stream))
        return 1;
    if (freopen(replacement_path, "w+", stream) != stream)
        return 2;
    if (fwide(stream, 0) != 0 || ferror(stream) || feof(stream))
        return 3;
    errno = ERANGE;
    return 0;
}

/* The allocation and publication slots stay in this image while main owns
 * the FILE close. The published allocation remains owned here after close.
 */
static FILE *memstream_stream;
static char *memstream_buffer;
static size_t memstream_length;
static unsigned memstream_stage;

FILE *crabc_memstream_dso_open(char ***buffer_slot, size_t **length_slot,
                               int *main_errno)
{
    if (buffer_slot == NULL || length_slot == NULL || main_errno != &errno ||
        errno != EDOM || memstream_stream != NULL || memstream_stage != 0)
        return NULL;
    memstream_stream = open_memstream(&memstream_buffer, &memstream_length);
    if (memstream_stream == NULL || memstream_buffer == NULL ||
        memstream_length != 0 || memstream_buffer[0] != 0)
        return NULL;
    *buffer_slot = &memstream_buffer;
    *length_slot = &memstream_length;
    errno = ERANGE;
    return memstream_stream;
}

int crabc_memstream_dso_checkpoint(FILE *stream, enum crabc_memstream_dso_stage stage,
                                    int *main_errno)
{
    static const unsigned char final[] = {'a', 'l', 'X', 'Y', 'a', '!', 0, 0, 'Z', 0};

    if (stream == NULL || stream != memstream_stream || main_errno != &errno ||
        errno != EDOM || (unsigned)stage != memstream_stage + 1 ||
        memstream_buffer == NULL)
        return 1;
    if (stage == CRABC_MEMSTREAM_DSO_FIRST_BUFFERED) {
        if (memstream_length != 0 || memstream_buffer[0] != 0 ||
            fflush(stream) != 0 || memstream_length != 5 ||
            memcmp(memstream_buffer, "alpha\0", 6) != 0)
            return 2;
    } else if (stage == CRABC_MEMSTREAM_DSO_MAIN_REWRITE_FLUSHED) {
        if (memstream_length != 4 ||
            memcmp(memstream_buffer, "alXYa", 5) != 0)
            return 3;
    } else if (stage == CRABC_MEMSTREAM_DSO_APPEND_BUFFERED) {
        if (memstream_length != 4 ||
            memcmp(memstream_buffer, "alXYa", 5) != 0 ||
            fflush(stream) != 0 || memstream_length != 6 ||
            memcmp(memstream_buffer, "alXYa!\0", 7) != 0)
            return 4;
    } else if (stage == CRABC_MEMSTREAM_DSO_MAIN_HOLE_FLUSHED) {
        if (memstream_length != 9 ||
            memcmp(memstream_buffer, final, sizeof(final)) != 0)
            return 5;
    } else {
        return 6;
    }
    memstream_stage++;
    errno = ERANGE;
    return 0;
}

int crabc_memstream_dso_release(int *main_errno)
{
    static const unsigned char final[] = {'a', 'l', 'X', 'Y', 'a', '!', 0, 0, 'Z', 0};

    if (main_errno != &errno || errno != EDOM || memstream_stage != 4 ||
        memstream_buffer == NULL || memstream_length != 9 ||
        memcmp(memstream_buffer, final, sizeof(final)) != 0)
        return 1;
    free(memstream_buffer);
    memstream_buffer = NULL;
    memstream_length = 0;
    memstream_stream = NULL;
    memstream_stage++;
    errno = ERANGE;
    return 0;
}

/* The fixed storage belongs to this image and remains visible to main after
 * it closes the FILE. No stream callback owns or frees the caller buffer.
 */
static unsigned char fixed_buffer[8];
static FILE *fixed_stream;
static unsigned fixed_stage;

FILE *crabc_fixed_dso_open(unsigned char **buffer, size_t *capacity,
                            int *main_errno)
{
    static const unsigned char initial[] = {0, '?', '?', '?', '?', '?', '?', '?'};

    if (buffer == NULL || capacity == NULL || main_errno != &errno ||
        errno != EDOM || fixed_stream != NULL || fixed_stage != 0)
        return NULL;
    memset(fixed_buffer, '?', sizeof(fixed_buffer));
    fixed_stream = fmemopen(fixed_buffer, sizeof(fixed_buffer), "w+");
    if (fixed_stream == NULL ||
        memcmp(fixed_buffer, initial, sizeof(initial)) != 0)
        return NULL;
    *buffer = fixed_buffer;
    *capacity = sizeof(fixed_buffer);
    errno = ERANGE;
    return fixed_stream;
}

int crabc_fixed_dso_step(FILE *stream, enum crabc_fixed_dso_stage stage,
                          int *main_errno)
{
    static const unsigned char initial[] = {0, '?', '?', '?', '?', '?', '?', '?'};
    static const unsigned char first[] = {'a', 'b', 'c', 0, '?', '?', '?', '?'};
    static const unsigned char second[] = {'a', 'b', 'c', 'D', 'E', 0, '?', '?'};
    static const unsigned char third[] = {'a', 'b', 'c', 'D', 'E', 'F', 'G', 0};
    char large[1100];

    if (stream == NULL || stream != fixed_stream || main_errno != &errno ||
        errno != EDOM || (unsigned)stage != fixed_stage + 1)
        return 1;
    if (stage == CRABC_FIXED_DSO_FIRST_BUFFERED) {
        if (memcmp(fixed_buffer, initial, sizeof(initial)) != 0 ||
            fflush(stream) != 0 ||
            memcmp(fixed_buffer, first, sizeof(first)) != 0)
            return 2;
    } else if (stage == CRABC_FIXED_DSO_WRITE_DE) {
        if (fwrite("DE", 1, 2, stream) != 2 ||
            memcmp(fixed_buffer, first, sizeof(first)) != 0)
            return 3;
    } else if (stage == CRABC_FIXED_DSO_MAIN_FLUSHED) {
        if (memcmp(fixed_buffer, second, sizeof(second)) != 0)
            return 4;
    } else if (stage == CRABC_FIXED_DSO_APPEND_BUFFERED) {
        if (memcmp(fixed_buffer, second, sizeof(second)) != 0 ||
            fflush(stream) != 0 ||
            memcmp(fixed_buffer, third, sizeof(third)) != 0)
            return 5;
    } else if (stage == CRABC_FIXED_DSO_SHORT_WRITE) {
        memset(large, 'H', sizeof(large));
        if (ftell(stream) != 7 || fwrite(large, 1, sizeof(large), stream) != 1 ||
            errno != EDOM || ferror(stream) != 0 || ftell(stream) != 8 ||
            memcmp(fixed_buffer, "abcDEFGH", sizeof(fixed_buffer)) != 0)
            return 6;
    } else {
        return 7;
    }
    fixed_stage++;
    errno = ERANGE;
    return 0;
}

int crabc_fixed_dso_after_close(int *main_errno)
{
    if (main_errno != &errno || errno != EDOM || fixed_stage != 5 ||
        memcmp(fixed_buffer, "abcDEFGH", sizeof(fixed_buffer)) != 0)
        return 1;
    fixed_stream = NULL;
    fixed_stage++;
    errno = ERANGE;
    return 0;
}

/* The pointer and length slots remain in this image. Main closes the FILE;
 * this image owns and releases the published wide allocation afterward.
 */
static FILE *wide_memory_stream;
static wchar_t *wide_memory_buffer;
static size_t wide_memory_length;
static unsigned wide_memory_stage;

FILE *crabc_wide_memory_dso_open(wchar_t ***buffer_slot, size_t **length_slot,
                                  int *main_errno)
{
    if (buffer_slot == NULL || length_slot == NULL || main_errno != &errno ||
        errno != EDOM || wide_memory_stream != NULL || wide_memory_stage != 0 ||
        sizeof(wchar_t) != 4)
        return NULL;
    wide_memory_stream = open_wmemstream(&wide_memory_buffer, &wide_memory_length);
    if (wide_memory_stream == NULL || wide_memory_buffer == NULL ||
        wide_memory_length != 0 || wide_memory_buffer[0] != 0 ||
        fwide(wide_memory_stream, 0) <= 0)
        return NULL;
    *buffer_slot = &wide_memory_buffer;
    *length_slot = &wide_memory_length;
    errno = ERANGE;
    return wide_memory_stream;
}

int crabc_wide_memory_dso_step(FILE *stream, enum crabc_wide_memory_dso_stage stage,
                                int *main_errno)
{
    static const wchar_t euro[] = {0x20ac, 0};
    static const wchar_t han[] = {0x20ac, 0x4e2d, 0};
    static const wchar_t lambda[] = {0x20ac, 0x03bb, 0};
    static const wchar_t face[] = {0x20ac, 0x03bb, 0x1f600, 0};
    static const wchar_t final[] = {0x20ac, 0x03bb, 0x1f600, 0, 0, 0x03a9, 0};

    if (stream == NULL || stream != wide_memory_stream || main_errno != &errno ||
        errno != EDOM || (unsigned)stage != wide_memory_stage + 1 ||
        wide_memory_buffer == NULL || fwide(stream, 0) <= 0)
        return 1;
    if (stage == CRABC_WIDE_MEMORY_DSO_MAIN_EURO) {
        if (wide_memory_length != 1 ||
            memcmp(wide_memory_buffer, euro, sizeof(euro)) != 0 ||
            fflush(stream) != 0 || wide_memory_length != 1 ||
            memcmp(wide_memory_buffer, euro, sizeof(euro)) != 0)
            return 2;
    } else if (stage == CRABC_WIDE_MEMORY_DSO_WRITE_HAN) {
        if (fputwc((wchar_t)0x4e2d, stream) != 0x4e2d ||
            wide_memory_length != 2 ||
            memcmp(wide_memory_buffer, han, sizeof(han)) != 0)
            return 3;
    } else if (stage == CRABC_WIDE_MEMORY_DSO_MAIN_REWRITE) {
        if (wide_memory_length != 2 ||
            memcmp(wide_memory_buffer, lambda, sizeof(lambda)) != 0 ||
            fflush(stream) != 0 ||
            memcmp(wide_memory_buffer, lambda, sizeof(lambda)) != 0)
            return 4;
    } else if (stage == CRABC_WIDE_MEMORY_DSO_APPEND_FACE) {
        if (fseek(stream, 0, SEEK_END) != 0 ||
            fputwc((wchar_t)0x1f600, stream) != 0x1f600 ||
            wide_memory_length != 3 ||
            memcmp(wide_memory_buffer, face, sizeof(face)) != 0)
            return 5;
    } else if (stage == CRABC_WIDE_MEMORY_DSO_MAIN_GAP) {
        if (wide_memory_length != 6 ||
            memcmp(wide_memory_buffer, final, sizeof(final)) != 0 ||
            fflush(stream) != 0 ||
            memcmp(wide_memory_buffer, final, sizeof(final)) != 0)
            return 6;
    } else {
        return 7;
    }
    wide_memory_stage++;
    errno = ERANGE;
    return 0;
}

int crabc_wide_memory_dso_release(int *main_errno)
{
    static const wchar_t final[] = {0x20ac, 0x03bb, 0x1f600, 0, 0, 0x03a9, 0};

    if (main_errno != &errno || errno != EDOM || wide_memory_stage != 5 ||
        wide_memory_buffer == NULL || wide_memory_length != 6 ||
        memcmp(wide_memory_buffer, final, sizeof(final)) != 0)
        return 1;
    free(wide_memory_buffer);
    wide_memory_buffer = NULL;
    wide_memory_length = 0;
    wide_memory_stream = NULL;
    wide_memory_stage++;
    errno = ERANGE;
    return 0;
}

/* Both pathname streams join the same global list. The DSO owns this FILE
 * and buffer, while the executable retains its own FILE through both flushes.
 */
static FILE *global_dso_stream;
static char global_dso_buffer[64];
static int global_dso_descriptor;
static unsigned global_dso_stage;

static int global_dso_sizes(FILE *main_stream, off_t main_size, off_t dso_size)
{
    struct stat main_state, dso_state;

    return fstat(fileno(main_stream), &main_state) == 0 &&
        fstat(global_dso_descriptor, &dso_state) == 0 &&
        main_state.st_size == main_size && dso_state.st_size == dso_size &&
        ferror(main_stream) == 0 && ferror(global_dso_stream) == 0 &&
        feof(main_stream) == 0 && feof(global_dso_stream) == 0;
}

int crabc_global_dso_buffer(FILE *main_stream, const char *path, int *main_errno)
{
    if (main_stream == NULL || path == NULL || main_errno != &errno ||
        errno != EDOM || global_dso_stage != 0 || ferror(main_stream))
        return 1;
    global_dso_stream = fopen(path, "w");
    if (global_dso_stream == NULL ||
        setvbuf(global_dso_stream, global_dso_buffer, _IOFBF,
                sizeof(global_dso_buffer)) != 0)
        return 2;
    global_dso_descriptor = fileno(global_dso_stream);
    if (global_dso_descriptor < 0 ||
        fwrite("dso-before\n", 1, 11, global_dso_stream) != 11 ||
        !global_dso_sizes(main_stream, 0, 0))
        return 3;
    global_dso_stage = 1;
    errno = ERANGE;
    return 0;
}

int crabc_global_dso_flush(FILE *main_stream, int *main_errno)
{
    if (main_stream == NULL || main_errno != &errno || errno != EDOM ||
        global_dso_stage != 1 || !global_dso_sizes(main_stream, 0, 0))
        return 1;
    if (fflush(NULL) != 0 || !global_dso_sizes(main_stream, 12, 11))
        return 2;
    global_dso_stage = 2;
    errno = ERANGE;
    return 0;
}

int crabc_global_dso_tail(FILE *main_stream, int *main_errno)
{
    if (main_stream == NULL || main_errno != &errno || errno != EDOM ||
        global_dso_stage != 2 || !global_dso_sizes(main_stream, 12, 11))
        return 1;
    if (fwrite("dso-after\n", 1, 10, global_dso_stream) != 10 ||
        !global_dso_sizes(main_stream, 12, 11))
        return 2;
    global_dso_stage = 3;
    errno = ERANGE;
    return 0;
}

int crabc_global_dso_after_second(FILE *main_stream, int *main_errno)
{
    if (main_stream == NULL || main_errno != &errno || errno != EDOM ||
        global_dso_stage != 3 || !global_dso_sizes(main_stream, 23, 21))
        return 1;
    if (fcntl(fileno(main_stream), F_GETFD) < 0 ||
        fcntl(global_dso_descriptor, F_GETFD) < 0)
        return 2;
    global_dso_stage = 4;
    errno = ERANGE;
    return 0;
}

int crabc_global_dso_close(int *main_errno)
{
    if (main_errno != &errno || errno != EDOM || global_dso_stage != 4 ||
        global_dso_stream == NULL ||
        fcntl(global_dso_descriptor, F_GETFD) < 0)
        return 1;
    if (fclose(global_dso_stream) != 0)
        return 2;
    global_dso_stream = NULL;
    errno = 0;
    if (fcntl(global_dso_descriptor, F_GETFD) != -1 || errno != EBADF)
        return 3;
    global_dso_stage = 5;
    errno = ERANGE;
    return 0;
}

/* The executable owns the first FILE. This image selects wide orientation
 * before either image performs I/O, and its caller remains the close owner.
 */
int crabc_orientation_dso_set_wide(FILE *stream, int *main_errno)
{
    if (stream == NULL || main_errno != &errno || errno != EDOM ||
        fwide(stream, 0) != 0 || ferror(stream) || feof(stream))
        return 1;
    if (fwide(stream, 1) <= 0 || fwide(stream, -1) <= 0 ||
        fputwc((wchar_t)0x20ac, stream) != 0x20ac || ferror(stream))
        return 2;
    errno = ERANGE;
    return 0;
}

/* This FILE and descriptor belong to the DSO. Main chooses byte orientation
 * after open, then both images use only byte I/O until this image closes it.
 */
static FILE *orientation_dso_byte_stream;
static int orientation_dso_byte_descriptor;

FILE *crabc_orientation_dso_open_byte(const char *path, int *main_errno)
{
    if (path == NULL || main_errno != &errno || errno != EDOM ||
        orientation_dso_byte_stream != NULL)
        return NULL;
    orientation_dso_byte_stream = fopen(path, "w+");
    if (orientation_dso_byte_stream == NULL ||
        fwide(orientation_dso_byte_stream, 0) != 0)
        return NULL;
    orientation_dso_byte_descriptor = fileno(orientation_dso_byte_stream);
    if (orientation_dso_byte_descriptor < 0)
        return NULL;
    errno = ERANGE;
    return orientation_dso_byte_stream;
}

int crabc_orientation_dso_use_byte(FILE *stream, int *main_errno)
{
    if (stream == NULL || stream != orientation_dso_byte_stream ||
        main_errno != &errno || errno != EDOM || fwide(stream, 0) >= 0 ||
        fwide(stream, 1) >= 0 || ferror(stream) || feof(stream))
        return 1;
    if (fwrite("dso", 1, 3, stream) != 3 || fflush(stream) != 0 ||
        ferror(stream))
        return 2;
    errno = ERANGE;
    return 0;
}

int crabc_orientation_dso_close_byte(FILE *stream, int *main_errno)
{
    if (stream == NULL || stream != orientation_dso_byte_stream ||
        main_errno != &errno || errno != EDOM || fwide(stream, 0) >= 0 ||
        ferror(stream) || fcntl(orientation_dso_byte_descriptor, F_GETFD) < 0)
        return 1;
    if (fclose(stream) != 0)
        return 2;
    orientation_dso_byte_stream = NULL;
    errno = 0;
    if (fcntl(orientation_dso_byte_descriptor, F_GETFD) != -1 || errno != EBADF)
        return 3;
    errno = ERANGE;
    return 0;
}

/* A device that rejects every write keeps failure injection independent of
 * filesystem capacity. This image owns the buffered FILE through its close.
 */
static FILE *full_dso_stream;
static char full_dso_buffer[64];
static int full_dso_descriptor;
static unsigned full_dso_stage;

FILE *crabc_full_dso_open(int *main_errno)
{
    if (main_errno != &errno || errno != EDOM || full_dso_stage != 0)
        return NULL;
    full_dso_stream = fopen("/dev/full", "w");
    if (full_dso_stream == NULL ||
        setvbuf(full_dso_stream, full_dso_buffer, _IOFBF,
                sizeof(full_dso_buffer)) != 0)
        return NULL;
    full_dso_descriptor = fileno(full_dso_stream);
    if (full_dso_descriptor < 0 ||
        fwrite("pending", 1, 7, full_dso_stream) != 7 ||
        ferror(full_dso_stream) || feof(full_dso_stream) ||
        fcntl(full_dso_descriptor, F_GETFD) < 0)
        return NULL;
    full_dso_stage = 1;
    errno = ERANGE;
    return full_dso_stream;
}

int crabc_full_dso_close(FILE *stream, int *main_errno)
{
    if (stream == NULL || stream != full_dso_stream ||
        main_errno != &errno || errno != EDOM || full_dso_stage != 1 ||
        !ferror(stream) || feof(stream) ||
        fcntl(full_dso_descriptor, F_GETFD) < 0)
        return 1;
    if (fclose(stream) != 0 || errno != EDOM)
        return 2;
    full_dso_stream = NULL;
    full_dso_stage = 2;
    errno = 0;
    if (fcntl(full_dso_descriptor, F_GETFD) != -1 || errno != EBADF)
        return 3;
    errno = ERANGE;
    return 0;
}

/* A separate stream reaches the full device for the first time in fclose.
 * Return the close result and errno directly to the executable.
 */
static FILE *pending_close_dso_stream;
static char pending_close_dso_buffer[64];
static unsigned pending_close_dso_stage;

FILE *crabc_full_dso_open_pending_close(int *main_errno)
{
    if (main_errno != &errno || errno != EDOM || pending_close_dso_stage != 0)
        return NULL;
    pending_close_dso_stream = fopen("/dev/full", "w");
    if (pending_close_dso_stream == NULL ||
        setvbuf(pending_close_dso_stream, pending_close_dso_buffer, _IOFBF,
                sizeof(pending_close_dso_buffer)) != 0)
        return NULL;
    if (fileno(pending_close_dso_stream) < 0 ||
        fwrite("closing", 1, 7, pending_close_dso_stream) != 7 ||
        ferror(pending_close_dso_stream) || feof(pending_close_dso_stream))
        return NULL;
    pending_close_dso_stage = 1;
    errno = ERANGE;
    return pending_close_dso_stream;
}

int crabc_full_dso_close_pending(FILE *stream, int *main_errno)
{
    int result;

    if (stream == NULL || stream != pending_close_dso_stream ||
        main_errno != &errno || errno != EDOM || pending_close_dso_stage != 1 ||
        ferror(stream) || feof(stream))
        return 1;
    result = fclose(stream);
    pending_close_dso_stream = NULL;
    pending_close_dso_stage = 2;
    return result;
}

/* The first failed flush discards buffered bytes. Clearing the shared FILE
 * error permits a clean retry and a later buffered write from this image.
 */
static FILE *recovery_dso_stream;
static char recovery_dso_buffer[64];
static unsigned recovery_dso_stage;

FILE *crabc_full_dso_open_recovery(int *main_errno)
{
    if (main_errno != &errno || errno != EDOM || recovery_dso_stage != 0)
        return NULL;
    recovery_dso_stream = fopen("/dev/full", "w");
    if (recovery_dso_stream == NULL ||
        setvbuf(recovery_dso_stream, recovery_dso_buffer, _IOFBF,
                sizeof(recovery_dso_buffer)) != 0)
        return NULL;
    if (fileno(recovery_dso_stream) < 0 ||
        fwrite("first", 1, 5, recovery_dso_stream) != 5 ||
        ferror(recovery_dso_stream) || feof(recovery_dso_stream))
        return NULL;
    recovery_dso_stage = 1;
    errno = ERANGE;
    return recovery_dso_stream;
}

int crabc_full_dso_write_recovery(FILE *stream, int *main_errno)
{
    if (stream == NULL || stream != recovery_dso_stream ||
        main_errno != &errno || errno != EDOM || recovery_dso_stage != 1 ||
        ferror(stream) || feof(stream))
        return 1;
    if (fwrite("second", 1, 6, stream) != 6 || ferror(stream))
        return 2;
    recovery_dso_stage = 2;
    errno = ERANGE;
    return 0;
}

int crabc_full_dso_close_recovery(FILE *stream, int *main_errno)
{
    int result;

    if (stream == NULL || stream != recovery_dso_stream ||
        main_errno != &errno || errno != EDOM || recovery_dso_stage != 2 ||
        ferror(stream) || feof(stream))
        return 1;
    result = fclose(stream);
    recovery_dso_stream = NULL;
    recovery_dso_stage = 3;
    return result;
}

/* The DSO owns this pathname stream while main changes its pushback and
 * logical position. Reading here must observe the same FILE state.
 */
static FILE *pushback_dso_stream;
static char pushback_dso_buffer[64];
static unsigned pushback_dso_stage;

FILE *crabc_pushback_dso_open(const char *path, int *main_errno)
{
    if (path == NULL || main_errno != &errno || errno != EDOM ||
        pushback_dso_stage != 0)
        return NULL;
    pushback_dso_stream = fopen(path, "w+");
    if (pushback_dso_stream == NULL ||
        setvbuf(pushback_dso_stream, pushback_dso_buffer, _IOFBF,
                sizeof(pushback_dso_buffer)) != 0 ||
        fwrite("abcdef", 1, 6, pushback_dso_stream) != 6 ||
        fflush(pushback_dso_stream) != 0 ||
        fseek(pushback_dso_stream, 0, SEEK_SET) != 0 ||
        ftell(pushback_dso_stream) != 0 ||
        ferror(pushback_dso_stream) || feof(pushback_dso_stream))
        return NULL;
    pushback_dso_stage = 1;
    errno = ERANGE;
    return pushback_dso_stream;
}

int crabc_pushback_dso_consume(FILE *stream, int *main_errno)
{
    if (stream == NULL || stream != pushback_dso_stream ||
        main_errno != &errno || errno != EDOM || pushback_dso_stage != 1 ||
        feof(stream) || ferror(stream) || ftell(stream) != 5)
        return 1;
    if (fgetc(stream) != 'Q' || ftell(stream) != 6 ||
        feof(stream) || ferror(stream) || errno != EDOM)
        return 2;
    pushback_dso_stage = 2;
    errno = ERANGE;
    return 0;
}

int crabc_pushback_dso_close(FILE *stream, int *main_errno)
{
    if (stream == NULL || stream != pushback_dso_stream ||
        main_errno != &errno || errno != EDOM || pushback_dso_stage != 2 ||
        ftell(stream) != 5 || feof(stream) || ferror(stream))
        return 1;
    if (fgetc(stream) != 'f' || ftell(stream) != 6 ||
        feof(stream) || ferror(stream) || errno != EDOM)
        return 2;
    if (fclose(stream) != 0 || errno != EDOM)
        return 3;
    pushback_dso_stream = NULL;
    pushback_dso_stage = 3;
    errno = ERANGE;
    return 0;
}

/* The executable's main thread holds this DSO-owned stream while a worker
 * observes contention. Each thread releases only locks it acquired itself.
 */
static FILE *lock_dso_stream;
static char lock_dso_buffer[64];

FILE *crabc_lock_dso_open(const char *path, int *main_errno)
{
    if (path == NULL || main_errno != &errno || errno != EDOM ||
        lock_dso_stream != NULL)
        return NULL;
    lock_dso_stream = fopen(path, "w");
    if (lock_dso_stream == NULL ||
        setvbuf(lock_dso_stream, lock_dso_buffer, _IOFBF,
                sizeof(lock_dso_buffer)) != 0 ||
        fileno(lock_dso_stream) < 0 ||
        ferror(lock_dso_stream) || feof(lock_dso_stream))
        return NULL;
    errno = ERANGE;
    return lock_dso_stream;
}

int crabc_lock_dso_try_busy(FILE *stream, int *worker_errno)
{
    int result;

    if (stream == NULL || stream != lock_dso_stream ||
        worker_errno != &errno || errno != EDOM)
        return 1;
    result = ftrylockfile(stream);
    if (result == 0) {
        funlockfile(stream);
        return 2;
    }
    if (result != -1 || errno != EDOM)
        return 3;
    errno = ERANGE;
    return 0;
}

int crabc_lock_dso_write_unlock(FILE *stream, int *main_errno)
{
    struct stat state;
    int valid;

    if (stream == NULL || stream != lock_dso_stream ||
        main_errno != &errno || errno != EDOM)
        return 1;
    if (ftrylockfile(stream) != 0 || errno != EDOM) {
        funlockfile(stream);
        return 2;
    }
    valid = fwrite("main-", 1, 5, stream) == 5 &&
        fstat(fileno(stream), &state) == 0 && state.st_size == 0 &&
        !ferror(stream) && !feof(stream) && errno == EDOM;
    funlockfile(stream);
    funlockfile(stream);
    if (!valid || errno != EDOM)
        return 3;
    errno = ERANGE;
    return 0;
}

int crabc_lock_dso_worker_write(FILE *stream, int *worker_errno)
{
    int valid;

    if (stream == NULL || stream != lock_dso_stream ||
        worker_errno != &errno || errno != EDOM)
        return 1;
    if (ftrylockfile(stream) != 0 || errno != EDOM)
        return 2;
    valid = fwrite("worker", 1, 6, stream) == 6 &&
        !ferror(stream) && !feof(stream) && errno == EDOM;
    funlockfile(stream);
    if (!valid)
        return 3;
    if (fflush(stream) != 0 || ferror(stream) || feof(stream) || errno != EDOM)
        return 4;
    errno = ERANGE;
    return 0;
}

int crabc_lock_dso_close(FILE *stream, int *main_errno)
{
    if (stream == NULL || stream != lock_dso_stream ||
        main_errno != &errno || errno != EDOM ||
        ferror(stream) || feof(stream))
        return 1;
    if (fclose(stream) != 0 || errno != EDOM)
        return 2;
    lock_dso_stream = NULL;
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
