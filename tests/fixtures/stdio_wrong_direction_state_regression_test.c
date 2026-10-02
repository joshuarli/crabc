#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

struct cookie_output { char bytes[32]; size_t length; };

static ssize_t cookie_write(void *opaque, const char *bytes, size_t length)
{
    struct cookie_output *output = opaque;
    if (length > sizeof output->bytes - output->length) return -1;
    memcpy(output->bytes + output->length, bytes, length);
    output->length += length;
    return (ssize_t)length;
}

/* A rejected read drains pending output but never opens a readable region.
 * Its sticky error does not stop clearerr followed by ordinary output. */
static int one_case(int backend, int operation, int pending)
{
    const char *path = ".work/stdio-wrong-direction-state-regression";
    char memory[32] = {0};
    struct cookie_output cookie = {{0}, 0};
    cookie_io_functions_t functions = {0, cookie_write, 0, 0};
    FILE *stream = backend == 0 ? fopen(path, "w")
        : backend == 1 ? fmemopen(memory, sizeof memory, "w")
        : fopencookie(&cookie, "w", functions);
    if (!stream) return 1;
    int wide = operation >= 4;
    if (pending && (wide ? fputwc('A', stream) == WEOF : fputc('A', stream) == EOF)) return 2;
    char bytes[8] = {0};
    wchar_t wide_bytes[8] = {0};
    char *line = NULL;
    size_t capacity = 0;
    errno = ENOSPC;
    int rejected;
    switch (operation) {
    case 0: rejected = fgetc(stream) == EOF; break;
    case 1: rejected = fread(bytes, 1, sizeof bytes, stream) == 0; break;
    case 2: rejected = fgets(bytes, sizeof bytes, stream) == NULL; break;
    case 3: rejected = getline(&line, &capacity, stream) == -1; break;
    case 4: rejected = fgetwc(stream) == WEOF; break;
    case 5: rejected = fgetws(wide_bytes, 8, stream) == NULL; break;
    default: rejected = fwscanf(stream, L"%lc", wide_bytes) == EOF; break;
    }
    int saved_errno = errno;
    int reading = !!__freading(stream), writing = !!__fwriting(stream);
    int error = !!ferror(stream), end = !!feof(stream);
    size_t buffered = __fpending(stream);
    char transcript[128];
    int count = snprintf(transcript, sizeof transcript, "%d %d %d: %d %d %d %d %d %d %zu\n",
        backend, operation, pending, rejected, reading, writing, error, end, saved_errno, buffered);
    if (count < 0 || write(1, transcript, (size_t)count) != count) return 3;
    int failed = !rejected || reading || !writing || !error || end || saved_errno != ENOSPC || buffered;
    free(line);
    clearerr(stream);
    if (wide ? fputwc('Z', stream) == WEOF : fputc('Z', stream) == EOF) return 4;
    if (fclose(stream)) return 5;
    char actual[32] = {0};
    size_t length;
    if (backend == 0) {
        int descriptor = open(path, O_RDONLY);
        ssize_t received = descriptor < 0 ? -1 : read(descriptor, actual, sizeof actual);
        if (descriptor < 0 || received < 0 || close(descriptor) || unlink(path)) return 6;
        length = (size_t)received;
    } else if (backend == 1) {
        length = strlen(memory);
        memcpy(actual, memory, length);
    } else {
        length = cookie.length;
        memcpy(actual, cookie.bytes, length);
    }
    if (length != (size_t)(pending + 1) || memcmp(actual, pending ? "AZ" : "Z", length)) return 7;
    return failed;
}

int crabc_stdio_wrong_direction_state_regression(void)
{
    int failed = 0;
    for (int backend = 0; backend < 3; backend++)
        for (int operation = 0; operation < 7; operation++)
            for (int pending = 0; pending < 2; pending++)
                failed |= one_case(backend, operation, pending);
    return failed;
}

#ifndef CRABC_NATIVE_ENTRY
int main(void) { return crabc_stdio_wrong_direction_state_regression(); }
#endif
