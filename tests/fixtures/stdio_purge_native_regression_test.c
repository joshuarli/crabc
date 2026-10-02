#define _GNU_SOURCE
#include <stdio.h>
#include <stdio_ext.h>
#include <wchar.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#ifdef CRABC_NATIVE_FILE_INVARIANTS
/* Copy the native repr(C) header prefix rather than aliasing opaque FILE
 * storage. A neutral stream may have null inactive regions, or initialized
 * regions in its buffer; purging must never manufacture pointers from null.
 * This assertion is private to the native engine, not an installed FILE ABI.
 */
struct native_prefix {
    uint32_t flags;
    int descriptor, pipe_pid;
    signed char orientation;
    unsigned char wide_locale, direction;
    char *getln_buffer;
    unsigned char *buffer;
    size_t capacity;
    unsigned char *read_position, *read_end;
    unsigned char *write_base, *write_position, *write_end;
};

static int empty_region_is_backed(FILE *stream)
{
    struct native_prefix state;
    memcpy(&state, stream, sizeof state);
    if (!state.buffer)
        return !state.read_position && !state.read_end && !state.write_base
            && !state.write_position && !state.write_end;
    return state.read_position == state.buffer && state.read_end == state.buffer
        && state.write_base == state.buffer && state.write_position == state.buffer
        && (uintptr_t)state.write_end == (uintptr_t)state.buffer + state.capacity;
}
#endif

int crabc_stdio_purge_native_regression(void)
{
    FILE *permanent[] = { stdin, stdout, stderr };
    /* These must be the first FILE operations, while permanent buffers are
     * still lazy. In particular, do not report failures through stdio.
     */
    for (size_t i = 0; i < 3; i++) {
        errno = 123;
        if (__fpurge(permanent[i]) || errno != 123) return 10 + i;
#ifdef CRABC_NATIVE_FILE_INVARIANTS
        if (!empty_region_is_backed(permanent[i])) return 40 + i;
#endif
        if (fwide(permanent[i], 0) || __fpending(permanent[i])
            || __freadahead(permanent[i])) return 20 + i;
    }

    int input[2], output[2];
    if (pipe(input) || pipe(output)) return 50;
    if (write(input[1], "BC", 2) != 2 || close(input[1])
        || dup2(input[0], 0) != 0 || close(input[0])) return 51;
    if (ungetc('A', stdin) != 'A' || fgetc(stdin) != 'A'
        || fgetc(stdin) != 'B' || __freadahead(stdin) != 1) return 52;
    if (__fpurge(stdin) || fgetc(stdin) != EOF || !feof(stdin)) return 53;
    __fseterr(stdin);
    if (__fpurge(stdin) || !feof(stdin) || !ferror(stdin)) return 54;
    clearerr(stdin);
    if (ungetc('Z', stdin) != 'Z' || fgetc(stdin) != 'Z') return 55;

    if (dup2(output[1], 1) != 1 || close(output[1])) return 60;
    if (fwide(stdout, 1) <= 0 || fputwc(L'A', stdout) != L'A'
        || __fpending(stdout) != 1) return 61;
    if (__fpurge(stdout) || __fpending(stdout) || fwide(stdout, 0) <= 0
        || fputwc(L'B', stdout) != L'B' || fflush(stdout)) return 62;
    char byte;
    if (read(output[0], &byte, 1) != 1 || byte != 'B') return 63;
    if (close(output[0])) return 64;
    return 0;
}

#ifndef CRABC_NATIVE_ENTRY
int main(void) { return crabc_stdio_purge_native_regression(); }
#endif
