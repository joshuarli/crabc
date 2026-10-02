#define _GNU_SOURCE
#include <stdio.h>
#include <stdio_ext.h>
#include <wchar.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

struct callback_state { int reads, closes; FILE *other; };

static ssize_t cookie_read(void *opaque, char *destination, size_t length)
{
    struct callback_state *state = opaque;
    state->reads++;
    if (fputs("r", state->other) < 0) return -1;
    if (state->reads == 1 && length) { *destination = 'X'; return 1; }
    return 0;
}

static int cookie_close(void *opaque)
{
    struct callback_state *state = opaque;
    state->closes++;
    if (fputs("c", state->other) < 0) return -1;
    return fclose(state->other);
}

static int callback_pushback(void)
{
    char *output;
    size_t size;
    struct callback_state state = {0};
    state.other = open_memstream(&output, &size);
    if (!state.other) return 80;
    cookie_io_functions_t functions = { cookie_read, NULL, NULL, cookie_close };
    FILE *stream = fopencookie(&state, "r", functions);
    if (!stream) return 81;
    for (int i = 0; i < 9; i++)
        if (ungetc('a' + i, stream) != 'a' + i) return 82;
    for (int i = 8; i >= 0; i--)
        if (fgetc(stream) != 'a' + i) return 83;
    if (state.reads || fgetc(stream) != 'X' || state.reads != 1) return 84;
    if (fgetc(stream) != EOF || state.reads != 2 || !feof(stream)) return 85;
    /* The close callback can retire another live FILE. Neither callback
     * dispatch nor retirement may retain the global FILE registry lock.
     */
    if (fclose(stream) || state.closes != 1 || size != 3
        || memcmp(output, "rrc", 3)) return 86;
    free(output);
    return 0;
}

static int byte_pushback(int buffering, int reset)
{
    char input[] = "XY", buffer[16];
    FILE *stream = fmemopen(input, reset == 4 ? 2 : 1, "r");
    if (!stream) return 10;
    if (buffering == 1 && setvbuf(stream, buffer, _IOFBF, sizeof buffer)) return 11;
    if (buffering == 2 && setvbuf(stream, NULL, _IONBF, 0)) return 12;
    if (reset) {
        if (fgetc(stream) != 'X') return 13;
        if (reset == 1 && fseek(stream, 0, SEEK_SET)) return 14;
        if (reset == 2 && __fpurge(stream)) return 15;
        if (reset == 3 && fflush(stream)) return 16;
    }
    /* The fourth variant retains active lookahead: read admission must leave
     * its region intact while pushback uses the reserve preceding that region.
     */
    /* Before backend input, musl places the empty read region at the buffer
     * end. Pushback can use both configured storage and the eight reserve
     * bytes. An unbuffered stream still has those eight reserve bytes.
     */
    int count = buffering == 2 || reset == 4 ? 8 : buffering == 1 ? 16 : 9;
    for (int i = 0; i < count; i++)
        if (ungetc('a' + i, stream) != 'a' + i) return 20 + i;
    if ((buffering || reset == 4) && ungetc('!', stream) != EOF) return 40;
    for (int i = count - 1; i >= 0; i--)
        if (fgetc(stream) != 'a' + i) return 41;
    if (reset == 4 && fgetc(stream) != 'Y') return 42;
    if (__freadahead(stream)) return 42;
    if ((!reset || reset == 1) && fgetc(stream) != 'X') return 43;
    if (fgetc(stream) != EOF || !feof(stream) || ferror(stream)) return 44;
    if (fclose(stream)) return 45;
    return 0;
}

static int wide_pushback(int buffering, int reset)
{
    char input[] = "XY", buffer[16];
    FILE *stream = fmemopen(input, reset == 4 ? 2 : 1, "r");
    if (!stream) return 50;
    if (buffering == 1 && setvbuf(stream, buffer, _IOFBF, sizeof buffer)) return 51;
    if (buffering == 2 && setvbuf(stream, NULL, _IONBF, 0)) return 52;
    if (fwide(stream, 1) <= 0) return 53;
    if (reset) {
        if (fgetwc(stream) != L'X') return 54;
        if (reset == 1 && fseek(stream, 0, SEEK_SET)) return 55;
        if (reset == 2 && __fpurge(stream)) return 56;
        if (reset == 3 && fflush(stream)) return 57;
    }
    int count = buffering == 2 || reset == 4 ? 2 : buffering == 1 ? 4 : 3;
    for (int i = 0; i < count; i++)
        if (ungetwc(0x10000 + i, stream) != (wint_t)(0x10000 + i)) return 60 + i;
    if ((buffering || reset == 4) && ungetwc(0x10010, stream) != WEOF) return 70;
    for (int i = count - 1; i >= 0; i--)
        if (fgetwc(stream) != (wint_t)(0x10000 + i)) return 71;
    if (reset == 4 && fgetwc(stream) != L'Y') return 72;
    if (__freadahead(stream) || fwide(stream, 0) <= 0) return 72;
    if ((!reset || reset == 1) && fgetwc(stream) != L'X') return 73;
    if (fgetwc(stream) != WEOF || !feof(stream) || ferror(stream)) return 74;
    if (fclose(stream)) return 75;
    return 0;
}

int crabc_stdio_initial_pushback_regression(void)
{
    if (!setlocale(LC_CTYPE, "C.UTF-8")) return 1;
    for (int buffering = 0; buffering < 3; buffering++)
        for (int reset = 0; reset < 5; reset++) {
            int result = byte_pushback(buffering, reset);
            if (result) return result;
            result = wide_pushback(buffering, reset);
            if (result) return result;
        }
    return callback_pushback();
}

#ifndef CRABC_NATIVE_ENTRY
int main(void) { return crabc_stdio_initial_pushback_regression(); }
#endif
