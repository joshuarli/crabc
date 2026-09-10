/*
 * One installed-header stdio composition object.
 *
 * The byte and wide cases use distinct live FILE objects.  The byte object
 * crosses caller-buffered output, a seek/read/fsetpos/write direction change,
 * stream printf/scanf, EOF and a deterministic wrong-direction error, then
 * `freopen`.  The wide object fixes C.UTF-8 and remains independently wide
 * oriented.  A third byte FILE adopts one descriptor, while a duplicate proves
 * that closing the adopted FILE retires only its transferred descriptor.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <stdio.h>
#include <unistd.h>
#include <wchar.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(long) == 8, "x86-64 LP64 stream positions");
_Static_assert(sizeof(wchar_t) == 4, "installed wide FILE code units");

static int equal_bytes(const char *actual, const char *expected, size_t count)
{
    size_t index;

    for (index = 0; index != count; ++index)
        if (actual[index] != expected[index])
            return 0;
    return 1;
}

static int byte_stream(const char *first, const char *second)
{
    static const char initial[] = "prefix 42 word\ntail";
    static const char final[] = "prefix 42 word\ntail!";
    char caller_buffer[64];
    char line[32];
    char prefix[7] = { 0 };
    char word[8] = { 0 };
    char copied[sizeof(final) - 1U];
    FILE *stream;
    FILE *read_only;
    FILE *adopted;
    fpos_t saved;
    int adopted_descriptor;
    int surviving_descriptor;
    int number = 0;
    int descriptor;

    (void)unlink(first);
    (void)unlink(second);
    stream = fopen(first, "w+");
    if (stream == NULL || setvbuf(stream, caller_buffer, _IOFBF, sizeof(caller_buffer)) != 0)
        return 1;
    if (fputs("prefix ", stream) < 0 || fprintf(stream, "%d %s\n", 42, "word") != 8 ||
        fwrite("tail", 1, 4, stream) != 4 || ftell(stream) != 19 ||
        (descriptor = fileno(stream)) < 0 || lseek(descriptor, 0, SEEK_CUR) != 0 ||
        fgetpos(stream, &saved) != 0)
        return 2;

    /* fseek flushes buffered output.  fsetpos returns from byte input to
     * saved output before this final byte is written. */
    if (fseek(stream, 0, SEEK_SET) != 0 || fread(copied, 1, 7, stream) != 7 ||
        !equal_bytes(copied, "prefix ", 7) || ftell(stream) != 7 ||
        fsetpos(stream, &saved) != 0 || fputc('!', stream) != '!' ||
        ftell(stream) != 20 || fseek(stream, 0, SEEK_SET) != 0)
        return 3;
    if (fgets(line, sizeof(line), stream) != line ||
        !equal_bytes(line, "prefix 42 word\n", 16) || fseek(stream, 0, SEEK_SET) != 0 ||
        fscanf(stream, "%6s %d %7s", prefix, &number, word) != 3 ||
        !equal_bytes(prefix, "prefix", 7) || number != 42 || !equal_bytes(word, "word", 5) ||
        fgetc(stream) != '\n' || fgets(line, sizeof(line), stream) != line ||
        !equal_bytes(line, "tail!", 6) || fgetc(stream) != EOF || !feof(stream) ||
        ferror(stream) != 0)
        return 4;
    clearerr(stream);
    if (feof(stream) != 0 || ferror(stream) != 0 ||
        freopen(second, "w+", stream) != stream)
        return 5;
    if (fileno(stream) != descriptor || fputs("reopened\n", stream) < 0 ||
        fseek(stream, 0, SEEK_SET) != 0 || fgets(line, sizeof(line), stream) != line ||
        !equal_bytes(line, "reopened\n", 10) || fclose(stream) != 0)
        return 6;

    read_only = fopen(first, "r");
    if (read_only == NULL)
        return 7;
    /* owned_static_stdio::write_byte_held matches musl's direction error:
     * it makes F_ERR sticky without replacing the caller's errno. */
    errno = EAGAIN;
    if (fputc('x', read_only) != EOF || !ferror(read_only) || errno != EAGAIN)
        return 8;
    clearerr(read_only);
    if (ferror(read_only) != 0 || fclose(read_only) != 0)
        return 9;

    adopted_descriptor = open(first, O_RDONLY);
    if (adopted_descriptor < 0)
        return 10;
    surviving_descriptor = dup(adopted_descriptor);
    adopted = fdopen(adopted_descriptor, "r");
    if (surviving_descriptor < 0 || adopted == NULL || fgetc(adopted) != 'p' ||
        fclose(adopted) != 0)
        return 11;
    errno = 0;
    if (fcntl(adopted_descriptor, F_GETFD) != -1 || errno != EBADF ||
        read(surviving_descriptor, copied, 1) != 1 || copied[0] != 'r' ||
        close(surviving_descriptor) != 0)
        return 12;

    if (unlink(first) != 0 || unlink(second) != 0)
        return 13;
    return 0;
}

static int wide_stream(const char *path)
{
    wchar_t line[3];
    FILE *stream;

    (void)unlink(path);
    if (setlocale(LC_CTYPE, "C.UTF-8") == NULL)
        return 20;
    stream = fopen(path, "w+");
    if (stream == NULL || fwide(stream, 0) != 0 || fwide(stream, 1) <= 0 ||
        fwide(stream, -1) <= 0)
        return 21;
    if (fputwc(0x20ac, stream) != 0x20ac || fputws(L"\U0001f642\n", stream) < 0 ||
        fflush(stream) != 0 || ftell(stream) != 8 || fseek(stream, 0, SEEK_SET) != 0)
        return 22;
    if (fgetwc(stream) != 0x20ac || ungetwc(0x20ac, stream) != 0x20ac ||
        fgetwc(stream) != 0x20ac || fgetws(line, 3, stream) != line ||
        line[0] != 0x1f642 || line[1] != L'\n' || line[2] != L'\0' ||
        fgetwc(stream) != WEOF || !feof(stream) || ferror(stream) != 0)
        return 23;
    if (ungetwc(L'X', stream) != L'X' || feof(stream) != 0 ||
        fgetwc(stream) != L'X' || fclose(stream) != 0 || unlink(path) != 0)
        return 24;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4)
        return 80;
    if (byte_stream(argv[1], argv[2]) != 0)
        return 81;
    if (wide_stream(argv[3]) != 0)
        return 82;
    puts("owned-stdio-products-ok");
    return 0;
}
