#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

extern int __isoc99_vsscanf(const char *, const char *, va_list);
extern int __isoc99_vfscanf(FILE *, const char *, va_list);
extern int __isoc99_sscanf(const char *, const char *, ...);
extern int __isoc99_fscanf(FILE *, const char *, ...);
extern int __isoc99_swscanf(const wchar_t *, const wchar_t *, ...);
extern int __isoc99_fwscanf(FILE *, const wchar_t *, ...);
extern int __uflow(FILE *);
extern int __flbf(FILE *);
extern size_t __fpending(FILE *);

static int call_isoc99_vsscanf(const char *input, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int result = __isoc99_vsscanf(input, fmt, args);
    va_end(args);
    return result;
}

static int call_isoc99_vfscanf(FILE *stream, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int result = __isoc99_vfscanf(stream, fmt, args);
    va_end(args);
    return result;
}

int main(void) {
    FILE *stream = tmpfile();
    if (!stream) return 1;

    if (fputs_unlocked("xy\nrest", stream) < 0) return 2;
    if (fputc_unlocked('!', stream) != '!') return 3;
    if (putc_unlocked('?', stream) != '?') return 4;
    if (fflush(stream) != 0) return 5;
    rewind(stream);

    if (fgetc_unlocked(stream) != 'x') return 6;
    if (getc_unlocked(stream) != 'y') return 7;
    if (fgetc_unlocked(stream) != '\n') return 8;
    {
        char line[16];
        if (!fgets_unlocked(line, sizeof line, stream)) return 9;
        if (strcmp(line, "rest!?") != 0) return 10;
    }
    if (fgetc_unlocked(stream) != EOF) return 11;
    if (!feof_unlocked(stream) || ferror_unlocked(stream)) return 12;
    clearerr_unlocked(stream);
    if (feof_unlocked(stream) || ferror_unlocked(stream)) return 13;
    fclose(stream);

    {
        int number;
        char word[16];
        if (call_isoc99_vsscanf("42 answer", "%d %15s", &number, word) != 2) return 14;
        if (number != 42 || strcmp(word, "answer") != 0) return 15;
        if (__isoc99_sscanf("43 alias", "%d %15s", &number, word) != 2) return 21;
        if (number != 43 || strcmp(word, "alias") != 0) return 22;
    }

    stream = tmpfile();
    if (!stream) return 16;
    if (fputs("7 seven", stream) < 0) return 17;
    rewind(stream);
    {
        int number;
        char word[16];
        if (call_isoc99_vfscanf(stream, "%d %15s", &number, word) != 2) return 18;
        if (number != 7 || strcmp(word, "seven") != 0) return 19;
    }
    fclose(stream);

    stream = tmpfile();
    if (!stream) return 33;
    if (ftrylockfile(stream) != 0) return 34;
    if (ftrylockfile(stream) != 0) return 35;
    funlockfile(stream);
    funlockfile(stream);
    setlinebuf(stream);
    if (!__flbf(stream)) return 36;
    if (fputc('x', stream) != 'x' || __fpending(stream) != 1) return 37;
    if (fputc('\n', stream) != '\n' || __fpending(stream) != 0) return 38;
    fclose(stream);

    {
        char storage[] = "one\ntwo";
        stream = fmemopen(storage, sizeof storage - 1, "r");
        if (!stream) return 39;
        size_t line_len = 0;
        char *line = fgetln(stream, &line_len);
        if (!line || line_len != 4 || memcmp(line, "one\n", 4) != 0) return 40;
        line = fgetln(stream, &line_len);
        if (!line || line_len != 3 || memcmp(line, "two", 3) != 0) return 41;
        line_len = 99;
        line = fgetln(stream, &line_len);
        if (line || !feof(stream) || line_len != 99) return 42;
        fclose(stream);
    }

    {
        char storage[] = "wide\nrest";
        wchar_t wide[16];
        stream = fmemopen(storage, sizeof storage - 1, "r");
        if (!stream) return 43;
        if (!fgetws(wide, 16, stream) || wcscmp(wide, L"wide\n") != 0) return 44;
        if (!fgetws_unlocked(wide, 16, stream) || wcscmp(wide, L"rest") != 0) return 45;
        if (fgetws(wide, 16, stream) || !feof(stream)) return 46;
        fclose(stream);
    }

    stream = tmpfile();
    if (!stream) return 23;
    if (fputs("8 eight", stream) < 0) return 24;
    rewind(stream);
    {
        int number;
        char word[16];
        if (__isoc99_fscanf(stream, "%d %15s", &number, word) != 2) return 25;
        if (number != 8) return 26;
        if (strcmp(word, "eight") != 0) return 52;
    }
    fclose(stream);

    {
        int number;
        if (__isoc99_swscanf(L"9", L"%d", &number) != 1) return 27;
        if (number != 9) return 28;
    }

    stream = tmpfile();
    if (!stream) return 29;
    if (fputs("10 streamwide", stream) < 0) return 30;
    rewind(stream);
    {
        int number;
        if (__isoc99_fwscanf(stream, L"%d", &number) != 1) return 31;
        if (number != 10) return 32;
    }
    fclose(stream);

    stream = tmpfile();
    if (!stream) return 33;
    if (fputs("z", stream) < 0) return 34;
    rewind(stream);
    if (__uflow(stream) != 'z' || __uflow(stream) != EOF) return 35;
    fclose(stream);

    if (putchar_unlocked('U') != 'U') return 20;
    puts("stdio unlocked ok");
    return 0;
}
