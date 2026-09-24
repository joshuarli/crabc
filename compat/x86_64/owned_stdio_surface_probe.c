#define _GNU_SOURCE
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <wchar.h>
#include <locale.h>

/*
 * Frozen stdio surface row for the installed FILE engine.
 *
 * Together with the other FILE-engine rows, this object calls every frozen
 * `stdio.path-stream`, `stdio.stream-io`, `stdio.position-buffering`, and
 * `stdio.format-scan` symbol through the installed headers (or through the
 * source-only declarations below, where pinned musl 1.2.6 exports a name that
 * no public header declares). Every observation is printed and compared with
 * the same object linked against pinned musl; CHECK failures go to stderr,
 * which the runner requires to be empty for the oracle too.
 *
 * It also retains three pinned-musl regressions for the owned engine:
 *   - src/stdio/{feof,ferror}.c return exactly 0 or 1 (`!!(flags & F_*)`);
 *   - src/stdio/setvbuf.c only reconfigures buf/buf_size/lbf. It never drops
 *     pending output or unread input, never sets errno, and resets lbf before
 *     rejecting an unknown type;
 *   - src/stdio/__stdio_exit.c flushes the open-file list (most recent first)
 *     before stdin, stdout and stderr.
 * argv[1] is private scratch for this process and is removed before exit.
 */
extern wint_t __fgetwc_unlocked(FILE *);
extern wint_t __fputwc_unlocked(wint_t, FILE *);
extern ssize_t __getdelim(char **, size_t *, int, FILE *);
extern int fpurge(FILE *);
extern int _IO_feof_unlocked(FILE *);
extern int _IO_ferror_unlocked(FILE *);
extern int __isoc99_fscanf(FILE *, const char *, ...);
extern int __isoc99_scanf(const char *, ...);
extern int __isoc99_sscanf(const char *, const char *, ...);
extern int __isoc99_vfscanf(FILE *, const char *, va_list);
extern int __isoc99_vscanf(const char *, va_list);
extern int __isoc99_vsscanf(const char *, const char *, va_list);
extern int __isoc99_fwscanf(FILE *, const wchar_t *, ...);
extern int __isoc99_swscanf(const wchar_t *, const wchar_t *, ...);
extern int __isoc99_vfwscanf(FILE *, const wchar_t *, va_list);
extern int __isoc99_vswscanf(const wchar_t *, const wchar_t *, va_list);
extern int __isoc99_vwscanf(const wchar_t *, va_list);
extern int __isoc99_wscanf(const wchar_t *, ...);

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "surface:%d errno=%d\n", __LINE__, errno); exit(1); } } while (0)

static const char *path;

static void replace(const char *bytes)
{
    FILE *f = fopen(path, "w");
    CHECK(f && fputs(bytes, f) >= 0 && !fclose(f));
}

static int forward_vfscanf(FILE *f, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = __isoc99_vfscanf(f, format, arguments);
    va_end(arguments);
    return result;
}
static int forward_vscanf(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = __isoc99_vscanf(format, arguments);
    va_end(arguments);
    return result;
}
static int forward_vsscanf(const char *input, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = __isoc99_vsscanf(input, format, arguments);
    va_end(arguments);
    return result;
}
static int forward_vfwscanf(FILE *f, const wchar_t *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = __isoc99_vfwscanf(f, format, arguments);
    va_end(arguments);
    return result;
}
static int forward_vswscanf(const wchar_t *input, const wchar_t *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = __isoc99_vswscanf(input, format, arguments);
    va_end(arguments);
    return result;
}
static int forward_vwscanf(const wchar_t *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = __isoc99_vwscanf(format, arguments);
    va_end(arguments);
    return result;
}

/* feof/ferror and their unlocked/_IO_ aliases report exactly 0 or 1. */
static void status_values(void)
{
    replace("x");
    FILE *f = fopen(path, "r");
    CHECK(f && fgetc(f) == 'x' && fgetc(f) == EOF);
    printf("eof %d %d %d %d\n", feof(f), feof_unlocked(f), _IO_feof_unlocked(f), ferror(f));
    CHECK(fputc('y', f) == EOF);
    printf("error %d %d %d\n", ferror(f), ferror_unlocked(f), _IO_ferror_unlocked(f));
    clearerr(f);
    printf("cleared %d %d\n", feof(f), ferror(f));
    CHECK(!fclose(f));
}

/* Mid-stream setvbuf keeps the active buffered bytes (src/stdio/setvbuf.c). */
static void reconfiguration(void)
{
    static char external[24], reading[16];
    FILE *f = fopen(path, "w+");
    CHECK(f);
    errno = 0;
    printf("invalid %d %d\n", setvbuf(f, NULL, 7, 0), errno);
    printf("invalid-lbf %d\n", __flbf(f));
    CHECK(fputs("pending", f) >= 0);
    printf("pending %zu %zu\n", __fpending(f), __fbufsize(f));
    CHECK(!setvbuf(f, NULL, _IONBF, 0));
    printf("unbuffered %zu %zu %d\n", __fpending(f), __fbufsize(f), __flbf(f));
    CHECK(fputs("+more", f) >= 0);
    printf("retained %zu\n", __fpending(f));
    CHECK(!setvbuf(f, external, _IOLBF, sizeof external));
    printf("external %zu %zu %d\n", __fpending(f), __fbufsize(f), __flbf(f));
    CHECK(fputs("-line\ntail", f) >= 0);
    printf("line %zu\n", __fpending(f));
    CHECK(!fflush(f) && !__fpending(f));
    CHECK(fputs("[next]", f) >= 0);
    printf("next %zu\n", __fpending(f));
    CHECK(!fseek(f, 0, SEEK_SET));
    char bytes[64] = {0};
    size_t count = fread(bytes, 1, sizeof bytes - 1, f);
    printf("written %zu %s\n", count, bytes);
    CHECK(!fclose(f));

    replace("0123456789abcdef");
    f = fopen(path, "r");
    CHECK(f && fgetc(f) == '0');
    CHECK(!setvbuf(f, reading, _IOFBF, sizeof reading));
    printf("unread %zu %zu", __freadahead(f), __fbufsize(f));
    for (int c; (c = fgetc(f)) != EOF;) printf(" %c", c);
    printf(" end %d\n", feof(f));
    CHECK(!fclose(f));
}

/* Frozen symbols without another FILE-engine row's direct call. Each call
 * is sequenced before printing: argument evaluation order is unspecified. */
static void remaining_surface(void)
{
    char terminal[L_ctermid];
    int same = ctermid(terminal) == terminal;
    printf("ctermid %d %s %s\n", same, terminal, ctermid(NULL));

    FILE *f = fopen(path, "w+");
    CHECK(f);
    CHECK(putc('a', f) == 'a' && fputc_unlocked('b', f) == 'b' && putc_unlocked('c', f) == 'c');
    CHECK(fwrite_unlocked("de\nfg\nh", 1, 7, f) == 7);
    printf("tello %lld\n", (long long)ftello(f));
    CHECK(!fseeko(f, 1, SEEK_SET));
    int first = getc(f), second = fgetc_unlocked(f), third = getc_unlocked(f);
    printf("getc %c %c %c\n", first, second, third);
    char bytes[8] = {0};
    CHECK(fread_unlocked(bytes, 1, 1, f) == 1);
    printf("fread_unlocked %s\n", bytes);
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length = getline(&line, &capacity, f);
    printf("getline %zd [%s]\n", length, line);
    length = getdelim(&line, &capacity, 'g', f);
    printf("getdelim %zd [%s]\n", length, line);
    length = __getdelim(&line, &capacity, '\n', f);
    printf("__getdelim %zd [%s]\n", length, line);
    length = getdelim(&line, &capacity, '\n', f);
    printf("partial %zd [%s] %d\n", length, line, feof(f));
    length = getdelim(&line, &capacity, '\n', f);
    printf("eof %zd %d\n", length, feof(f));
    free(line);
    CHECK(!fseeko(f, 0, SEEK_END) && fputs("purged", f) >= 0);
    int purged = fpurge(f);
    printf("fpurge %d %zu %lld\n", purged, __fpending(f), (long long)ftello(f));
    CHECK(!fclose(f));

    replace("q");
    CHECK(freopen(path, "r", stdin) == stdin);
    first = getchar();
    second = getchar_unlocked();
    printf("getchar %c %d %d\n", first, second, feof(stdin));
    CHECK(putchar_unlocked('!') == '!' && putchar('\n') == '\n');

    CHECK(setlocale(LC_CTYPE, "C.UTF-8"));
    f = fopen(path, "w+");
    CHECK(f && __fputwc_unlocked(0x20ac, f) == 0x20ac && __fputwc_unlocked(L'w', f) == L'w');
    CHECK(!fseeko(f, 0, SEEK_SET));
    wint_t euro = __fgetwc_unlocked(f), letter = __fgetwc_unlocked(f), end = __fgetwc_unlocked(f);
    printf("wide %x %x %d\n", (unsigned)euro, (unsigned)letter, end == WEOF);
    CHECK(!fclose(f));
    CHECK(setlocale(LC_CTYPE, "C"));
}

/* Musl's ISO C99 scan aliases share their conventional bodies. */
static void scan_aliases(void)
{
    int first = 0, second = 0, third = 0, count = 0, result;
    char word[8] = "";
    result = __isoc99_sscanf("12 ab", "%d %2s%n", &first, word, &count);
    printf("sscanf %d %d %s %d\n", result, first, word, count);
    result = forward_vsscanf("0x1f z", "%i %c", &first, word);
    printf("vsscanf %d %d %c\n", result, first, word[0]);

    replace("7 8 9 tail");
    FILE *f = fopen(path, "r");
    CHECK(f);
    result = __isoc99_fscanf(f, "%d", &first);
    printf("fscanf %d %d", result, first);
    result = forward_vfscanf(f, "%d", &second);
    printf(" vfscanf %d %d", result, second);
    result = fgetc(f);
    printf(" next [%c]\n", result);
    CHECK(!fclose(f));

    CHECK(freopen(path, "r", stdin) == stdin);
    result = __isoc99_scanf("%d", &first);
    printf("scanf %d %d", result, first);
    result = forward_vscanf("%d %d", &second, &third);
    printf(" vscanf %d %d %d\n", result, second, third);

    CHECK(setlocale(LC_CTYPE, "C.UTF-8"));
    wchar_t wide[8] = L"";
    result = __isoc99_swscanf(L"\x20ac 5", L"%lc %d", wide, &first);
    printf("swscanf %d %x %d\n", result, (unsigned)wide[0], first);
    result = forward_vswscanf(L"ab 6", L"%ls %d", wide, &second);
    printf("vswscanf %d %x %d\n", result, (unsigned)wide[1], second);

    replace("\xe2\x82\xac 3 4 5 6");
    f = fopen(path, "r");
    CHECK(f);
    result = __isoc99_fwscanf(f, L"%lc %d", wide, &first);
    printf("fwscanf %d %x %d", result, (unsigned)wide[0], first);
    result = forward_vfwscanf(f, L"%d", &second);
    printf(" vfwscanf %d %d %d\n", result, second, fwide(f, 0) > 0);
    CHECK(!fclose(f));

    CHECK(freopen(path, "r", stdin) == stdin);
    result = __isoc99_wscanf(L"%lc", wide);
    printf("wscanf %d %x", result, (unsigned)wide[0]);
    result = forward_vwscanf(L"%d %d", &first, &second);
    printf(" vwscanf %d %d %d\n", result, first, second);
    CHECK(setlocale(LC_CTYPE, "C"));
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    path = argv[1];
    alarm(30);
    status_values();
    reconfiguration();
    remaining_surface();
    scan_aliases();
    CHECK(!unlink(path));

    /* Leave output pending in stdout and in two younger descriptor streams
     * sharing its open file description: ordinary exit flushes the list
     * newest first, then the standard streams. */
    FILE *older = fdopen(dup(1), "w"), *newer = fdopen(dup(1), "w");
    CHECK(older && newer);
    CHECK(fflush(stdout) == 0);
    CHECK(fputs("stdout-pending\n", stdout) >= 0);
    CHECK(fputs("older-pending\n", older) >= 0);
    CHECK(fputs("newer-pending\n", newer) >= 0);
    return 0;
}
