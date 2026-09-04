/* Permanent-stream formatted-I/O vertical-slice fixture.
 *
 * This deliberately stays on the three exported stream objects: the output
 * calls exercise direct and VaList forwarding, buffering, explicit flush, and
 * a failed output flush observed through ferror;
 * the input calls exercise whitespace, integer/string/character conversion,
 * %n, assignment suppression, character conversion, matching failure, EOF,
 * and preservation of delimiters for fgetc.
 */
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires Linux/x86-64 little-endian LP64"
#endif

typedef int (*close_fn)(int);
typedef int (*dup2_fn)(int, int);
typedef int (*dup_fn)(int);
typedef void (*clearerr_fn)(FILE *);
typedef int (*fflush_fn)(FILE *);
typedef int (*ferror_fn)(FILE *);
typedef int (*fgetc_fn)(FILE *);
typedef int (*fprintf_fn)(FILE *, const char *, ...);
typedef int (*fscanf_fn)(FILE *, const char *, ...);
typedef int (*pipe_fn)(int *);
typedef int (*printf_fn)(const char *, ...);
typedef int (*scanf_fn)(const char *, ...);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef ssize_t (*write_fn)(int, const void *, size_t);

static close_fn volatile close_entry = close;
static dup2_fn volatile dup2_entry = dup2;
static dup_fn volatile dup_entry = dup;
static clearerr_fn volatile clearerr_entry = clearerr;
static fflush_fn volatile fflush_entry = fflush;
static ferror_fn volatile ferror_entry = ferror;
static fgetc_fn volatile fgetc_entry = fgetc;
static fprintf_fn volatile fprintf_entry = fprintf;
static fscanf_fn volatile fscanf_entry = fscanf;
static pipe_fn volatile pipe_entry = pipe;
static printf_fn volatile printf_entry = printf;
static scanf_fn volatile scanf_entry = scanf;
static read_fn volatile read_entry = read;
static write_fn volatile write_entry = write;

static int call_vprintf(const char *format, ...)
{
    va_list args;
    int result;
    va_start(args, format);
    result = vprintf(format, args);
    va_end(args);
    return result;
}

static int call_vfprintf(FILE *stream, const char *format, ...)
{
    va_list args;
    int result;
    va_start(args, format);
    result = vfprintf(stream, format, args);
    va_end(args);
    return result;
}

static int call_vfscanf(FILE *stream, const char *format, ...)
{
    va_list args;
    int result;
    va_start(args, format);
    result = vfscanf(stream, format, args);
    va_end(args);
    return result;
}

static int call_vscanf(const char *format, ...)
{
    va_list args;
    int result;
    va_start(args, format);
    result = vscanf(format, args);
    va_end(args);
    return result;
}

static int write_all(int fd, const char *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t result = write_entry(fd, bytes + offset, length - offset);
        if (result <= 0)
            return -1;
        offset += (size_t)result;
    }
    return 0;
}

static int read_exact(int fd, char *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t result = read_entry(fd, bytes + offset, length - offset);
        if (result <= 0)
            return -1;
        offset += (size_t)result;
    }
    return 0;
}

static int bytes_equal(const char *actual, const char *expected, size_t length)
{
    size_t index;
    for (index = 0; index < length; ++index)
        if (actual[index] != expected[index])
            return 0;
    return 1;
}

static int redirect_output(int *saved, int *reader)
{
    int ends[2];
    if ((*saved = dup_entry(STDOUT_FILENO)) < 0 || pipe_entry(ends) != 0)
        return -1;
    if (dup2_entry(ends[1], STDOUT_FILENO) != STDOUT_FILENO)
        return -1;
    close_entry(ends[1]);
    *reader = ends[0];
    return 0;
}

static int redirect_input(const char *source, size_t length, int *saved)
{
    int ends[2];
    if ((*saved = dup_entry(STDIN_FILENO)) < 0 || pipe_entry(ends) != 0)
        return -1;
    if (write_all(ends[1], source, length) != 0 || close_entry(ends[1]) != 0)
        return -1;
    if (dup2_entry(ends[0], STDIN_FILENO) != STDIN_FILENO)
        return -1;
    close_entry(ends[0]);
    return 0;
}

int crabc_x86_64_stdio_permanent_format_scan_wave_probe(void)
{
    static const char expected[] = "i=7 s=ok v=9 f=11\nvf=12\n";
    static const char input[] = "3 4 7 ok;tail";
    char actual[sizeof(expected)];
    char word[8] = {0};
    int saved_output = -1, output_reader = -1;
    int saved_input = -1;
    int number = 0, via_v = 0, count = -1;
    float rejected_float = 0.0f;
    char character = '\0';

    if (redirect_output(&saved_output, &output_reader) != 0)
        return 1;
    if (printf_entry("i=%d s=%s ", 7, "ok") != 9 ||
        call_vprintf("v=%d ", 9) != 4 ||
        fprintf_entry(stdout, "f=%d\n", 11) != 5 ||
        call_vfprintf(stdout, "vf=%d\n", 12) != 6 ||
        fflush_entry(stdout) != 0 ||
        read_exact(output_reader, actual, sizeof(expected) - 1) != 0 ||
        !bytes_equal(actual, expected, sizeof(expected) - 1))
        return 2;
    /* The read above intentionally asks only for payload bytes. */
    if (printf_entry("e") != 1 ||
        close_entry(STDOUT_FILENO) != 0 ||
        fflush_entry(stdout) != EOF ||
        ferror_entry(stdout) == 0)
        return 18;
    if (dup2_entry(saved_output, STDOUT_FILENO) != STDOUT_FILENO)
        return 3;
    close_entry(saved_output);
    close_entry(output_reader);
    clearerr_entry(stdout);

    if (redirect_input(input, sizeof(input) - 1, &saved_input) != 0)
        return 4;
    if (scanf_entry("%d", &via_v) != 1 || via_v != 3 ||
        call_vscanf("%d", &number) != 1 || number != 4)
        return 5;
    if (fscanf_entry(stdin, "%d", &number) != 1 || number != 7 ||
        fgetc_entry(stdin) != ' ')
        return 6;
    if (call_vfscanf(stdin, "%2s%n", word, &count) != 1)
        return 7;
    if (word[0] != 'o' || word[1] != 'k' || word[2] != '\0')
    {
        write_entry(STDERR_FILENO, word, 3);
        return 17;
    }
    if (count != 2)
        return 27;
    if (fgetc_entry(stdin) != ';')
        return 37;
    if (fscanf_entry(stdin, "%*c%c", &character) != 1 || character != 'a')
        return 47;
#ifdef CRABC_STDIO_PERMANENT_FORMAT_SCAN_WAVE_FREESTANDING
    errno = 0;
    if (fscanf_entry(stdin, "%f", &rejected_float) != 0 || errno != EINVAL)
        return 38;
#endif
    if (fscanf_entry(stdin, "%d", &via_v) != 0 || fgetc_entry(stdin) != 'i')
        return 8;
    if (fgetc_entry(stdin) != 'l' ||
        fscanf_entry(stdin, "%d", &via_v) != EOF)
        return 10;
    if (dup2_entry(saved_input, STDIN_FILENO) != STDIN_FILENO)
        return 11;
    close_entry(saved_input);
#ifdef CRABC_STDIO_PERMANENT_FORMAT_SCAN_WAVE_FREESTANDING
    errno = 0;
    if (printf_entry("%p", (void *)0) != EOF || errno != EINVAL)
        return 40;
    errno = 0;
    if (printf_entry("%f", 1.0) != EOF || errno != EINVAL)
        return 41;
    errno = 0;
    if (printf_entry("%m") != EOF || errno != EINVAL)
        return 44;
    errno = 0;
    if (fprintf_entry((FILE *)(uintptr_t)1, "x") != EOF || errno != EINVAL)
        return 42;
    errno = 0;
    if (fscanf_entry((FILE *)(uintptr_t)1, "%d", &via_v) != EOF || errno != EINVAL)
        return 43;
#endif
    return 0;
}

int main(void)
{
    return crabc_x86_64_stdio_permanent_format_scan_wave_probe();
}
