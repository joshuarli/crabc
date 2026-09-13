/*
 * Exercise musl 1.2.6's same-address stdio aliases and their locking shape.
 *
 * The callbacks synchronously create and join a contender while the active
 * operation is inside its backend callback.  That gives ftrylockfile an
 * unambiguous observation of the enclosing operation's lock: there is no
 * timing loop or probabilistic scheduling assumption.  Musl aliases fread,
 * fwrite, fgetws and fputws to their locking bodies; the byte and wide-char
 * unlocked aliases retain their caller-held-lock contract.
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <locale.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <wchar.h>

extern wint_t __fgetwc_unlocked(FILE *);
extern wint_t __fputwc_unlocked(wint_t, FILE *);
extern ssize_t __getdelim(char **, size_t *, int, FILE *);
extern int __fpurge(FILE *);
extern int fpurge(FILE *);
extern int _IO_feof_unlocked(FILE *);
extern int _IO_ferror_unlocked(FILE *);
extern int _IO_getc(FILE *);
extern int _IO_getc_unlocked(FILE *);
extern int _IO_putc(int, FILE *);
extern int _IO_putc_unlocked(int, FILE *);
extern int __isoc99_fscanf(FILE *, const char *, ...);
extern int __isoc99_vfscanf(FILE *, const char *, va_list);
extern int __isoc99_scanf(const char *, ...);
extern int __isoc99_vscanf(const char *, va_list);
extern int __isoc99_sscanf(const char *, const char *, ...);
extern int __isoc99_vsscanf(const char *, const char *, va_list);
extern int __isoc99_fwscanf(FILE *, const wchar_t *, ...);
extern int __isoc99_vfwscanf(FILE *, const wchar_t *, va_list);
extern int __isoc99_wscanf(const wchar_t *, ...);
extern int __isoc99_vwscanf(const wchar_t *, va_list);
extern int __isoc99_swscanf(const wchar_t *, const wchar_t *, ...);
extern int __isoc99_vswscanf(const wchar_t *, const wchar_t *, va_list);

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "stdio-alias-contract:%d errno=%d\n", __LINE__, errno); \
        return 1; \
    } \
} while (0)

#define SAME_ADDRESS(first, second) ((uintptr_t)(first) == (uintptr_t)(second))

struct lock_round {
    FILE *stream;
    int expected_locked;
    int observed_locked;
    int callback_count;
    int failed;
    const char *input;
    size_t input_offset;
};

static void *contender(void *opaque)
{
    struct lock_round *round = opaque;
    int acquired = ftrylockfile(round->stream) == 0;

    round->observed_locked = !acquired;
    if (acquired)
        funlockfile(round->stream);
    return NULL;
}

static int observe_enclosing_lock(struct lock_round *round)
{
    pthread_t thread;

    if (pthread_create(&thread, NULL, contender, round) != 0)
        return 0;
    if (pthread_join(thread, NULL) != 0)
        return 0;
    ++round->callback_count;
    return round->observed_locked == round->expected_locked;
}

static ssize_t read_cookie(void *opaque, char *destination, size_t count)
{
    struct lock_round *round = opaque;
    size_t available;

    if (!observe_enclosing_lock(round)) {
        round->failed = 1;
        errno = EIO;
        return -1;
    }
    available = 2 - round->input_offset;
    if (available > count)
        available = count;
    if (available != 0) {
        for (size_t index = 0; index != available; ++index)
            destination[index] = round->input[round->input_offset + index];
        round->input_offset += available;
    }
    return (ssize_t)available;
}

static ssize_t write_cookie(void *opaque, const char *source, size_t count)
{
    struct lock_round *round = opaque;

    (void)source;
    if (!observe_enclosing_lock(round)) {
        round->failed = 1;
        errno = EIO;
        return -1;
    }
    return (ssize_t)count;
}

static FILE *open_read_round(struct lock_round *round, int expected_locked)
{
    cookie_io_functions_t functions = { .read = read_cookie };
    FILE *stream;

    *round = (struct lock_round){
        .expected_locked = expected_locked,
        .input = "x\n",
    };
    stream = fopencookie(round, "r", functions);
    if (stream == NULL)
        return NULL;
    round->stream = stream;
    if (setvbuf(stream, NULL, _IONBF, 0) != 0) {
        fclose(stream);
        return NULL;
    }
    return stream;
}

static FILE *open_write_round(struct lock_round *round, int expected_locked)
{
    cookie_io_functions_t functions = { .write = write_cookie };
    FILE *stream;

    *round = (struct lock_round){ .expected_locked = expected_locked };
    stream = fopencookie(round, "w", functions);
    if (stream == NULL)
        return NULL;
    round->stream = stream;
    if (setvbuf(stream, NULL, _IONBF, 0) != 0) {
        fclose(stream);
        return NULL;
    }
    return stream;
}

static int check_alias_addresses(void)
{
    CHECK(SAME_ADDRESS(fgetc_unlocked, getc_unlocked));
    CHECK(SAME_ADDRESS(fputc_unlocked, putc_unlocked));
    CHECK(SAME_ADDRESS(fread_unlocked, fread));
    CHECK(SAME_ADDRESS(fwrite_unlocked, fwrite));
    CHECK(SAME_ADDRESS(fgetwc_unlocked, __fgetwc_unlocked));
    CHECK(SAME_ADDRESS(getwc_unlocked, __fgetwc_unlocked));
    CHECK(SAME_ADDRESS(fputwc_unlocked, __fputwc_unlocked));
    CHECK(SAME_ADDRESS(putwc_unlocked, __fputwc_unlocked));
    CHECK(SAME_ADDRESS(fgetws_unlocked, fgetws));
    CHECK(SAME_ADDRESS(fputws_unlocked, fputws));
    CHECK(SAME_ADDRESS(getwchar_unlocked, getwchar));
    CHECK(SAME_ADDRESS(putwchar_unlocked, putwchar));
    CHECK(SAME_ADDRESS(__getdelim, getdelim));
    CHECK(SAME_ADDRESS(fpurge, __fpurge));
    CHECK(SAME_ADDRESS(fflush_unlocked, fflush));
    CHECK(SAME_ADDRESS(fileno_unlocked, fileno));
    CHECK(SAME_ADDRESS(fgets_unlocked, fgets));
    CHECK(SAME_ADDRESS(fputs_unlocked, fputs));
    CHECK(SAME_ADDRESS(clearerr_unlocked, clearerr));
    CHECK(SAME_ADDRESS(feof_unlocked, feof));
    CHECK(SAME_ADDRESS(ferror_unlocked, ferror));
    CHECK(SAME_ADDRESS(_IO_feof_unlocked, feof));
    CHECK(SAME_ADDRESS(_IO_ferror_unlocked, ferror));
    CHECK(SAME_ADDRESS(_IO_getc, getc));
    CHECK(SAME_ADDRESS(_IO_putc, putc));
    CHECK(SAME_ADDRESS(_IO_getc_unlocked, getc_unlocked));
    CHECK(SAME_ADDRESS(_IO_putc_unlocked, putc_unlocked));
    CHECK(SAME_ADDRESS(__isoc99_sscanf, sscanf));
    CHECK(SAME_ADDRESS(__isoc99_vsscanf, vsscanf));
    CHECK(SAME_ADDRESS(__isoc99_scanf, scanf));
    CHECK(SAME_ADDRESS(__isoc99_vscanf, vscanf));
    CHECK(SAME_ADDRESS(__isoc99_fscanf, fscanf));
    CHECK(SAME_ADDRESS(__isoc99_vfscanf, vfscanf));
    CHECK(SAME_ADDRESS(__isoc99_fwscanf, fwscanf));
    CHECK(SAME_ADDRESS(__isoc99_vfwscanf, vfwscanf));
    CHECK(SAME_ADDRESS(__isoc99_wscanf, wscanf));
    CHECK(SAME_ADDRESS(__isoc99_vwscanf, vwscanf));
    CHECK(SAME_ADDRESS(__isoc99_swscanf, swscanf));
    CHECK(SAME_ADDRESS(__isoc99_vswscanf, vswscanf));
    return 0;
}

static int invoke_isoc99_vsscanf(const char *source, ...)
{
    va_list arguments;
    int result;

    va_start(arguments, source);
    result = __isoc99_vsscanf(source, "%d", arguments);
    va_end(arguments);
    return result;
}

static int invoke_isoc99_vswscanf(const wchar_t *source, ...)
{
    va_list arguments;
    int result;

    va_start(arguments, source);
    result = __isoc99_vswscanf(source, L"%d", arguments);
    va_end(arguments);
    return result;
}

static int check_extended_file_aliases(void)
{
    char input[] = "xy";
    char delimiter_input[] = "line\n";
    char written[16] = {0};
    char line[8];
    char *allocated = NULL;
    size_t capacity = 0;
    FILE *stream;

    stream = fmemopen(input, sizeof input - 1, "r");
    CHECK(stream != NULL);
    CHECK(_IO_getc(stream) == 'x');
    CHECK(_IO_getc_unlocked(stream) == 'y');
    CHECK(_IO_getc(stream) == EOF);
    CHECK(feof_unlocked(stream) != 0 && _IO_feof_unlocked(stream) != 0);
    CHECK(ferror_unlocked(stream) == 0 && _IO_ferror_unlocked(stream) == 0);
    clearerr_unlocked(stream);
    CHECK(feof_unlocked(stream) == 0 && fclose(stream) == 0);

    stream = fmemopen(written, sizeof written, "w+");
    CHECK(stream != NULL);
    CHECK(_IO_putc('a', stream) == 'a');
    CHECK(_IO_putc_unlocked('b', stream) == 'b');
    CHECK(fputs_unlocked("c", stream) != EOF && fflush_unlocked(stream) == 0);
    CHECK(fileno_unlocked(stream) == fileno(stream));
    CHECK(fseek(stream, 0, SEEK_SET) == 0);
    CHECK(fgets_unlocked(line, sizeof line, stream) == line);
    CHECK(line[0] == 'a' && line[1] == 'b' && line[2] == 'c' && line[3] == '\0');
    CHECK(fpurge(stream) == 0 && fclose(stream) == 0);

    stream = fmemopen(delimiter_input, sizeof delimiter_input - 1, "r");
    CHECK(stream != NULL);
    CHECK(__getdelim(&allocated, &capacity, '\n', stream) == 5);
    CHECK(capacity >= 6 && allocated[0] == 'l' && allocated[4] == '\n' && allocated[5] == '\0');
    free(allocated);
    CHECK(fclose(stream) == 0);
    return 0;
}

static int check_isoc99_scan_aliases(void)
{
    int byte_value = 0;
    int wide_value = 0;

    CHECK(__isoc99_sscanf("17", "%d", &byte_value) == 1 && byte_value == 17);
    byte_value = 0;
    CHECK(invoke_isoc99_vsscanf("18", &byte_value) == 1 && byte_value == 18);
    CHECK(__isoc99_swscanf(L"19", L"%d", &wide_value) == 1 && wide_value == 19);
    wide_value = 0;
    CHECK(invoke_isoc99_vswscanf(L"20", &wide_value) == 1 && wide_value == 20);
    return 0;
}

/* The separate override executable owns these public definitions itself.
 * This ordinary consumer therefore also calls each default alias explicitly. */
static int check_default_position_aliases(void)
{
    char storage[32] = {0};
    FILE *file = fmemopen(storage, sizeof storage, "w+");
    FILE *adopted;
    int descriptors[2];

    CHECK(file != NULL);
    CHECK(fputs("alias", file) >= 0 && fflush(file) == 0);
    CHECK(ftello(file) == 5 && fseeko(file, 1, SEEK_SET) == 0);
    CHECK(ftello(file) == 1 && fgetc(file) == 'l');
    CHECK(pipe(descriptors) == 0);
    adopted = fdopen(descriptors[0], "r");
    CHECK(adopted != NULL && fclose(adopted) == 0
          && close(descriptors[1]) == 0 && fclose(file) == 0);
    return 0;
}

static int check_read_locking(void)
{
    struct lock_round round;
    FILE *stream;
    char byte;
    wchar_t wide[4];

    stream = open_read_round(&round, 0);
    CHECK(stream != NULL);
    CHECK(fgetc_unlocked(stream) == 'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_read_round(&round, 1);
    CHECK(stream != NULL);
    CHECK(fread_unlocked(&byte, 1, 1, stream) == 1 && byte == 'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_read_round(&round, 0);
    CHECK(stream != NULL);
    CHECK(fgetwc_unlocked(stream) == L'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_read_round(&round, 1);
    CHECK(stream != NULL);
    CHECK(fgetws_unlocked(wide, 4, stream) == wide && wide[0] == L'x'
          && wide[1] == L'\n' && wide[2] == L'\0');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);
    return 0;
}

static int check_write_locking(void)
{
    struct lock_round round;
    FILE *stream;

    stream = open_write_round(&round, 0);
    CHECK(stream != NULL);
    CHECK(fputc_unlocked('x', stream) == 'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_write_round(&round, 1);
    CHECK(stream != NULL);
    CHECK(fwrite_unlocked("x", 1, 1, stream) == 1);
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_write_round(&round, 0);
    CHECK(stream != NULL);
    CHECK(fputwc_unlocked(L'x', stream) == L'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_write_round(&round, 1);
    CHECK(stream != NULL);
    CHECK(fputws_unlocked(L"x", stream) >= 0);
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);
    return 0;
}

int main(void)
{
    CHECK(setlocale(LC_CTYPE, "C.UTF-8") != NULL);
    CHECK(check_alias_addresses() == 0);
    CHECK(check_default_position_aliases() == 0);
    CHECK(check_extended_file_aliases() == 0);
    CHECK(check_isoc99_scan_aliases() == 0);
    CHECK(check_read_locking() == 0);
    CHECK(check_write_locking() == 0);
    puts("owned-stdio-alias-contract-ok");
    return 0;
}
