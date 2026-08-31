/* Static x86-64 fixed pathname-stream regression fixture.
 *
 * The same project-header source first executes against pinned musl 1.2.6,
 * then against one `-nostdlib -static` crabc archive. It proves a bounded
 * regular-file route only: one `fopen("w+")` slot, caller-buffered full I/O,
 * byte/block transfer, logical positions across output and read-ahead,
 * fpos_t save/restore, rewind, close, and slot reuse through `fopen("r")`.
 * It is not a general FILE/stdio, stream allocator, fdopen/freopen, append,
 * line/unbuffered buffering, formatter/scanner, or public x86 proof.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(fpos_t) == 16, "musl-compatible opaque fpos_t size");
_Static_assert(sizeof(long) == 8 && sizeof(off_t) == 8,
    "x86-64 LP64 logical-position scalar widths");

typedef int (*fclose_fn)(FILE *);
typedef int (*fflush_fn)(FILE *);
typedef int (*fileno_fn)(FILE *);
typedef FILE *(*fopen_fn)(const char *, const char *);
typedef int (*fgetc_fn)(FILE *);
typedef int (*fgetpos_fn)(FILE *, fpos_t *);
typedef int (*fseek_fn)(FILE *, long, int);
typedef int (*fseeko_fn)(FILE *, off_t, int);
typedef int (*fsetpos_fn)(FILE *, const fpos_t *);
typedef long (*ftell_fn)(FILE *);
typedef off_t (*ftello_fn)(FILE *);
typedef off_t (*lseek_fn)(int, off_t, int);
typedef int (*fputc_fn)(int, FILE *);
typedef size_t (*fread_fn)(void *, size_t, size_t, FILE *);
typedef size_t (*fwrite_fn)(const void *, size_t, size_t, FILE *);
typedef void (*rewind_fn)(FILE *);
typedef int (*setvbuf_fn)(FILE *, char *, int, size_t);
typedef int (*unlink_fn)(const char *);

static fclose_fn volatile fclose_entry = fclose;
static fflush_fn volatile fflush_entry = fflush;
static fileno_fn volatile fileno_entry = fileno;
static fopen_fn volatile fopen_entry = fopen;
static fgetc_fn volatile fgetc_entry = fgetc;
static fgetpos_fn volatile fgetpos_entry = fgetpos;
static fseek_fn volatile fseek_entry = fseek;
static fseeko_fn volatile fseeko_entry = fseeko;
static fsetpos_fn volatile fsetpos_entry = fsetpos;
static ftell_fn volatile ftell_entry = ftell;
static ftello_fn volatile ftello_entry = ftello;
static lseek_fn volatile lseek_entry = lseek;
static fputc_fn volatile fputc_entry = fputc;
static fread_fn volatile fread_entry = fread;
static fwrite_fn volatile fwrite_entry = fwrite;
static rewind_fn volatile rewind_entry = rewind;
static setvbuf_fn volatile setvbuf_entry = setvbuf;
static unlink_fn volatile unlink_entry = unlink;

static int bytes_equal(const char *actual, const char *expected, size_t length)
{
    size_t index;

    for (index = 0; index != length; ++index)
        if (actual[index] != expected[index])
            return 0;
    return 1;
}

static int check_fixed_path_stream(void)
{
    static const char path[] = "/tmp/crabc-x86-stdio-path-stream-probe";
    static const char initial[] = "abcdef";
    static const char final[] = "abcdefZ";
    char caller_buffer[5];
    char observed[sizeof(final) - 1U];
    FILE *stream = NULL;
    fpos_t saved;
    unsigned char *saved_bytes = (unsigned char *)&saved;
    size_t index;
    int status = 0;

    (void)unlink_entry(path);
    stream = fopen_entry(path, "w+");
    if (stream == NULL)
        return 1;
#ifdef CRABC_STDIO_PATH_STREAM_FREESTANDING
    errno = 0;
    if (fopen_entry(path, "r") != NULL || errno != EMFILE) {
        status = 20;
        goto close_stream;
    }
    errno = 0;
    if (setvbuf_entry(stream, caller_buffer, _IONBF, sizeof(caller_buffer)) != -1 ||
        errno != EINVAL) {
        status = 21;
        goto close_stream;
    }
#endif
    if (setvbuf_entry(stream, caller_buffer, _IOFBF, sizeof(caller_buffer)) != 0) {
        status = 2;
        goto close_stream;
    }
    if (fwrite_entry(initial, 1, sizeof(initial) - 1U, stream) !=
            sizeof(initial) - 1U ||
        ftell_entry(stream) != 6 || ftello_entry(stream) != 6) {
        status = 3;
        goto close_stream;
    }
#ifdef CRABC_STDIO_PATH_STREAM_FREESTANDING
    errno = 0;
    if (setvbuf_entry(stream, caller_buffer, _IOFBF, sizeof(caller_buffer)) != -1 ||
        errno != EINVAL) {
        status = 22;
        goto close_stream;
    }
#endif
    /* The active path slot participates in musl's all-output-stream flush. */
    if (fflush_entry(NULL) != 0 ||
        lseek_entry(fileno_entry(stream), 0, SEEK_CUR) != 6) {
        status = 4;
        goto close_stream;
    }
    errno = 0;
    if (fseeko_entry(stream, -1, SEEK_SET) != -1 || errno != EINVAL ||
        ferror(stream) != 0 || ftello_entry(stream) != 6) {
        status = 5;
        goto close_stream;
    }
    for (index = 0; index != sizeof(saved); ++index)
        saved_bytes[index] = 0xa5U;
    if (fgetpos_entry(stream, &saved) != 0) {
        status = 6;
        goto close_stream;
    }
    /* Pinned musl stores only the offset prefix of the opaque fpos_t object. */
    for (index = sizeof(off_t); index != sizeof(saved); ++index) {
        if (saved_bytes[index] != 0xa5U) {
            status = 7;
            goto close_stream;
        }
    }
    if (
        fseek_entry(stream, 0, SEEK_SET) != 0) {
        status = 8;
        goto close_stream;
    }
    if (fread_entry(observed, 1, 2, stream) != 2 ||
        !bytes_equal(observed, "ab", 2) || ftello_entry(stream) != 2) {
        status = 9;
        goto close_stream;
    }
    /* The selected read-ahead-adjusted SEEK_CUR route accounts for the unread refill suffix. */
    if (fseeko_entry(stream, 1, SEEK_CUR) != 0 || fgetc_entry(stream) != 'd' ||
        ftell_entry(stream) != 4) {
        status = 10;
        goto close_stream;
    }
    if (fsetpos_entry(stream, &saved) != 0 || fputc_entry('Z', stream) != 'Z' ||
        ftello_entry(stream) != 7 || fseeko_entry(stream, 0, SEEK_SET) != 0) {
        status = 11;
        goto close_stream;
    }
    if (fread_entry(observed, 1, sizeof(observed), stream) != sizeof(observed) ||
        !bytes_equal(observed, final, sizeof(observed)) || fgetc_entry(stream) != EOF ||
        feof(stream) == 0) {
        status = 12;
        goto close_stream;
    }
    rewind_entry(stream);
    if (feof(stream) != 0 || ferror(stream) != 0 || fgetc_entry(stream) != 'a') {
        status = 13;
        goto close_stream;
    }

close_stream:
    if (fclose_entry(stream) != 0 && status == 0)
        status = 14;
    stream = NULL;
    if (status != 0)
        goto cleanup;

#ifdef CRABC_STDIO_PATH_STREAM_FREESTANDING
    errno = 0;
    stream = fopen_entry(path, "a");
    if (stream != NULL || errno != EINVAL) {
        status = 23;
        goto cleanup;
    }
#endif
    /* A successful close returns the one static slot to the selected `r` path. */
    stream = fopen_entry(path, "r");
    if (stream == NULL || fgetc_entry(stream) != 'a') {
        status = 15;
        goto close_stream;
    }
    if (fclose_entry(stream) != 0) {
        stream = NULL;
        status = 16;
        goto cleanup;
    }
    stream = NULL;

cleanup:
    if (stream != NULL)
        (void)fclose_entry(stream);
    if (unlink_entry(path) != 0 && errno != ENOENT && status == 0)
        status = 17;
    return status;
}

int crabc_x86_64_stdio_path_stream_probe(void)
{
    return check_fixed_path_stream();
}

#ifndef CRABC_STDIO_PATH_STREAM_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_path_stream_probe();
}
#endif
