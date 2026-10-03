/*
 * One installed-header stdio composition object.
 *
 * The fopen64 macro consumer, byte, and wide cases use distinct live FILE
 * objects.  The macro consumer retains Linux LP64's source-only fopen64
 * alias through the selected fopen path.  The byte object
 * crosses caller-buffered output, a seek/read/fsetpos/write direction change,
 * stream printf/scanf, EOF and a deterministic wrong-direction error, then
 * `freopen`.  The wide object fixes C.UTF-8 and remains independently wide
 * oriented.  A third byte FILE adopts one descriptor, while a duplicate proves
 * that closing the adopted FILE retires only its transferred descriptor.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <wchar.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(long) == 8, "x86-64 LP64 stream positions");
_Static_assert(sizeof(wchar_t) == 4, "installed wide FILE code units");

#ifndef _LARGEFILE64_SOURCE
#error "this installed macro consumer requires _LARGEFILE64_SOURCE=1"
#endif
#ifndef fopen64
#error "Linux LP64 must expose fopen64 as a preprocessing alias"
#endif

typedef FILE *(*fopen_signature)(const char *, const char *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&fopen64),
    fopen_signature), "fopen64 macro function type");

static fopen_signature volatile fopen_entry = fopen;
/* This initializer must preprocess to the same ordinary fopen spelling. */
static fopen_signature volatile fopen64_macro_entry = fopen64;

static int equal_bytes(const char *actual, const char *expected, size_t count)
{
    size_t index;

    for (index = 0; index != count; ++index)
        if (actual[index] != expected[index])
            return 0;
    return 1;
}

static int fopen64_macro_consumer(const char *path)
{
    static const char payload[] = "fopen64 macro consumer";
    char observed[sizeof(payload)];
    FILE *stream;

    if (fopen_entry != fopen64_macro_entry)
        return 1;
    (void)unlink(path);
    errno = 0;
    if (fopen64_macro_entry(path, "r") != NULL || errno != ENOENT)
        return 2;
    stream = fopen64_macro_entry(path, "w+");
    if (stream == NULL)
        return 3;
    if (fwrite(payload, 1, sizeof(payload), stream) != sizeof(payload) ||
        fseek(stream, 0, SEEK_SET) != 0 ||
        fread(observed, 1, sizeof(observed), stream) != sizeof(observed) ||
        !equal_bytes(observed, payload, sizeof(payload))) {
        (void)fclose(stream);
        (void)unlink(path);
        return 4;
    }
    if (fclose(stream) != 0) {
        (void)unlink(path);
        return 5;
    }
    stream = fopen64_macro_entry(path, "r");
    if (stream == NULL) {
        (void)unlink(path);
        return 6;
    }
    if (fgetc(stream) != payload[0]) {
        (void)fclose(stream);
        (void)unlink(path);
        return 7;
    }
    if (fclose(stream) != 0 || unlink(path) != 0)
        return 8;
    return 0;
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

static __thread int callback_tls = 17;

struct live_cookie {
    char bytes[64];
    size_t position;
    size_t length;
    FILE *nested;
    int tls;
    int closed;
    int failed;
};

/* Each callback owns its temporary client and touches a distinct live FILE.
 * The cookie's borrowed state and nested stream remain live until fclose. */
static int callback_client(struct live_cookie *cookie)
{
    unsigned char *client = malloc(19);
    unsigned char *grown;
    int index;

    if (client == NULL)
        return 1;
    for (index = 0; index != 19; ++index)
        client[index] = (unsigned char)(index + cookie->tls);
    grown = realloc(client, 37);
    if (grown == NULL) {
        free(client);
        return 2;
    }
    for (index = 0; index != 19; ++index)
        if (grown[index] != (unsigned char)(index + cookie->tls)) {
            free(grown);
            return 3;
        }
    free(grown);
    errno = EDOM;
    if (callback_tls != cookie->tls)
        return 4;
    if (cookie->nested != NULL && fputc('C', cookie->nested) != 'C')
        return 5;
    return errno != EDOM;
}

static ssize_t live_write(void *opaque, const char *bytes, size_t count)
{
    struct live_cookie *cookie = opaque;
    size_t index;

    if (callback_client(cookie) != 0 || count > sizeof(cookie->bytes) - cookie->position) {
        cookie->failed = 1;
        return -1;
    }
    for (index = 0; index != count; ++index)
        cookie->bytes[cookie->position + index] = bytes[index];
    cookie->position += count;
    if (cookie->length < cookie->position)
        cookie->length = cookie->position;
    return (ssize_t)count;
}

static ssize_t live_read(void *opaque, char *bytes, size_t count)
{
    struct live_cookie *cookie = opaque;
    size_t index;

    if (callback_client(cookie) != 0) {
        cookie->failed = 1;
        return -1;
    }
    if (count > cookie->length - cookie->position)
        count = cookie->length - cookie->position;
    for (index = 0; index != count; ++index)
        bytes[index] = cookie->bytes[cookie->position + index];
    cookie->position += count;
    return (ssize_t)count;
}

static int live_seek(void *opaque, off64_t *offset, int whence)
{
    struct live_cookie *cookie = opaque;
    off64_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ?
        (off64_t)cookie->position : (off64_t)cookie->length;
    off64_t position = base + *offset;

    if (callback_client(cookie) != 0 || position < 0 || position > (off64_t)cookie->length) {
        cookie->failed = 1;
        return -1;
    }
    cookie->position = (size_t)position;
    *offset = position;
    return 0;
}

static int live_close(void *opaque)
{
    struct live_cookie *cookie = opaque;
    cookie->closed += 1;
    if (callback_client(cookie) != 0)
        cookie->failed = 1;
    return cookie->failed ? -1 : 0;
}

static ssize_t short_cookie_write(void *opaque, const char *bytes, size_t count)
{
    return live_write(opaque, bytes, count > 2 ? 2 : count);
}

/* A positive short backend write publishes only complete fwrite items.
 * Both streams borrow live storage through close; neither short prefix sets
 * the stream error indicator or replaces the callback's errno. */
static int short_write_composition(int tls)
{
    char fixed_bytes[4] = { 0 };
    struct live_cookie cookie = { .tls = tls };
    cookie_io_functions_t functions = { NULL, short_cookie_write, NULL, live_close };
    FILE *fixed = fmemopen(fixed_bytes, sizeof(fixed_bytes), "w+");
    FILE *stream = fopencookie(&cookie, "w", functions);
    int result = 1;

    if (fixed == NULL || stream == NULL || setvbuf(fixed, NULL, _IONBF, 0) != 0 ||
        setvbuf(stream, NULL, _IONBF, 0) != 0)
        goto close_live;
    errno = EDOM;
    if (fwrite("abcdef", 2, 3, fixed) != 2 || ferror(fixed) != 0 || errno != EDOM ||
        !equal_bytes(fixed_bytes, "abcd", 4))
        goto close_live;
    if (fwrite("ABCD", 2, 2, stream) != 1 || ferror(stream) != 0 || errno != EDOM ||
        cookie.position != 2 || cookie.length != 2 || !equal_bytes(cookie.bytes, "AB", 2) ||
        cookie.failed || callback_tls != tls)
        goto close_live;
    result = 0;
close_live:
    if (stream != NULL && fclose(stream) != 0)
        result = 2;
    if (fixed != NULL && fclose(fixed) != 0)
        result = 3;
    return result;
}

static int memory_cookie_composition(int tls)
{
    char fixed_bytes[32] = { 0 };
    char observed[9];
    char *grown = NULL;
    size_t length = 0;
    struct live_cookie cookie = { .tls = tls };
    cookie_io_functions_t functions = { live_read, live_write, live_seek, live_close };
    FILE *fixed = fmemopen(fixed_bytes, sizeof(fixed_bytes), "w+");
    FILE *stream = NULL;
    size_t index;
    int result = 1;

    cookie.nested = open_memstream(&grown, &length);
    if (fixed == NULL || cookie.nested == NULL)
        goto close_live;
    stream = fopencookie(&cookie, "w+", functions);
    result = 2;
    if (stream == NULL || fwide(stream, -1) >= 0 ||
        fwrite("callback", 1, 8, stream) != 8 || fflush(stream) != 0 ||
        fseek(stream, 0, SEEK_SET) != 0 || fread(observed, 1, 8, stream) != 8 ||
        !equal_bytes(observed, "callback", 8))
        goto close_live;
    result = fclose(stream);
    stream = NULL;
    if (result != 0 || cookie.closed != 1 || cookie.failed) {
        result = 3;
        goto close_live;
    }
    result = 4;
    if (fflush(cookie.nested) != 0 || length == 0 || grown[length] != '\0')
        goto close_live;
    for (index = 0; index != length; ++index)
        if (grown[index] != 'C')
            goto close_live;
    result = fclose(cookie.nested);
    cookie.nested = NULL;
    if (result != 0 || grown[length] != '\0') {
        result = 5;
        goto close_live;
    }
    result = 6;
    if (fwrite("memory", 1, 6, fixed) != 6 || fflush(fixed) != 0 ||
        !equal_bytes(fixed_bytes, "memory\0", 7) || fseek(fixed, 0, SEEK_SET) != 0 ||
        fread(observed, 1, 6, fixed) != 6 || !equal_bytes(observed, "memory", 6))
        goto close_live;
    result = 0;
close_live:
    /* Even a failed assertion retires borrowed FILE state before its stack
     * objects end. The nested stream remains available through cookie close. */
    if (stream != NULL && fclose(stream) != 0)
        result = 7;
    if (cookie.nested != NULL && fclose(cookie.nested) != 0)
        result = 8;
    if (fixed != NULL && fclose(fixed) != 0)
        result = 9;
    free(grown);
    return result;
}

static void *callback_worker(void *opaque)
{
    int *result = opaque;
    callback_tls = 31;
    *result = memory_cookie_composition(31);
    if (*result == 0)
        *result = short_write_composition(31);
    return opaque;
}

static struct live_cookie exit_cookie = { .tls = 17 };
static char exit_buffer[128];
static int exit_handler_observed;

static void ordinary_exit_handler(void)
{
    exit_handler_observed = callback_client(&exit_cookie) == 0;
}

/* Static cookie state and buffering outlive main. Only raw descriptor output
 * is used while exit holds the stream registry lock. The transcript proves
 * the pending callback ran after the ordinary exit handler. */
static ssize_t exit_write(void *opaque, const char *bytes, size_t count)
{
    static const char transcript[] = "owned-stdio-products-ok\n";
    struct live_cookie *cookie = opaque;
    size_t written = 0;

    /* A flush may invoke the cookie with an empty pending region as well. */
    if (count == 0)
        return 0;
    if (!exit_handler_observed || callback_client(cookie) != 0 || count != 4 ||
        !equal_bytes(bytes, "exit", 4))
        _Exit(87);
    while (written != sizeof(transcript) - 1) {
        ssize_t step = write(STDOUT_FILENO, transcript + written,
            sizeof(transcript) - 1 - written);
        if (step <= 0)
            _Exit(88);
        written += (size_t)step;
    }
    return (ssize_t)count;
}

int main(int argc, char **argv)
{
    pthread_t worker;
    void *worker_result = NULL;
    int result = -1;
    FILE *pending;
    cookie_io_functions_t functions = { NULL, exit_write, NULL, NULL };

    if (argc != 4)
        return 80;
    if (byte_stream(argv[1], argv[2]) != 0)
        return 81;
    if (fopen64_macro_consumer(argv[1]) != 0)
        return 82;
    if (wide_stream(argv[3]) != 0)
        return 83;
    if (memory_cookie_composition(17) != 0 || short_write_composition(17) != 0 ||
        pthread_create(&worker, NULL, callback_worker, &result) != 0 ||
        pthread_join(worker, &worker_result) != 0 || worker_result != &result ||
        result != 0 || callback_tls != 17)
        return 84;
    if (fileno(stdin) != STDIN_FILENO || fileno(stdout) != STDOUT_FILENO ||
        fileno(stderr) != STDERR_FILENO || fprintf(stdout, "%s", "") != 0 ||
        fflush(stdout) != 0)
        return 85;
    pending = fopencookie(&exit_cookie, "w", functions);
    if (pending == NULL || setvbuf(pending, exit_buffer, _IOFBF, sizeof(exit_buffer)) != 0 ||
        atexit(ordinary_exit_handler) != 0 || fwrite("exit", 1, 4, pending) != 4 ||
        exit_handler_observed)
        return 86;
    return 0;
}
