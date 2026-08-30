/* Static x86-64 permanent-standard-stream behavior fixture.
 *
 * This is deliberately not a general stdio fixture.  It exercises only the
 * three process-permanent globals (`stdin`, `stdout`, and `stderr`) and the
 * allocation-free descriptor interactions needed to observe them.  A later
 * runner must first execute this exact source against pinned musl 1.2.6,
 * release commit 9fa28ece75d8a2191de7c5bb53bed224c5947417, then link it as a
 * true `-nostdlib -static` candidate against the selected crabc archive.
 *
 * The selected contract is explicit-flush-only for the permanent output
 * streams: stdout's small writes remain in its stream buffer until an
 * explicit `fflush(stdout)` or `fflush(NULL)`, while stderr writes are
 * immediately observable.  It does not select path streams, caller-selected
 * buffering, formatted I/O, exit-time flushing, locks, allocation, wide I/O,
 * a general FILE ABI, CRT behavior, or a general C runtime.
 *
 * Every callable C boundary is reached through a volatile function pointer.
 * That prevents compiler builtins or an ambient libc from satisfying the
 * future freestanding candidate checks in place of the selected symbols.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(STDIN_FILENO == 0 && STDOUT_FILENO == 1 && STDERR_FILENO == 2,
    "Linux standard descriptor numbers");
_Static_assert(sizeof(int) == 4 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");

typedef int (*close_fn)(int);
typedef int (*dup_fn)(int);
typedef int (*dup2_fn)(int, int);
typedef int (*fcntl_fn)(int, int, ...);
typedef int (*fflush_fn)(FILE *);
typedef int (*ferror_fn)(FILE *);
typedef int (*feof_fn)(FILE *);
typedef int (*fgetc_fn)(FILE *);
typedef int (*fileno_fn)(FILE *);
typedef int (*fputc_fn)(int, FILE *);
typedef int (*pipe_fn)(int *);
typedef int (*ungetc_fn)(int, FILE *);
typedef size_t (*fread_fn)(void *, size_t, size_t, FILE *);
typedef size_t (*fwrite_fn)(const void *, size_t, size_t, FILE *);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef ssize_t (*write_fn)(int, const void *, size_t);
typedef void (*clearerr_fn)(FILE *);

static close_fn volatile close_entry = close;
static dup_fn volatile dup_entry = dup;
static dup2_fn volatile dup2_entry = dup2;
static fcntl_fn volatile fcntl_entry = fcntl;
static fflush_fn volatile fflush_entry = fflush;
static ferror_fn volatile ferror_entry = ferror;
static feof_fn volatile feof_entry = feof;
static fgetc_fn volatile fgetc_entry = fgetc;
static fileno_fn volatile fileno_entry = fileno;
static fputc_fn volatile fputc_entry = fputc;
static pipe_fn volatile pipe_entry = pipe;
static ungetc_fn volatile ungetc_entry = ungetc;
static fread_fn volatile fread_entry = fread;
static fwrite_fn volatile fwrite_entry = fwrite;
static read_fn volatile read_entry = read;
static write_fn volatile write_entry = write;
static clearerr_fn volatile clearerr_entry = clearerr;

/* A saved descriptor of -1 records that the inherited target was already
 * closed.  The fixture restores that closed state rather than assuming a
 * shell supplied all three descriptors. */
static int save_descriptor(int descriptor, int *saved)
{
    *saved = dup_entry(descriptor);
    if (*saved >= 0)
        return 0;
    return errno == EBADF ? 0 : -1;
}

static int restore_descriptor(int descriptor, int saved)
{
    if (saved < 0) {
        if (close_entry(descriptor) == 0 || errno == EBADF)
            return 0;
        return -1;
    }
    if (dup2_entry(saved, descriptor) != descriptor) {
        (void)close_entry(saved);
        return -1;
    }
    return close_entry(saved) == 0 ? 0 : -1;
}

static int write_all(int descriptor, const char *bytes, size_t length)
{
    size_t written = 0;

    while (written != length) {
        ssize_t result = write_entry(descriptor, bytes + written,
            length - written);

        if (result > 0) {
            written += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR)
            continue;
        return -1;
    }
    return 0;
}

static int make_nonblocking(int descriptor)
{
    int flags = fcntl_entry(descriptor, F_GETFL);

    if (flags < 0)
        return -1;
    return fcntl_entry(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

static int bytes_equal(const char *actual, const char *expected, size_t length)
{
    size_t index;

    for (index = 0; index != length; ++index) {
        if (actual[index] != expected[index])
            return 0;
    }
    return 1;
}

static int expect_pipe_empty(int descriptor)
{
    char byte;

    errno = 0;
    if (read_entry(descriptor, &byte, sizeof(byte)) != -1)
        return -1;
    return errno == EAGAIN ? 0 : -1;
}

static int expect_pipe_bytes(int descriptor, const char *expected, size_t length)
{
    char observed[8];
    ssize_t result;

    if (length > sizeof(observed))
        return -1;
    result = read_entry(descriptor, observed, length);
    if (result != (ssize_t)length)
        return -1;
    return bytes_equal(observed, expected, length) ? 0 : -1;
}

/* Redirect one standard output descriptor to a fresh pipe and retain its read
 * end.  If the inherited target was closed, pipe(2) may allocate that number
 * to the read end; duplicate it before dup2 replaces that descriptor. */
static int redirect_output_to_pipe(int descriptor, int *saved, int *reader)
{
    int pipe_descriptors[2] = {-1, -1};

    *reader = -1;
    if (save_descriptor(descriptor, saved) != 0)
        return -1;
    if (pipe_entry(pipe_descriptors) != 0)
        goto failure;
    if (pipe_descriptors[0] == descriptor) {
        *reader = dup_entry(pipe_descriptors[0]);
        if (*reader < 0)
            goto failure;
    } else {
        *reader = pipe_descriptors[0];
    }
    if (dup2_entry(pipe_descriptors[1], descriptor) != descriptor)
        goto failure;
    if (pipe_descriptors[1] != descriptor &&
        close_entry(pipe_descriptors[1]) != 0)
        goto failure;
    return 0;

failure:
    if (*reader >= 0 && *reader != pipe_descriptors[0])
        (void)close_entry(*reader);
    if (pipe_descriptors[0] != descriptor)
        (void)close_entry(pipe_descriptors[0]);
    if (pipe_descriptors[1] != descriptor)
        (void)close_entry(pipe_descriptors[1]);
    (void)restore_descriptor(descriptor, *saved);
    *reader = -1;
    return -1;
}

static int check_standard_globals(void)
{
    FILE *input = stdin;
    FILE *output = stdout;
    FILE *error = stderr;

    if (input == NULL || output == NULL || error == NULL)
        return 1;
    if (input == output || input == error || output == error)
        return 2;
    if (fileno_entry(input) != STDIN_FILENO)
        return 3;
    if (fileno_entry(output) != STDOUT_FILENO)
        return 4;
    if (fileno_entry(error) != STDERR_FILENO)
        return 5;
    /* Musl's ungetc first enters read mode, so the non-readable permanent
     * output stream records F_ERR rather than silently returning EOF. */
    if (ungetc_entry('X', output) != EOF || ferror_entry(output) == 0)
        return 6;
    clearerr_entry(output);
    return ferror_entry(output) == 0 ? 0 : 7;
}

static int check_stdin_buffering_and_ebadf(void)
{
    static const char payload[] = "abcd";
    static const char replacement_payload[] = "Q";
    int pipe_descriptors[2] = {-1, -1};
    int replacement_descriptors[2] = {-1, -1};
    int saved = -1;
    char bytes[2];
    int status = 0;

    if (save_descriptor(STDIN_FILENO, &saved) != 0)
        return 1;
    if (pipe_entry(pipe_descriptors) != 0) {
        status = 2;
        goto cleanup;
    }
    if (write_all(pipe_descriptors[1], payload, sizeof(payload) - 1U) != 0) {
        status = 3;
        goto cleanup;
    }
    if (close_entry(pipe_descriptors[1]) != 0) {
        status = 4;
        goto cleanup;
    }
    pipe_descriptors[1] = -1;
    if (pipe_descriptors[0] != STDIN_FILENO &&
        dup2_entry(pipe_descriptors[0], STDIN_FILENO) != STDIN_FILENO) {
        status = 5;
        goto cleanup;
    }
    if (pipe_descriptors[0] != STDIN_FILENO &&
        close_entry(pipe_descriptors[0]) != 0) {
        status = 6;
        goto cleanup;
    }
    pipe_descriptors[0] = -1;

    /* fread is deliberately the first input operation. Its two-byte request
     * drives the selected readv-plus-lookahead path instead of a one-byte
     * read fallback; the later fgetc calls must drain the retained suffix. */
    if (fread_entry(bytes, 1, sizeof(bytes), stdin) != sizeof(bytes) ||
        bytes[0] != 'a' || bytes[1] != 'b') {
        status = 10;
        goto cleanup;
    }
    if (fgetc_entry(stdin) != 'c' || fgetc_entry(stdin) != 'd') {
        status = 11;
        goto cleanup;
    }
    if (fgetc_entry(stdin) != EOF || feof_entry(stdin) == 0 ||
        ferror_entry(stdin) != 0) {
        status = 12;
        goto cleanup;
    }
    clearerr_entry(stdin);
    if (feof_entry(stdin) != 0 || ferror_entry(stdin) != 0) {
        status = 13;
        goto cleanup;
    }
    if (ungetc_entry('Z', stdin) != 'Z' || feof_entry(stdin) != 0 ||
        ferror_entry(stdin) != 0 || fgetc_entry(stdin) != 'Z') {
        status = 14;
        goto cleanup;
    }
    if (fgetc_entry(stdin) != EOF || feof_entry(stdin) == 0 ||
        ferror_entry(stdin) != 0) {
        status = 15;
        goto cleanup;
    }

    /* EOF is sticky. Replacing descriptor zero with readable input cannot
     * make a selected stream issue another read before clearerr or ungetc. */
    if (pipe_entry(replacement_descriptors) != 0) {
        status = 16;
        goto cleanup;
    }
    if (write_all(replacement_descriptors[1], replacement_payload,
        sizeof(replacement_payload) - 1U) != 0 ||
        close_entry(replacement_descriptors[1]) != 0) {
        status = 17;
        goto cleanup;
    }
    replacement_descriptors[1] = -1;
    if (replacement_descriptors[0] != STDIN_FILENO &&
        dup2_entry(replacement_descriptors[0], STDIN_FILENO) != STDIN_FILENO) {
        status = 18;
        goto cleanup;
    }
    if (replacement_descriptors[0] != STDIN_FILENO &&
        close_entry(replacement_descriptors[0]) != 0) {
        status = 19;
        goto cleanup;
    }
    replacement_descriptors[0] = -1;
    if (fgetc_entry(stdin) != EOF || feof_entry(stdin) == 0 ||
        ferror_entry(stdin) != 0) {
        status = 20;
        goto cleanup;
    }
    clearerr_entry(stdin);
    if (fgetc_entry(stdin) != 'Q') {
        status = 21;
        goto cleanup;
    }
    /* `ungetc` returns the converted unsigned-byte value, not its original
     * out-of-range int argument. */
    if (ungetc_entry(-2, stdin) != 254 || fgetc_entry(stdin) != 254) {
        status = 22;
        goto cleanup;
    }

    /* The stream has no buffered bytes left.  Closing descriptor zero must
     * therefore turn the next read into EBADF, set only the error indicator,
     * and leave the end indicator clear. */
    clearerr_entry(stdin);
    if (close_entry(STDIN_FILENO) != 0) {
        status = 23;
        goto cleanup;
    }
    errno = 0;
    if (fgetc_entry(stdin) != EOF) {
        status = 24;
        goto cleanup;
    }
    if (errno != EBADF) {
        status = 25;
        goto cleanup;
    }
    if (ferror_entry(stdin) == 0) {
        status = 26;
        goto cleanup;
    }
    if (feof_entry(stdin) != 0) {
        status = 27;
        goto cleanup;
    }
    clearerr_entry(stdin);

cleanup:
    if (pipe_descriptors[0] >= 0)
        (void)close_entry(pipe_descriptors[0]);
    if (pipe_descriptors[1] >= 0)
        (void)close_entry(pipe_descriptors[1]);
    if (replacement_descriptors[0] >= 0)
        (void)close_entry(replacement_descriptors[0]);
    if (replacement_descriptors[1] >= 0)
        (void)close_entry(replacement_descriptors[1]);
    if (restore_descriptor(STDIN_FILENO, saved) != 0 && status == 0)
        status = 28;
    clearerr_entry(stdin);
    return status;
}

static int check_stdout_explicit_flush(void)
{
    static const char first[] = "out";
    static const char second[] = "all";
    int saved = -1;
    int reader = -1;
    int status = 0;

    if (redirect_output_to_pipe(STDOUT_FILENO, &saved, &reader) != 0)
        return 1;
    if (make_nonblocking(reader) != 0) {
        status = 2;
        goto cleanup;
    }
    if (fwrite_entry(first, 1, sizeof(first) - 1U, stdout) !=
            sizeof(first) - 1U ||
        fputc_entry('!', stdout) != '!') {
        status = 3;
        goto cleanup;
    }
    if (expect_pipe_empty(reader) != 0) {
        status = 4;
        goto cleanup;
    }
    if (fflush_entry(stdout) != 0 ||
        expect_pipe_bytes(reader, "out!", 4) != 0 ||
        ferror_entry(stdout) != 0) {
        status = 5;
        goto cleanup;
    }

    if (fwrite_entry(second, 1, sizeof(second) - 1U, stdout) !=
        sizeof(second) - 1U) {
        status = 6;
        goto cleanup;
    }
    if (expect_pipe_empty(reader) != 0) {
        status = 7;
        goto cleanup;
    }
    /* `NULL` must visit permanent output globals as well as the direct
     * stdout form above.  stderr has no pending bytes by design. */
    if (fflush_entry(NULL) != 0 ||
        expect_pipe_bytes(reader, second, sizeof(second) - 1U) != 0 ||
        ferror_entry(stdout) != 0) {
        status = 8;
        goto cleanup;
    }

cleanup:
    if (restore_descriptor(STDOUT_FILENO, saved) != 0 && status == 0)
        status = 9;
    if (reader >= 0 && close_entry(reader) != 0 && status == 0)
        status = 10;
    return status;
}

static int check_stdout_failed_flush_discards_bytes(void)
{
    static const char tail[] = "tail";
    int saved = -1;
    int reader = -1;
    int writer = -1;
    int status = 0;

    if (redirect_output_to_pipe(STDOUT_FILENO, &saved, &reader) != 0)
        return 1;
    if (make_nonblocking(reader) != 0) {
        status = 2;
        goto cleanup;
    }
    /* Keep a duplicate of the pipe writer so the same descriptor number can
     * be made invalid for fflush and then recovered without changing the
     * permanent stdout object's descriptor identity. */
    writer = dup_entry(STDOUT_FILENO);
    if (writer < 0) {
        status = 3;
        goto cleanup;
    }
    if (fwrite_entry(tail, 1, sizeof(tail) - 1U, stdout) !=
        sizeof(tail) - 1U) {
        status = 4;
        goto cleanup;
    }
    if (close_entry(STDOUT_FILENO) != 0) {
        status = 5;
        goto cleanup;
    }
    errno = 0;
    if (fflush_entry(stdout) != EOF || errno != EBADF ||
        ferror_entry(stdout) == 0) {
        status = 6;
        goto cleanup;
    }
    if (dup2_entry(writer, STDOUT_FILENO) != STDOUT_FILENO) {
        status = 7;
        goto cleanup;
    }
    if (close_entry(writer) != 0) {
        status = 8;
        goto cleanup;
    }
    writer = -1;
    clearerr_entry(stdout);
    /* Musl's __stdio_write clears its output cursors on an error. A retry
     * after clearerr therefore observes an empty stream buffer, not tail. */
    if (fflush_entry(stdout) != 0 || ferror_entry(stdout) != 0 ||
        expect_pipe_empty(reader) != 0) {
        status = 9;
        goto cleanup;
    }

cleanup:
    if (writer >= 0)
        (void)close_entry(writer);
    if (restore_descriptor(STDOUT_FILENO, saved) != 0 && status == 0)
        status = 10;
    if (reader >= 0 && close_entry(reader) != 0 && status == 0)
        status = 11;
    return status;
}

static int check_stderr_immediate(void)
{
    int saved = -1;
    int reader = -1;
    int status = 0;

    if (redirect_output_to_pipe(STDERR_FILENO, &saved, &reader) != 0)
        return 1;
    if (make_nonblocking(reader) != 0) {
        status = 2;
        goto cleanup;
    }
    if (fputc_entry('E', stderr) != 'E') {
        status = 3;
        goto cleanup;
    }
    /* No fflush call precedes this read: permanent stderr must be immediate. */
    if (expect_pipe_bytes(reader, "E", 1) != 0 || ferror_entry(stderr) != 0) {
        status = 4;
        goto cleanup;
    }

cleanup:
    if (restore_descriptor(STDERR_FILENO, saved) != 0 && status == 0)
        status = 5;
    if (reader >= 0 && close_entry(reader) != 0 && status == 0)
        status = 6;
    return status;
}

int crabc_x86_64_stdio_standard_probe(void)
{
    int status = check_standard_globals();

    if (status != 0)
        return status;
    status = check_stdin_buffering_and_ebadf();
    if (status != 0)
        return 100 + status;
    status = check_stdout_explicit_flush();
    if (status != 0)
        return 200 + status;
    status = check_stdout_failed_flush_discards_bytes();
    if (status != 0)
        return 300 + status;
    status = check_stderr_immediate();
    return status == 0 ? 0 : 400 + status;
}

#ifndef CRABC_STDIO_STANDARD_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_standard_probe();
}
#endif
