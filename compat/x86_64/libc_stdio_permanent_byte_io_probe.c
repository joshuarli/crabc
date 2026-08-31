/* Static x86-64 permanent-standard-stream byte-I/O regression fixture.
 *
 * The same project-header source first executes through pinned musl 1.2.6,
 * then through one true -nostdlib/-static crabc archive. It proves only the
 * shared strong fgetc/getc/getchar and fputc/putc/putchar entries when their
 * calls use the process-lifetime standard streams. One successful non-EOF
 * ungetc after EOF proves its unsigned-byte result and EOF-clearing transition.
 *
 * Pipe and descriptor transport merely observes those permanent descriptors.
 * This fixture never creates a FILE stream and does not select pathname,
 * descriptor-adoption/reopen, tmpfile, block I/O, buffer configuration,
 * locking/unlocked, formatted/wide, memory/cookie/popen, or multiple-stream
 * behavior.
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

typedef int (*close_fn)(int);
typedef int (*dup_fn)(int);
typedef int (*dup2_fn)(int, int);
typedef int (*fflush_fn)(FILE *);
typedef int (*input_character_fn)(FILE *);
typedef int (*getchar_fn)(void);
typedef int (*output_character_fn)(int, FILE *);
typedef int (*putchar_fn)(int);
typedef int (*pipe_fn)(int *);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef int (*ungetc_fn)(int, FILE *);
typedef ssize_t (*write_fn)(int, const void *, size_t);

static close_fn volatile close_entry = close;
static dup_fn volatile dup_entry = dup;
static dup2_fn volatile dup2_entry = dup2;
static fflush_fn volatile fflush_entry = fflush;
static input_character_fn volatile fgetc_entry = fgetc;
static input_character_fn volatile getc_entry = getc;
static getchar_fn volatile getchar_entry = getchar;
static output_character_fn volatile fputc_entry = fputc;
static output_character_fn volatile putc_entry = putc;
static putchar_fn volatile putchar_entry = putchar;
static pipe_fn volatile pipe_entry = pipe;
static read_fn volatile read_entry = read;
static ungetc_fn volatile ungetc_entry = ungetc;
static write_fn volatile write_entry = write;

static int bytes_equal(const char *actual, const char *expected, size_t length)
{
    size_t index;

    for (index = 0; index != length; ++index)
        if (actual[index] != expected[index])
            return 0;
    return 1;
}

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

static int redirect_input(const char *bytes, size_t length, int *saved)
{
    int descriptors[2] = {-1, -1};
    int status = -1;

    if (save_descriptor(STDIN_FILENO, saved) != 0 ||
        pipe_entry(descriptors) != 0)
        goto cleanup;
    if (write_all(descriptors[1], bytes, length) != 0 ||
        close_entry(descriptors[1]) != 0)
        goto cleanup;
    descriptors[1] = -1;
    if (descriptors[0] != STDIN_FILENO &&
        dup2_entry(descriptors[0], STDIN_FILENO) != STDIN_FILENO)
        goto cleanup;
    if (descriptors[0] != STDIN_FILENO && close_entry(descriptors[0]) != 0)
        goto cleanup;
    descriptors[0] = -1;
    status = 0;

cleanup:
    if (descriptors[0] >= 0)
        (void)close_entry(descriptors[0]);
    if (descriptors[1] >= 0)
        (void)close_entry(descriptors[1]);
    return status;
}

static int redirect_output(int descriptor, int *saved, int *reader)
{
    int descriptors[2] = {-1, -1};
    int status = -1;

    *reader = -1;
    if (save_descriptor(descriptor, saved) != 0 || pipe_entry(descriptors) != 0)
        goto cleanup;
    if (descriptors[1] != descriptor &&
        dup2_entry(descriptors[1], descriptor) != descriptor)
        goto cleanup;
    if (descriptors[1] != descriptor && close_entry(descriptors[1]) != 0)
        goto cleanup;
    descriptors[1] = -1;
    *reader = descriptors[0];
    descriptors[0] = -1;
    status = 0;

cleanup:
    if (descriptors[0] >= 0)
        (void)close_entry(descriptors[0]);
    if (descriptors[1] >= 0)
        (void)close_entry(descriptors[1]);
    return status;
}

static int expect_pipe_bytes(int descriptor, const char *expected, size_t length)
{
    size_t received = 0;

    while (received != length) {
        char buffer[16];
        size_t requested = length - received;
        ssize_t result;

        if (requested > sizeof(buffer))
            requested = sizeof(buffer);
        result = read_entry(descriptor, buffer, requested);
        if (result > 0) {
            if (!bytes_equal(buffer, expected + received, (size_t)result))
                return -1;
            received += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR)
            continue;
        return -1;
    }
    return 0;
}

static int check_input_aliases_and_one_byte_ungetc(void)
{
    static const char payload[] = {'A', 'B'};
    int saved = -1;
    int status = 0;

    if (redirect_input(payload, sizeof(payload), &saved) != 0)
        return 1;
    if (fgetc_entry(stdin) != 'A') {
        status = 2;
        goto cleanup;
    }
    if (getc_entry(stdin) != 'B') {
        status = 3;
        goto cleanup;
    }
    if (getchar_entry() != EOF) {
        status = 4;
        goto cleanup;
    }
    /* Musl's ungetc returns the converted unsigned byte and clears the EOF
     * flag. This artifact proves one such transition, not pushback capacity. */
    if (ungetc_entry(-2, stdin) != 254 || getchar_entry() != 254) {
        status = 5;
        goto cleanup;
    }
    if (fgetc_entry(stdin) != EOF)
        status = 6;

cleanup:
    if (restore_descriptor(STDIN_FILENO, saved) != 0 && status == 0)
        status = 7;
    return status;
}

static int check_fputc_putc_on_permanent_stderr(void)
{
    static const char expected[] = {(char)254, 'C'};
    int saved = -1;
    int reader = -1;
    int status = 0;

    if (redirect_output(STDERR_FILENO, &saved, &reader) != 0)
        return 1;
    if (fputc_entry(-2, stderr) != 254 || putc_entry('C', stderr) != 'C' ||
        expect_pipe_bytes(reader, expected, sizeof(expected)) != 0) {
        status = 2;
        goto cleanup;
    }

cleanup:
    if (reader >= 0 && close_entry(reader) != 0 && status == 0)
        status = 3;
    if (restore_descriptor(STDERR_FILENO, saved) != 0 && status == 0)
        status = 4;
    return status;
}

static int check_putchar_on_permanent_stdout(void)
{
    static const char expected[] = "P";
    int saved = -1;
    int reader = -1;
    int status = 0;

    if (redirect_output(STDOUT_FILENO, &saved, &reader) != 0)
        return 1;
    if (putchar_entry('P') != 'P' || fflush_entry(stdout) != 0 ||
        expect_pipe_bytes(reader, expected, sizeof(expected) - 1U) != 0) {
        status = 2;
        goto cleanup;
    }

cleanup:
    if (reader >= 0 && close_entry(reader) != 0 && status == 0)
        status = 3;
    if (restore_descriptor(STDOUT_FILENO, saved) != 0 && status == 0)
        status = 4;
    return status;
}

int crabc_x86_64_stdio_permanent_byte_io_probe(void)
{
    int status;

    status = check_input_aliases_and_one_byte_ungetc();
    if (status != 0)
        return status;
    status = check_fputc_putc_on_permanent_stderr();
    if (status != 0)
        return 32 + status;
    status = check_putchar_on_permanent_stdout();
    return status == 0 ? 0 : 64 + status;
}

#ifndef CRABC_STDIO_PERMANENT_BYTE_IO_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_byte_io_probe();
}
#endif
