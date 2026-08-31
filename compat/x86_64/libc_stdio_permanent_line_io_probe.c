/* Static x86-64 permanent-standard-stream line-I/O regression fixture.
 *
 * The same project-header source first executes through pinned musl 1.2.6,
 * then through one true -nostdlib/-static crabc archive. It proves only the
 * selected fgets/fputs/puts behavior on the three permanent standard streams:
 * newline-bounded input, the one-byte fgets boundary, EOF-before-a-byte,
 * musl's permanent-stdout `puts` newline visibility, an fputs newline/suffix
 * visible only after explicit fflush, and direct stderr output.
 * It does not use or select pathname, descriptor-adoption/reopen, tmpfile,
 * LFS, locking, memory/cookie/popen, wide, formatted, or multiple-stream I/O.
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

typedef int (*close_fn)(int);
typedef int (*dup_fn)(int);
typedef int (*dup2_fn)(int, int);
typedef int (*fcntl_fn)(int, int, ...);
typedef int (*fflush_fn)(FILE *);
typedef int (*feof_fn)(FILE *);
typedef char *(*fgets_fn)(char *, int, FILE *);
typedef int (*fputs_fn)(const char *, FILE *);
typedef int (*pipe_fn)(int *);
typedef int (*puts_fn)(const char *);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef ssize_t (*write_fn)(int, const void *, size_t);
typedef void (*clearerr_fn)(FILE *);

static close_fn volatile close_entry = close;
static dup_fn volatile dup_entry = dup;
static dup2_fn volatile dup2_entry = dup2;
static fcntl_fn volatile fcntl_entry = fcntl;
static fflush_fn volatile fflush_entry = fflush;
static feof_fn volatile feof_entry = feof;
static fgets_fn volatile fgets_entry = fgets;
static fputs_fn volatile fputs_entry = fputs;
static pipe_fn volatile pipe_entry = pipe;
static puts_fn volatile puts_entry = puts;
static read_fn volatile read_entry = read;
static write_fn volatile write_entry = write;
static clearerr_fn volatile clearerr_entry = clearerr;

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

static int make_nonblocking(int descriptor)
{
    int flags = fcntl_entry(descriptor, F_GETFL);

    if (flags < 0)
        return -1;
    return fcntl_entry(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

static int expect_pipe_empty(int descriptor)
{
    char byte;
    ssize_t result = read_entry(descriptor, &byte, 1);

    return result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
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

static int check_fgets_permanent_stdin(void)
{
    static const char input[] = "ab\ncd\n";
    char line[8] = {0};
    int saved = -1;
    int status = 0;

    if (redirect_input(input, sizeof(input) - 1U, &saved) != 0)
        return 1;
    if (fgets_entry(line, 3, stdin) != line ||
        !bytes_equal(line, "ab\0", 3)) {
        status = 2;
        goto cleanup;
    }
    if (fgets_entry(line, 1, stdin) != line || line[0] != '\0') {
        status = 3;
        goto cleanup;
    }
    if (fgets_entry(line, 4, stdin) != line ||
        !bytes_equal(line, "\n\0", 2)) {
        status = 4;
        goto cleanup;
    }
    if (fgets_entry(line, 4, stdin) != line ||
        !bytes_equal(line, "cd\n\0", 4)) {
        status = 5;
        goto cleanup;
    }
    if (fgets_entry(line, 4, stdin) != NULL || feof_entry(stdin) == 0) {
        status = 6;
        goto cleanup;
    }

cleanup:
    if (restore_descriptor(STDIN_FILENO, saved) != 0 && status == 0)
        status = 7;
    clearerr_entry(stdin);
    return status;
}

static int check_fputs_puts_permanent_stdout(void)
{
    static const char puts_expected[] = "firstsecond\n";
    static const char flush_expected[] = "third\ntail";
    int saved = -1;
    int reader = -1;
    int status = 0;

    if (redirect_output(STDOUT_FILENO, &saved, &reader) != 0)
        return 1;
    if (make_nonblocking(reader) != 0) {
        status = 2;
        goto cleanup;
    }
    if (fputs_entry("first", stdout) < 0) {
        status = 3;
        goto cleanup;
    }
    if (expect_pipe_empty(reader) != 0) {
        status = 4;
        goto cleanup;
    }
    if (puts_entry("second") < 0 ||
        expect_pipe_bytes(reader, puts_expected, sizeof(puts_expected) - 1U) != 0) {
        status = 5;
        goto cleanup;
    }
    if (fputs_entry("third\n", stdout) < 0 ||
        expect_pipe_empty(reader) != 0) {
        status = 6;
        goto cleanup;
    }
    if (fputs_entry("tail", stdout) < 0 || fputs_entry("", stdout) < 0 ||
        expect_pipe_empty(reader) != 0) {
        status = 7;
        goto cleanup;
    }
    if (fflush_entry(stdout) != 0 ||
        expect_pipe_bytes(reader, flush_expected, sizeof(flush_expected) - 1U) != 0) {
        status = 8;
        goto cleanup;
    }

cleanup:
    if (reader >= 0 && close_entry(reader) != 0 && status == 0)
        status = 9;
    if (restore_descriptor(STDOUT_FILENO, saved) != 0 && status == 0)
        status = 10;
    clearerr_entry(stdout);
    return status;
}

static int check_fputs_permanent_stderr(void)
{
    static const char expected[] = "error";
    int saved = -1;
    int reader = -1;
    int status = 0;

    if (redirect_output(STDERR_FILENO, &saved, &reader) != 0)
        return 1;
    if (fputs_entry(expected, stderr) < 0 ||
        expect_pipe_bytes(reader, expected, sizeof(expected) - 1U) != 0) {
        status = 2;
        goto cleanup;
    }

cleanup:
    if (reader >= 0 && close_entry(reader) != 0 && status == 0)
        status = 3;
    if (restore_descriptor(STDERR_FILENO, saved) != 0 && status == 0)
        status = 4;
    clearerr_entry(stderr);
    return status;
}

int crabc_x86_64_stdio_permanent_line_io_probe(void)
{
    int status;

    status = check_fgets_permanent_stdin();
    if (status != 0)
        return status;
    status = check_fputs_puts_permanent_stdout();
    if (status != 0)
        return 32 + status;
    status = check_fputs_permanent_stderr();
    return status == 0 ? 0 : 64 + status;
}

#ifndef CRABC_STDIO_PERMANENT_LINE_IO_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_line_io_probe();
}
#endif
