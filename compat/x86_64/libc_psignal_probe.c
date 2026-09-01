/* Static x86-64 psignal/psiginfo regression fixture.
 *
 * One project-header body runs through pinned musl 1.2.6 first and then one
 * true -nostdlib/-static crabc archive.  It captures only the reporting
 * bytes through a pipe, proving the non-null/null prefix forms, known and
 * unknown signal descriptions, psiginfo's si_signo forwarding, a terminating
 * newline, success-only errno preservation, and closed-stderr/nonblocking
 * full-pipe output failures. It does not select general diagnostics or a
 * general stdio API.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
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
typedef int (*pipe_fn)(int [2]);
typedef void (*psignal_fn)(int, const char *);
typedef void (*psiginfo_fn)(const siginfo_t *, const char *);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef ssize_t (*write_fn)(int, const void *, size_t);

static close_fn volatile close_entry = close;
static dup_fn volatile dup_entry = dup;
static dup2_fn volatile dup2_entry = dup2;
static fcntl_fn volatile fcntl_entry = fcntl;
static pipe_fn volatile pipe_entry = pipe;
static psignal_fn volatile psignal_entry = psignal;
static psiginfo_fn volatile psiginfo_entry = psiginfo;
static read_fn volatile read_entry = read;
static write_fn volatile write_entry = write;

static int bytes_equal(const char *actual, const char *expected, size_t length)
{
    size_t index;

    for (index = 0; index != length; ++index)
        if (actual[index] != expected[index])
            return 0;
    return 1;
}

static int restore_stderr(int saved)
{
    if (dup2_entry(saved, STDERR_FILENO) != STDERR_FILENO) {
        (void)close_entry(saved);
        return -1;
    }
    return close_entry(saved) == 0 ? 0 : -1;
}

static int expect_pipe_bytes(int descriptor, const char *expected, size_t length)
{
    size_t received = 0;

    while (received != length) {
        char buffer[17];
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

    for (;;) {
        char byte;
        ssize_t result = read_entry(descriptor, &byte, 1);

        if (result == 0)
            return 0;
        if (result < 0 && errno == EINTR)
            continue;
        return -1;
    }
}

static int reporting_success_case(void)
{
    static const char expected[] =
        "notice: User defined signal 1\n"
        "Unknown signal\n"
        "term: Terminated\n"
        "unknown: Unknown signal\n";
    int descriptors[2] = {-1, -1};
    int saved = -1;
    siginfo_t information;
    int status = 0;

    saved = dup_entry(STDERR_FILENO);
    if (saved < 0 || pipe_entry(descriptors) != 0) {
        status = 1;
        goto cleanup;
    }
    if (dup2_entry(descriptors[1], STDERR_FILENO) != STDERR_FILENO ||
        close_entry(descriptors[1]) != 0) {
        status = 2;
        goto cleanup;
    }
    descriptors[1] = -1;

    errno = EALREADY;
    psignal_entry(SIGUSR1, "notice");
    if (errno != EALREADY) {
        status = 3;
        goto cleanup;
    }
    errno = ENOTTY;
    psignal_entry(0, 0);
    if (errno != ENOTTY) {
        status = 4;
        goto cleanup;
    }
    information.si_signo = SIGTERM;
    errno = EAGAIN;
    psiginfo_entry(&information, "term");
    if (errno != EAGAIN) {
        status = 5;
        goto cleanup;
    }
    errno = ECHILD;
    psignal_entry(65, "unknown");
    if (errno != ECHILD) {
        status = 6;
        goto cleanup;
    }

    if (restore_stderr(saved) != 0) {
        saved = -1;
        status = 7;
        goto cleanup;
    }
    saved = -1;
    if (expect_pipe_bytes(descriptors[0], expected, sizeof(expected) - 1U) != 0)
        status = 8;

cleanup:
    if (saved >= 0 && restore_stderr(saved) != 0 && status == 0)
        status = 9;
    if (descriptors[0] >= 0 && close_entry(descriptors[0]) != 0 && status == 0)
        status = 10;
    if (descriptors[1] >= 0 && close_entry(descriptors[1]) != 0 && status == 0)
        status = 11;
    return status;
}

static int reporting_failure_case(void)
{
    int saved = dup_entry(STDERR_FILENO);
    int status = 0;

    if (saved < 0)
        return 1;
    if (close_entry(STDERR_FILENO) != 0) {
        (void)close_entry(saved);
        return 2;
    }
    errno = EALREADY;
    psignal_entry(SIGUSR1, "closed");
    if (errno != EBADF)
        status = 3;
    if (restore_stderr(saved) != 0 && status == 0)
        status = 4;
    return status;
}

/* Fill a nonblocking pipe completely, so psignal's first stderr publication
 * deterministically fails with EAGAIN. This checks the failure branch without
 * claiming parity for musl fprintf's internal-buffer partial-write mechanics.
 */
static int reporting_nonblocking_failure_case(void)
{
    static const char fill[512] = {0};
    int descriptors[2] = {-1, -1};
    int saved = -1;
    int status = 0;
    int flags;

    if (pipe_entry(descriptors) != 0)
        return 1;
    flags = fcntl_entry(descriptors[1], F_GETFL);
    if (flags < 0 ||
        fcntl_entry(descriptors[1], F_SETFL, flags | O_NONBLOCK) != 0) {
        status = 2;
        goto cleanup;
    }
    for (;;) {
        ssize_t result = write_entry(descriptors[1], fill, sizeof(fill));

        if (result > 0)
            continue;
        if (result == -1 && errno == EAGAIN)
            break;
        status = 3;
        goto cleanup;
    }
    saved = dup_entry(STDERR_FILENO);
    if (saved < 0 || dup2_entry(descriptors[1], STDERR_FILENO) != STDERR_FILENO) {
        status = 4;
        goto cleanup;
    }
    if (close_entry(descriptors[1]) != 0) {
        descriptors[1] = -1;
        status = 5;
        goto cleanup;
    }
    descriptors[1] = -1;

    errno = EALREADY;
    psignal_entry(SIGUSR1, "full");
    if (errno != EAGAIN)
        status = 6;

cleanup:
    if (saved >= 0 && restore_stderr(saved) != 0 && status == 0)
        status = 7;
    if (descriptors[0] >= 0 && close_entry(descriptors[0]) != 0 && status == 0)
        status = 8;
    if (descriptors[1] >= 0 && close_entry(descriptors[1]) != 0 && status == 0)
        status = 9;
    return status;
}

int crabc_x86_64_psignal_probe(void)
{
    int status = reporting_success_case();

    if (status != 0)
        return status;
    status = reporting_nonblocking_failure_case();
    if (status != 0)
        return 32 + status;
    status = reporting_failure_case();
    return status == 0 ? 0 : 64 + status;
}

#ifndef CRABC_PSIGNAL_FREESTANDING
int main(void)
{
    return crabc_x86_64_psignal_probe();
}
#endif
