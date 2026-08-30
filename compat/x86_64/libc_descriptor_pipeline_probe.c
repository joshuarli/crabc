/* Static crabc-libc x86-64 descriptor pipeline composition fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc `libc.a`.  It composes already-selected descriptor creation,
 * fcntl status/descriptor flags, vector transfer, duplicate ownership, and
 * poll readiness into one pipe lifecycle.  No new C API is selected: this
 * artifact proves that those independently selected archive leaves cooperate
 * with one descriptor state and one initial-TLS errno owner.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar ABI");
_Static_assert(sizeof(struct pollfd) == 8 && _Alignof(struct pollfd) == 4 &&
    offsetof(struct pollfd, fd) == 0 && offsetof(struct pollfd, events) == 4 &&
    offsetof(struct pollfd, revents) == 6, "x86 pollfd ABI");
_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8,
    "x86 iovec ABI");
_Static_assert(SYS_pipe2 == 293 && SYS_fcntl == 72 && SYS_poll == 7 &&
    SYS_readv == 19 && SYS_writev == 20 && SYS_dup == 32 && SYS_close == 3,
    "x86 selected descriptor pipeline syscalls");
_Static_assert(O_NONBLOCK == 0x800 && O_CLOEXEC == 0x80000 &&
    FD_CLOEXEC == 1 && F_GETFD == 1 && F_SETFD == 2 && F_GETFL == 3 &&
    F_SETFL == 4, "x86 descriptor flag ABI");
_Static_assert(POLLIN == 0x0001 && POLLHUP == 0x0010 && POLLNVAL == 0x0020,
    "x86 poll ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pipe2),
    int (*)(int *, int)), "pipe2 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fcntl),
    int (*)(int, int, ...)), "fcntl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&poll),
    int (*)(struct pollfd *, nfds_t, int)), "poll declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readv),
    ssize_t (*)(int, const struct iovec *, int)), "readv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&writev),
    ssize_t (*)(int, const struct iovec *, int)), "writev declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dup), int (*)(int)),
    "dup declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&close), int (*)(int)),
    "close declaration");

static int same_bytes(const char *left, const char *right, size_t length)
{
    for (size_t index = 0; index < length; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static void close_if_open(int *descriptor)
{
    if (*descriptor >= 0) {
        (void)close(*descriptor);
        *descriptor = -1;
    }
}

int crabc_x86_64_descriptor_pipeline_probe(void)
{
    static const char expected[] = "left-right";
    char first[4] = { 0, 0, 0, 0 };
    char second[6] = { 0, 0, 0, 0, 0, 0 };
    struct iovec outgoing[2] = {
        { (void *)"left", 4 }, { (void *)"-right", 6 },
    };
    struct iovec incoming[2] = {
        { first, sizeof(first) }, { second, sizeof(second) },
    };
    struct pollfd readiness = { .fd = -1, .events = POLLIN, .revents = 0 };
    int pipe_descriptors[2] = { -1, -1 };
    int duplicate = -1;
    int closed_descriptor = -1;
    int status = 0;

    errno = 71;
    if (pipe2(pipe_descriptors, O_NONBLOCK | O_CLOEXEC) != 0 || errno != 71) {
        status = 1;
        goto finish;
    }
    errno = 72;
    if ((fcntl(pipe_descriptors[0], F_GETFL) & O_NONBLOCK) == 0 ||
        (fcntl(pipe_descriptors[1], F_GETFL) & O_NONBLOCK) == 0 ||
        fcntl(pipe_descriptors[0], F_GETFD) != FD_CLOEXEC ||
        fcntl(pipe_descriptors[1], F_GETFD) != FD_CLOEXEC || errno != 72) {
        status = 2;
        goto finish;
    }
    if (fcntl(pipe_descriptors[0], F_SETFD, 0) != 0 ||
        fcntl(pipe_descriptors[0], F_GETFD) != 0 ||
        fcntl(pipe_descriptors[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(pipe_descriptors[0], F_GETFD) != FD_CLOEXEC) {
        status = 3;
        goto finish;
    }

    readiness.fd = pipe_descriptors[0];
    readiness.revents = (short)0x7fff;
    errno = 73;
    if (poll(&readiness, 1, 0) != 0 || readiness.revents != 0 || errno != 73) {
        status = 4;
        goto finish;
    }
    if (writev(pipe_descriptors[1], outgoing, 2) != (ssize_t)sizeof(expected) - 1) {
        status = 5;
        goto finish;
    }
    readiness.revents = 0;
    if (poll(&readiness, 1, 0) != 1 || (readiness.revents & POLLIN) == 0) {
        status = 6;
        goto finish;
    }

    duplicate = dup(pipe_descriptors[0]);
    if (duplicate < 0 || close(pipe_descriptors[0]) != 0) {
        status = 7;
        goto finish;
    }
    pipe_descriptors[0] = -1;
    if (readv(duplicate, incoming, 2) != (ssize_t)sizeof(expected) - 1 ||
        !same_bytes(first, expected, sizeof(first)) ||
        !same_bytes(second, expected + sizeof(first), sizeof(second))) {
        status = 8;
        goto finish;
    }
    readiness.fd = duplicate;
    readiness.revents = (short)0x7fff;
    if (poll(&readiness, 1, 0) != 0 || readiness.revents != 0) {
        status = 9;
        goto finish;
    }
    if (close(pipe_descriptors[1]) != 0) {
        status = 10;
        goto finish;
    }
    pipe_descriptors[1] = -1;
    readiness.revents = 0;
    if (poll(&readiness, 1, 0) != 1 || (readiness.revents & POLLHUP) == 0) {
        status = 11;
        goto finish;
    }

    errno = 0;
    if (fcntl(-1, F_GETFL) != -1 || errno != EBADF) {
        status = 12;
        goto finish;
    }
    errno = 0;
    if (pipe2(pipe_descriptors, 0x40000000) != -1 || errno != EINVAL) {
        status = 13;
        goto finish;
    }
    closed_descriptor = duplicate;
    if (close(duplicate) != 0) {
        status = 14;
        goto finish;
    }
    duplicate = -1;
    readiness.fd = closed_descriptor;
    readiness.revents = 0;
    if (poll(&readiness, 1, 0) != 1 || readiness.revents != POLLNVAL) {
        status = 15;
        goto finish;
    }

finish:
    close_if_open(&duplicate);
    close_if_open(&pipe_descriptors[0]);
    close_if_open(&pipe_descriptors[1]);
    return status;
}

#ifndef CRABC_DESCRIPTOR_PIPELINE_FREESTANDING
int main(void)
{
    return crabc_x86_64_descriptor_pipeline_probe();
}
#endif
