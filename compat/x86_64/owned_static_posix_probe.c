/* Owned static Linux/x86-64 POSIX composition probe.
 *
 * This one ordinary C program is intentionally not a collection of leaf
 * fixtures.  It first mutates and queries the selected process environment,
 * forks and execs itself with that live environment, reaps the replacement
 * image, then drives a pipe through writev/readv, poll readiness, dup, and
 * close/HUP/invalid-descriptor lifecycle transitions.  The same source is
 * suitable for a pinned-musl reference and an owned static ET_EXEC or static
 * PIE link: it uses no fixture-local raw syscall, startup, allocator, or
 * descriptor substitute.
 *
 * It establishes this narrow usable composition only.  It does not select
 * PATH search, spawn/vfork, cancellation points, concurrent environment or
 * descriptor policy, a process supervisor, dynamic linking, or broader POSIX
 * family completion.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "owned static POSIX composition requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct pollfd) == 8 && _Alignof(struct pollfd) == 4,
    "x86 pollfd layout");
_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8,
    "x86 iovec layout");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getenv),
    char *(*)(const char *)), "getenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setenv),
    int (*)(const char *, const char *, int)), "setenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&putenv),
    int (*)(char *)), "putenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&unsetenv),
    int (*)(const char *)), "unsetenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clearenv),
    int (*)(void)), "clearenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fork), pid_t (*)(void)),
    "fork declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execve),
    int (*)(const char *, char *const[], char *const[])), "execve declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&waitpid),
    pid_t (*)(pid_t, int *, int)), "waitpid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pipe), int (*)(int[2])),
    "pipe declaration");
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
_Static_assert(__builtin_types_compatible_p(__typeof__(&write),
    ssize_t (*)(int, const void *, size_t)), "write declaration");

static const char environment_name[] = "CRABC_OWNED_STATIC_POSIX";
static const char environment_value[] = "roundtrip";
static const char borrowed_name[] = "CRABC_OWNED_STATIC_BORROWED";
static char borrowed_entry[] = "CRABC_OWNED_STATIC_BORROWED=one";
static const char child_flag[] = "--owned-static-posix-child";
static const char success_message[] = "owned-static-posix: PASS\n";

static int strings_equal(const char *left, const char *right)
{
    for (;;) {
        if (*left != *right)
            return 0;
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
}

static int bytes_equal(const char *left, const char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static void close_if_open(int *descriptor)
{
    if (*descriptor >= 0) {
        (void)close(*descriptor);
        *descriptor = -1;
    }
}

static int child_environment_check(void)
{
    const char *primary = getenv(environment_name);
    const char *borrowed = getenv(borrowed_name);

    if (primary == NULL || !strings_equal(primary, environment_value))
        return 1;
    if (borrowed == NULL || !strings_equal(borrowed, "on2"))
        return 2;
    return 0;
}

static void *worker_signal_mask(void *unused)
{
    (void)unused;
    sigset_t mask, current;
    if (sigemptyset(&mask) || sigaddset(&mask, SIGUSR1)) return (void *)1;
    errno = ERANGE;
    if (pthread_sigmask(SIG_UNBLOCK, &mask, &current) || errno != ERANGE
        || !sigismember(&current, SIGUSR1)) return (void *)2;
    if (pthread_sigmask(SIG_SETMASK, NULL, &current)
        || sigismember(&current, SIGUSR1)) return (void *)3;
    return NULL;
}

static int thread_signal_masks(void)
{
    sigset_t saved, mask, current;
    if (sigemptyset(&mask) || sigaddset(&mask, SIGUSR1)) return 1;
    memset(&saved, 0xa5, sizeof saved);
    errno = ERANGE;
    if (pthread_sigmask(SIG_BLOCK, &mask, &saved) || errno != ERANGE) return 2;
    /* Musl changes only the first kernel-visible word of the public record. */
    for (size_t index = sizeof(unsigned long); index < sizeof saved; ++index)
        if (((unsigned char *)&saved)[index] != 0xa5) return 3;
    if (pthread_sigmask(99, &mask, NULL) != EINVAL || errno != ERANGE) return 4;
    if (pthread_sigmask(99, (const sigset_t *)1, NULL) != EINVAL
        || errno != ERANGE) return 4;
    if (sigprocmask(99, (const sigset_t *)1, NULL) != -1 || errno != EINVAL)
        return 4;
    errno = ERANGE;
    if (pthread_sigmask(99, NULL, &current) || errno != ERANGE) return 5;
    if (pthread_sigmask(SIG_SETMASK, NULL, (sigset_t *)1) != EFAULT
        || errno != ERANGE) return 6;
    pthread_t thread;
    void *result;
    if (pthread_create(&thread, NULL, worker_signal_mask, NULL)
        || pthread_join(thread, &result) || result) return 7;
    if (pthread_sigmask(SIG_SETMASK, NULL, &current)
        || !sigismember(&current, SIGUSR1)) return 8;
    if (pthread_sigmask(SIG_SETMASK, &saved, NULL)) return 9;
    return 0;
}

/* Change only a disposable child's root to the existing consumer directory.
   The caller's CWD and open directory descriptors retain their Linux meaning. */
static int child_root_change(const char *self)
{
    char directory[4096];
    const char *name = strrchr(self, '/');
    if (self[0] != '/' || !name || (size_t)(name - self) >= sizeof directory)
        return 1;
    memcpy(directory, self, (size_t)(name - self));
    directory[name - self] = 0;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        struct stat before, after;
        errno = 0;
        if (chroot("") != -1 || errno != ENOENT) _exit(1);
        if (chdir("/") || stat(".", &before)) _exit(2);
        errno = ERANGE;
        if (chroot(directory) || errno != ERANGE) _exit(3);
        if (stat(".", &after) || before.st_dev != after.st_dev
            || before.st_ino != after.st_ino) _exit(4);
        int descriptor = open(name, O_RDONLY | O_CLOEXEC);
        if (descriptor < 0 || close(descriptor)) _exit(5);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
        || WEXITSTATUS(status)) return 3;
    int descriptor = open(self, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0 || close(descriptor)) return 4;
    return 0;
}

static int environment_exec_roundtrip(const char *self)
{
    char *child_argv[] = { (char *)self, (char *)child_flag, NULL };
    pid_t child;
    int status;

    if (self == NULL || self[0] == '\0')
        return 1;
    if (setenv(environment_name, environment_value, 1) != 0 ||
        getenv(environment_name) == NULL ||
        !strings_equal(getenv(environment_name), environment_value))
        return 2;
    if (putenv(borrowed_entry) != 0 ||
        getenv(borrowed_name) == NULL ||
        !strings_equal(getenv(borrowed_name), "one"))
        return 3;
    borrowed_entry[sizeof(borrowed_entry) - 2] = '2';
    if (getenv(borrowed_name) == NULL ||
        !strings_equal(getenv(borrowed_name), "on2"))
        return 4;

    child = fork();
    if (child < 0)
        return 5;
    if (child == 0) {
        (void)execve(self, child_argv, environ);
        _exit(101);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 6;

    if (unsetenv(environment_name) != 0 || getenv(environment_name) != NULL)
        return 7;
    if (unsetenv(borrowed_name) != 0 || getenv(borrowed_name) != NULL)
        return 8;
    if (clearenv() != 0 || environ != NULL || getenv(environment_name) != NULL)
        return 9;
    return 0;
}

static int descriptor_pipeline(void)
{
    static const char first[] = "vector";
    static const char second[] = "-io";
    static const char expected[] = "vector-io";
    struct iovec outgoing[2] = {
        { (void *)first, sizeof(first) - 1 },
        { (void *)second, sizeof(second) - 1 },
    };
    char incoming_first[6] = { 0 };
    char incoming_second[3] = { 0 };
    struct iovec incoming[2] = {
        { incoming_first, sizeof(incoming_first) },
        { incoming_second, sizeof(incoming_second) },
    };
    struct pollfd readiness;
    int descriptors[2] = { -1, -1 };
    int duplicate = -1;
    int result = 0;

    if (pipe(descriptors) != 0)
        return 1;
    readiness.fd = descriptors[0];
    readiness.events = POLLIN;
    readiness.revents = 0;
    errno = 0;
    if (poll(&readiness, 1, 0) != 0 || readiness.revents != 0) {
        result = 2;
        goto cleanup;
    }
    if (writev(descriptors[1], outgoing, 2) !=
        (ssize_t)(sizeof(expected) - 1)) {
        result = 3;
        goto cleanup;
    }
    readiness.revents = 0;
    if (poll(&readiness, 1, 0) != 1 || (readiness.revents & POLLIN) == 0) {
        result = 4;
        goto cleanup;
    }
    duplicate = dup(descriptors[0]);
    if (duplicate < 0 || close(descriptors[0]) != 0) {
        result = 5;
        goto cleanup;
    }
    descriptors[0] = -1;
    if (readv(duplicate, incoming, 2) != (ssize_t)(sizeof(expected) - 1) ||
        !bytes_equal(incoming_first, expected, sizeof(incoming_first)) ||
        !bytes_equal(incoming_second, expected + sizeof(incoming_first),
            sizeof(incoming_second))) {
        result = 6;
        goto cleanup;
    }
    readiness.fd = duplicate;
    readiness.revents = 0;
    if (poll(&readiness, 1, 0) != 0 || readiness.revents != 0) {
        result = 7;
        goto cleanup;
    }
    if (close(descriptors[1]) != 0) {
        result = 8;
        goto cleanup;
    }
    descriptors[1] = -1;
    readiness.revents = 0;
    if (poll(&readiness, 1, 0) != 1 || (readiness.revents & POLLHUP) == 0) {
        result = 9;
        goto cleanup;
    }
    if (close(duplicate) != 0) {
        result = 10;
        goto cleanup;
    }
    readiness.revents = 0;
    if (poll(&readiness, 1, 0) != 1 || readiness.revents != POLLNVAL)
        result = 11;
    duplicate = -1;

cleanup:
    close_if_open(&duplicate);
    close_if_open(&descriptors[0]);
    close_if_open(&descriptors[1]);
    return result;
}

int main(int argc, char **argv)
{
    int result;

    if (argc == 2 && strings_equal(argv[1], child_flag))
        return child_environment_check();
    if (argc != 1)
        return 90;
    result = thread_signal_masks();
    if (result != 0) return 80 + result;
    result = child_root_change(argv[0]);
    if (result != 0) return 90 + result;
    result = environment_exec_roundtrip(argv[0]);
    if (result != 0)
        return 10 + result;
    result = descriptor_pipeline();
    if (result != 0)
        return 30 + result;
    if (write(STDOUT_FILENO, success_message, sizeof(success_message) - 1) !=
        (ssize_t)(sizeof(success_message) - 1))
        return 70;
    return 0;
}
