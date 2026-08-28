/* Pinned-musl/raw Linux/x86-64 flock(2) ABI and advisory-lock reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
    TOKEN_TIMEOUT_MS = 5000,
    CHILD_EXIT_WAIT_STEPS = 50,
    CHILD_EXIT_WAIT_NS = 100000000,
    UNKNOWN_LOCK_BIT = 0x10,
};

_Static_assert(SYS_flock == 73, "x86 flock syscall number");
_Static_assert(LOCK_SH == 1 && LOCK_EX == 2 && LOCK_NB == 4 && LOCK_UN == 8,
               "x86 flock operation bits");
_Static_assert((LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN) == 15,
               "x86 flock operation-bit closure");

static long raw_flock(int fd, int operation)
{
    return syscall(SYS_flock, (long)fd, (long)operation);
}

static int expect_error(long result, int error)
{
    return result == -1 && errno == error;
}

static int is_lock_conflict(int error)
{
    return error == EWOULDBLOCK || error == EAGAIN;
}

static int write_token(int fd, char token)
{
    ssize_t written;

    do {
        written = write(fd, &token, 1);
    } while (written < 0 && errno == EINTR);
    return written == 1;
}

static int wait_for_token(int fd, char expected)
{
    struct pollfd poll_fd = {
        .fd = fd,
        .events = POLLIN,
    };
    char token;
    int ready;
    ssize_t read_count;

    do {
        ready = poll(&poll_fd, 1, TOKEN_TIMEOUT_MS);
    } while (ready < 0 && errno == EINTR);
    if (ready != 1 || (poll_fd.revents & POLLIN) == 0)
        return 0;

    do {
        read_count = read(fd, &token, 1);
    } while (read_count < 0 && errno == EINTR);
    return read_count == 1 && token == expected;
}

static int wait_for_child_success(pid_t child, int *reaped)
{
    struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = CHILD_EXIT_WAIT_NS,
    };
    int status;

    for (int attempt = 0; attempt < CHILD_EXIT_WAIT_STEPS; ++attempt) {
        pid_t observed = waitpid(child, &status, WNOHANG);

        if (observed == child) {
            *reaped = 1;
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if (observed < 0)
            return 0;
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        }
        delay.tv_sec = 0;
        delay.tv_nsec = CHILD_EXIT_WAIT_NS;
    }
    return 0;
}

static void stop_child(pid_t child, int *reaped)
{
    int status;
    pid_t observed;

    if (child <= 0 || *reaped)
        return;

    do {
        observed = waitpid(child, &status, WNOHANG);
    } while (observed < 0 && errno == EINTR);
    if (observed == child || (observed < 0 && errno == ECHILD)) {
        *reaped = 1;
        return;
    }
    if (observed == 0) {
        (void)kill(child, SIGKILL);
        do {
            observed = waitpid(child, &status, 0);
        } while (observed < 0 && errno == EINTR);
    }
    if (observed == child || (observed < 0 && errno == ECHILD))
        *reaped = 1;
}

static int child_lifecycle(int inherited_fixture_fd, const char *path,
                           int to_parent, int from_parent)
{
    int fd = -1;
    int result = 0;

    /* The child must not retain the parent's open file description. */
    if (close(inherited_fixture_fd) != 0)
        return 20;
    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return 21;

    /* This separate open creates the distinct description under test. */
    if (!write_token(to_parent, 'O')) {
        result = 22;
        goto cleanup;
    }
    if (!wait_for_token(from_parent, 'L')) {
        result = 23;
        goto cleanup;
    }

    /* A raw nonblocking exclusive request conflicts with musl's shared one. */
    errno = 0;
    if (raw_flock(fd, LOCK_EX | LOCK_NB) != -1 || !is_lock_conflict(errno)) {
        result = 24;
        goto cleanup;
    }
    if (!write_token(to_parent, 'C')) {
        result = 25;
        goto cleanup;
    }
    if (!wait_for_token(from_parent, 'R')) {
        result = 26;
        goto cleanup;
    }

    /* After raw release, the musl nonblocking exclusive request must work. */
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        result = 27;
        goto cleanup;
    }
    if (raw_flock(fd, LOCK_UN | LOCK_NB) != 0) {
        result = 28;
        goto cleanup;
    }
    if (!write_token(to_parent, 'S'))
        result = 29;

cleanup:
    if (fd >= 0 && close(fd) != 0 && result == 0)
        result = 30;
    return result;
}

int main(void)
{
    char template[] = "/tmp/crabc-x86-flock-XXXXXX";
    int fixture_fd = -1;
    int closed_fd = -1;
    int child_to_parent[2] = {-1, -1};
    int parent_to_child[2] = {-1, -1};
    pid_t child = -1;
    int child_reaped = 0;
    int result = 0;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        return 10;
    fixture_fd = mkstemp(template);
    if (fixture_fd < 0)
        return 11;
    if (pipe(child_to_parent) != 0 || pipe(parent_to_child) != 0) {
        result = 12;
        goto cleanup;
    }

    child = fork();
    if (child < 0) {
        result = 13;
        goto cleanup;
    }
    if (child == 0) {
        if (close(child_to_parent[0]) != 0 || close(parent_to_child[1]) != 0)
            _exit(14);
        _exit(child_lifecycle(fixture_fd, template, child_to_parent[1],
                              parent_to_child[0]));
    }

    if (close(child_to_parent[1]) != 0) {
        result = 15;
        goto cleanup;
    }
    child_to_parent[1] = -1;
    if (close(parent_to_child[0]) != 0) {
        result = 16;
        goto cleanup;
    }
    parent_to_child[0] = -1;

    if (!wait_for_token(child_to_parent[0], 'O')) {
        result = 17;
        goto cleanup;
    }

    /* This musl request cannot wait: the unique fixture has no other lock. */
    if (flock(fixture_fd, LOCK_SH | LOCK_NB) != 0) {
        result = 18;
        goto cleanup;
    }
    if (!write_token(parent_to_child[1], 'L')) {
        result = 19;
        goto cleanup;
    }
    if (!wait_for_token(child_to_parent[0], 'C')) {
        result = 31;
        goto cleanup;
    }

    /* The raw release makes the separate child description eligible to lock. */
    if (raw_flock(fixture_fd, LOCK_UN | LOCK_NB) != 0) {
        result = 32;
        goto cleanup;
    }
    if (!write_token(parent_to_child[1], 'R')) {
        result = 33;
        goto cleanup;
    }
    if (!wait_for_token(child_to_parent[0], 'S')) {
        result = 34;
        goto cleanup;
    }
    if (!wait_for_child_success(child, &child_reaped)) {
        result = 35;
        goto cleanup;
    }

    /* Raw acquisition and musl release agree after the child's raw release. */
    if (raw_flock(fixture_fd, LOCK_SH | LOCK_NB) != 0) {
        result = 36;
        goto cleanup;
    }
    if (flock(fixture_fd, LOCK_UN) != 0) {
        result = 37;
        goto cleanup;
    }

    errno = 0;
    if (!expect_error(flock(fixture_fd, UNKNOWN_LOCK_BIT), EINVAL)) {
        result = 38;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(raw_flock(fixture_fd, UNKNOWN_LOCK_BIT), EINVAL)) {
        result = 39;
        goto cleanup;
    }

    closed_fd = dup(fixture_fd);
    if (closed_fd < 0) {
        result = 40;
        goto cleanup;
    }
    if (close(closed_fd) != 0) {
        result = 41;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(flock(closed_fd, LOCK_EX | LOCK_NB), EBADF)) {
        result = 42;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(raw_flock(closed_fd, LOCK_EX | LOCK_NB), EBADF)) {
        result = 43;
        goto cleanup;
    }

cleanup:
    stop_child(child, &child_reaped);
    (void)unlink(template);
    if (child_to_parent[0] >= 0 && close(child_to_parent[0]) != 0 && result == 0)
        result = 50;
    if (child_to_parent[1] >= 0 && close(child_to_parent[1]) != 0 && result == 0)
        result = 51;
    if (parent_to_child[0] >= 0 && close(parent_to_child[0]) != 0 && result == 0)
        result = 52;
    if (parent_to_child[1] >= 0 && close(parent_to_child[1]) != 0 && result == 0)
        result = 53;
    if (fixture_fd >= 0 && close(fixture_fd) != 0 && result == 0)
        result = 54;
    if (result != 0)
        return result;

    puts("syscall=73 bits=SH1,EX2,NB4,UN8 "
         "lifecycle=distinct-open-description:shared-conflict:release:exclusive "
         "raw=matches-musl errors=EINVAL,EBADF fcntl-record-locks=excluded "
         "c-api-selection=excluded path-surface=excluded durability=unproved");
    return 0;
}
