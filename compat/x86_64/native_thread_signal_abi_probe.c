/* Installed-header C workload for the native x86 tgkill extension.
 *
 * This object is compiled exactly once through the selected dynamic product's
 * signal.h, then linked unchanged with either the separate pinned-musl
 * syscall adapter or the selected crabc static/dynamic products. It never
 * calls SYS_tgkill directly: the test selects the public C entry.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this workload requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(int) == 4, "x86 C int width");
_Static_assert(sizeof(pid_t) == 4, "x86 pid_t width");
_Static_assert(SIGUSR1 == 10, "x86 SIGUSR1 number");

static volatile sig_atomic_t child_received;

static void child_handler(int signal)
{
    child_received = signal;
}

static int write_one(int fd, const void *data, size_t size)
{
    const unsigned char *cursor = data;

    while (size != 0) {
        ssize_t result = write(fd, cursor, size);
        if (result > 0) {
            cursor += (size_t)result;
            size -= (size_t)result;
            continue;
        }
        if (result == -1 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int read_one(int fd, void *data, size_t size)
{
    unsigned char *cursor = data;

    while (size != 0) {
        ssize_t result = read(fd, cursor, size);
        if (result > 0) {
            cursor += (size_t)result;
            size -= (size_t)result;
            continue;
        }
        if (result == -1 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int release_and_reap(pid_t child, int release_fd)
{
    char release = 'R';
    int status;
    pid_t waited;

    (void)write_one(release_fd, &release, sizeof(release));
    (void)close(release_fd);
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int child_main(int ready_fd, int release_fd)
{
    struct sigaction action = { 0 };
    sigset_t blocked;
    sigset_t old_mask;
    sigset_t pending;
    char ready = 'R';
    char release;

    action.sa_handler = child_handler;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigemptyset(&blocked) != 0 ||
        sigaddset(&blocked, SIGUSR1) != 0 ||
        sigaction(SIGUSR1, &action, 0) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &old_mask) != 0 ||
        write_one(ready_fd, &ready, sizeof(ready)) != 0 ||
        read_one(release_fd, &release, sizeof(release)) != 0 || release != 'R')
        return 1;

    /* The parent sends SIGUSR1 only after this process published readiness;
     * it therefore remains pending until the release pipe makes that order
     * observable. Unblocking delivers it before this syscall returns to the
     * child, then the inherited mask is restored. No scheduling spin is part
     * of the C ABI observation. */
    if (sigpending(&pending) != 0 || sigismember(&pending, SIGUSR1) != 1)
        return 2;
    if (sigprocmask(SIG_UNBLOCK, &blocked, 0) != 0)
        return 3;
    if (child_received != SIGUSR1)
        return 4;
    if (sigprocmask(SIG_SETMASK, &old_mask, 0) != 0)
        return 5;
    return 0;
}

static int exercise_tgkill(void)
{
    int ready_pipe[2];
    int release_pipe[2];
    char ready;
    pid_t child;
    int passed = 1;

    if (pipe(ready_pipe) != 0 || pipe(release_pipe) != 0) return 10;
    child = fork();
    if (child == -1) return 11;
    if (child == 0) {
        (void)close(ready_pipe[0]);
        (void)close(release_pipe[1]);
        _exit(child_main(ready_pipe[1], release_pipe[0]));
    }

    (void)close(ready_pipe[1]);
    (void)close(release_pipe[0]);
    if (read_one(ready_pipe[0], &ready, sizeof(ready)) != 0 || ready != 'R')
        passed = 0;
    (void)close(ready_pipe[0]);

    /* This proves `tgid` is caller-selected: `child` is a different process
     * from this caller, and its first task has tid == tgid. Signal zero tests
     * reachability without delivering a signal. */
    errno = ERANGE;
    if (tgkill(child, child, 0) != 0 || errno != ERANGE) passed = 0;
    errno = ERANGE;
    if (tgkill(getpid(), getpid(), 0) != 0 || errno != ERANGE) passed = 0;
    errno = 0;
    if (tgkill(child, INT_MAX, 0) != -1 || errno != ESRCH) passed = 0;
    errno = 0;
    if (tgkill(child, child, 65) != -1 || errno != EINVAL) passed = 0;
    /* Linux's tgkill syscall rejects each nonpositive identifier before task
     * lookup. These EINVAL observations come from the pinned musl syscall
     * adapter as well as the candidate provider. */
    errno = 0;
    if (tgkill(-1, child, 0) != -1 || errno != EINVAL) passed = 0;
    errno = 0;
    if (tgkill(0, child, 0) != -1 || errno != EINVAL) passed = 0;
    errno = 0;
    if (tgkill(child, -1, 0) != -1 || errno != EINVAL) passed = 0;
    errno = 0;
    if (tgkill(child, 0, 0) != -1 || errno != EINVAL) passed = 0;
    errno = ERANGE;
    if (tgkill(child, child, SIGUSR1) != 0 || errno != ERANGE) passed = 0;

    if (release_and_reap(child, release_pipe[1]) != 0) passed = 0;
    return passed ? 0 : 12;
}

int main(void)
{
    static const char success[] =
        "tgkill-c-abi=caller-selected-child:signal0:delivery:ESRCH:EINVAL\n";

    if (exercise_tgkill() != 0 ||
        write_one(STDOUT_FILENO, success, sizeof(success) - 1) != 0)
        return 1;
    return 0;
}
