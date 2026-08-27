/* Pinned-musl Linux/x86-64 targeted getrlimit/prlimit64 behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(unsigned long) == 8, "x86 unsigned long width");
_Static_assert(sizeof(struct rlimit) == 16, "x86 rlimit size");
_Static_assert(_Alignof(struct rlimit) == 8, "x86 rlimit alignment");
_Static_assert(offsetof(struct rlimit, rlim_cur) == 0,
               "x86 rlimit current offset");
_Static_assert(offsetof(struct rlimit, rlim_max) == 8,
               "x86 rlimit maximum offset");
_Static_assert(RLIM_INFINITY == UINT64_MAX, "x86 RLIM_INFINITY");
_Static_assert(RLIMIT_NOFILE == 7, "x86 RLIMIT_NOFILE");
_Static_assert(SYS_prlimit64 == 302, "x86 prlimit64 syscall number");

static int same_limit(const struct rlimit *left, const struct rlimit *right)
{
    return left->rlim_cur == right->rlim_cur &&
           left->rlim_max == right->rlim_max;
}

static int valid_limit(const struct rlimit *limit)
{
    return limit->rlim_cur <= limit->rlim_max &&
           (limit->rlim_cur != RLIM_INFINITY ||
            limit->rlim_max == RLIM_INFINITY);
}

static int write_full(int fd, const void *buffer, size_t length)
{
    const unsigned char *bytes = buffer;

    while (length != 0) {
        ssize_t written = write(fd, bytes, length);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        if (written == 0)
            return 0;
        bytes += (size_t)written;
        length -= (size_t)written;
    }
    return 1;
}

static int read_full(int fd, void *buffer, size_t length)
{
    unsigned char *bytes = buffer;

    while (length != 0) {
        ssize_t read_count = read(fd, bytes, length);
        if (read_count < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        if (read_count == 0)
            return 0;
        bytes += (size_t)read_count;
        length -= (size_t)read_count;
    }
    return 1;
}

static int raw_prlimit(pid_t pid, int resource, struct rlimit *result)
{
    /* A null new-limit argument makes this direct query read-only. */
    return syscall(SYS_prlimit64, pid, resource, NULL, result) == 0;
}

static int choose_child_limit(const struct rlimit *original,
                              struct rlimit *changed)
{
    *changed = *original;
    if (original->rlim_max == 0)
        return 0;

    /* Lowering is unprivileged; choose a value guaranteed to differ when the
     * host's usable RLIMIT_NOFILE range has at least two values. */
    if (original->rlim_cur != 1) {
        changed->rlim_cur = 1;
    } else if (original->rlim_max >= 2) {
        changed->rlim_cur = 2;
    } else {
        return 0;
    }
    return valid_limit(changed) && !same_limit(original, changed);
}

static int child_target_case(int ready_write, int release_read)
{
    struct rlimit original;
    struct rlimit changed;
    struct rlimit observed;
    unsigned char release;

    if (getrlimit(RLIMIT_NOFILE, &original) != 0 ||
        !choose_child_limit(&original, &changed))
        return 10;
    if (setrlimit(RLIMIT_NOFILE, &changed) != 0)
        return 11;
    if (getrlimit(RLIMIT_NOFILE, &observed) != 0 ||
        !same_limit(&observed, &changed))
        return 12;
    if (!write_full(ready_write, &observed, sizeof(observed)))
        return 13;
    close(ready_write);

    /* Keep this distinct target alive while the parent performs both queries. */
    if (!read_full(release_read, &release, sizeof(release)))
        return 14;
    return release == 0xa5 ? 0 : 15;
}

static int targeted_case(void)
{
    struct rlimit parent_limit;
    struct rlimit child_limit;
    struct rlimit libc_target;
    struct rlimit raw_target;
    struct rlimit invalid;
    int ready[2] = {-1, -1};
    int release[2] = {-1, -1};
    pid_t child = -1;
    int status = 0;
    unsigned char release_byte = 0xa5;
    int result = 0;

    if (getrlimit(RLIMIT_NOFILE, &parent_limit) != 0 ||
        !valid_limit(&parent_limit))
        return 20;
    if (pipe(ready) != 0 || pipe(release) != 0) {
        if (ready[0] >= 0)
            close(ready[0]);
        if (ready[1] >= 0)
            close(ready[1]);
        return 21;
    }

    child = fork();
    if (child < 0) {
        result = 22;
        goto cleanup;
    }
    if (child == 0) {
        close(ready[0]);
        close(release[1]);
        _exit(child_target_case(ready[1], release[0]));
    }

    close(ready[1]);
    ready[1] = -1;
    close(release[0]);
    release[0] = -1;

    if (!read_full(ready[0], &child_limit, sizeof(child_limit)) ||
        !valid_limit(&child_limit) || same_limit(&parent_limit, &child_limit)) {
        result = 23;
        goto cleanup;
    }
    close(ready[0]);
    ready[0] = -1;

    if (prlimit(child, RLIMIT_NOFILE, NULL, &libc_target) != 0 ||
        !valid_limit(&libc_target) || !same_limit(&libc_target, &child_limit)) {
        result = 24;
        goto cleanup;
    }
    if (!raw_prlimit(child, RLIMIT_NOFILE, &raw_target) ||
        !valid_limit(&raw_target) || !same_limit(&raw_target, &child_limit)) {
        result = 25;
        goto cleanup;
    }

    if (!write_full(release[1], &release_byte, sizeof(release_byte))) {
        result = 26;
        goto cleanup;
    }
    close(release[1]);
    release[1] = -1;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        result = 27;
        goto cleanup;
    }
    child = -1;

    errno = 0;
    if (prlimit((pid_t)INT_MAX, RLIMIT_NOFILE, NULL, &invalid) != -1 ||
        errno != ESRCH)
        result = 28;

cleanup:
    if (ready[0] >= 0)
        close(ready[0]);
    if (ready[1] >= 0)
        close(ready[1]);
    if (release[0] >= 0)
        close(release[0]);
    if (release[1] >= 0)
        close(release[1]);
    if (child > 0) {
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
    }
    return result;
}

int main(void)
{
    if (targeted_case() != 0)
        return 1;

    puts("layout=size16 align8 offsets=0,8 infinity=UINT64_MAX syscall=302 target=live-child-nofile musl=raw=child distinct=1 missing=ESRCH");
    return 0;
}
