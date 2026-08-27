/* Pinned-musl Linux/x86-64 setrlimit/prlimit64 behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(struct rlimit) == 16, "x86 rlimit size");
_Static_assert(_Alignof(struct rlimit) == 8, "x86 rlimit alignment");
_Static_assert(offsetof(struct rlimit, rlim_cur) == 0,
               "x86 rlimit current offset");
_Static_assert(offsetof(struct rlimit, rlim_max) == 8,
               "x86 rlimit maximum offset");
_Static_assert(RLIM_INFINITY == UINT64_MAX, "x86 RLIM_INFINITY");
_Static_assert(RLIMIT_CORE == 4, "x86 RLIMIT_CORE");
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

static int raw_prlimit(
    const struct rlimit *new_limit,
    struct rlimit *old_limit
)
{
    return syscall(SYS_prlimit64, 0, RLIMIT_CORE, new_limit, old_limit) == 0;
}

static struct rlimit reversible_limit(const struct rlimit original)
{
    struct rlimit changed = original;

    if (original.rlim_cur != RLIM_INFINITY &&
        original.rlim_cur < original.rlim_max) {
        ++changed.rlim_cur;
    } else if (original.rlim_cur != RLIM_INFINITY && original.rlim_cur > 0) {
        --changed.rlim_cur;
    } else if (original.rlim_max == RLIM_INFINITY) {
        changed.rlim_cur = 1;
    }
    return changed;
}

static int mutation_case(void)
{
    struct rlimit original;
    struct rlimit changed;
    struct rlimit observed;
    const struct rlimit inverted = { .rlim_cur = 1, .rlim_max = 0 };

    if (getrlimit(RLIMIT_CORE, &original) != 0 || !valid_limit(&original))
        return 10;
    changed = reversible_limit(original);
    if (!valid_limit(&changed))
        return 11;

    /* The raw PID-zero write is the x86 facade's direct kernel boundary. */
    if (!raw_prlimit(&changed, NULL))
        return 12;
    if (getrlimit(RLIMIT_CORE, &observed) != 0 ||
        !same_limit(&observed, &changed))
        return 13;

    /* The pinned-musl wrapper restores before the short-lived child exits. */
    if (setrlimit(RLIMIT_CORE, &original) != 0)
        return 14;
    if (!raw_prlimit(NULL, &observed) || !same_limit(&observed, &original))
        return 15;

    errno = 0;
    if (raw_prlimit(&inverted, NULL) || errno != EINVAL)
        return 16;
    errno = 0;
    if (setrlimit(RLIMIT_CORE, &inverted) != -1 || errno != EINVAL)
        return 17;
    return 0;
}

static int run_in_child(void)
{
    const pid_t child = fork();
    int status;

    if (child < 0)
        return 20;
    if (child == 0)
        _exit(mutation_case());
    if (waitpid(child, &status, 0) != child)
        return 21;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 22;
    return 0;
}

int main(void)
{
    if (run_in_child() != 0)
        return 1;

    puts("layout=size16 align8 offsets=0,8 infinity=UINT64_MAX syscall=302 lifecycle=raw-set:musl-read:musl-restore:raw-read invalid=EINVAL child-contained");
    return 0;
}
