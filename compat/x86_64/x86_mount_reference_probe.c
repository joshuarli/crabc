/*
 * Pinned-musl/raw Linux/x86-64 classic mount failure reference.
 *
 * This oracle deliberately proves only the bounded, non-mutating error path
 * selected by the private Rust facade.  Its target names a checked-absent
 * directory below /tmp, so neither arm can establish a mount even when the
 * runner happens to hold CAP_SYS_ADMIN.  The calls run only in a disposable
 * child; this is not a namespace-management, mount-success, or C-ABI test.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(size_t) == 8 &&
                   sizeof(void *) == 8,
               "x86 little-endian LP64 scalar widths");
_Static_assert(SYS_mount == 165, "x86 mount syscall number");
_Static_assert(SYS_umount2 == 166, "x86 umount2 syscall number");

enum invocation {
    INVOCATION_RAW,
    INVOCATION_MUSL,
};

struct invocation_result {
    int result;
    int error;
};

static const char mount_source[] = "none";
static const char mount_type[] = "tmpfs";

/*
 * Pick an absent target without creating one.  The private parent component
 * is checked absent immediately before the raw and musl calls; the PID makes
 * each child invocation distinct.  Both calls use this same absolute target.
 */
static int unique_missing_target(char *target, size_t capacity)
{
    unsigned long attempt;

    for (attempt = 0; attempt != 32; attempt++) {
        char parent[192];
        int parent_length;
        int target_length;
        struct stat status;

        parent_length = snprintf(parent, sizeof(parent),
                                 "/tmp/crabc-x86-mount-reference-%ld-%lu",
                                 (long)getpid(), attempt);
        if (parent_length < 0 || (size_t)parent_length >= sizeof(parent))
            return 0;

        errno = 0;
        if (lstat(parent, &status) == 0 || errno != ENOENT)
            continue;

        target_length = snprintf(target, capacity, "%s/missing-target", parent);
        if (target_length < 0 || (size_t)target_length >= capacity)
            return 0;
        return 1;
    }
    return 0;
}

static struct invocation_result invoke_mount(enum invocation invocation,
                                             const char *target)
{
    struct invocation_result outcome;

    errno = 0;
    if (invocation == INVOCATION_RAW) {
        outcome.result = (int)syscall(SYS_mount, mount_source, target,
                                      mount_type, 0UL, NULL);
    } else {
        outcome.result = mount(mount_source, target, mount_type, 0UL, NULL);
    }
    outcome.error = errno;
    return outcome;
}

static struct invocation_result invoke_umount2(enum invocation invocation,
                                               const char *target)
{
    struct invocation_result outcome;

    errno = 0;
    if (invocation == INVOCATION_RAW)
        outcome.result = (int)syscall(SYS_umount2, target, 0);
    else
        outcome.result = umount2(target, 0);
    outcome.error = errno;
    return outcome;
}

/*
 * Linux permission checking can precede target resolution.  Therefore an
 * unprivileged child observes EPERM while a CAP_SYS_ADMIN child reaches the
 * checked-absent target and observes ENOENT.  The contract is that raw and
 * pinned-musl agree on the direct failure, not that either environment wins
 * that ordering.
 */
static int matching_missing_target_failure(struct invocation_result raw,
                                           struct invocation_result musl)
{
    return raw.result == -1 && musl.result == -1 && raw.error == musl.error &&
           (raw.error == EPERM || raw.error == ENOENT);
}

static int run_failure_reference(void)
{
    char target[256];
    struct invocation_result raw_mount;
    struct invocation_result musl_mount;
    struct invocation_result raw_umount;
    struct invocation_result musl_umount;

    if (!unique_missing_target(target, sizeof(target)))
        return 10;

    raw_mount = invoke_mount(INVOCATION_RAW, target);
    musl_mount = invoke_mount(INVOCATION_MUSL, target);
    if (!matching_missing_target_failure(raw_mount, musl_mount))
        return 11;

    raw_umount = invoke_umount2(INVOCATION_RAW, target);
    musl_umount = invoke_umount2(INVOCATION_MUSL, target);
    if (!matching_missing_target_failure(raw_umount, musl_umount))
        return 12;

    return 0;
}

static int run_in_child(void)
{
    int status;
    pid_t child = fork();

    if (child < 0)
        return -1;
    if (child == 0)
        _exit(run_failure_reference());

    while (waitpid(child, &status, 0) == -1) {
        if (errno != EINTR)
            return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(void)
{
    if (run_in_child() != 0)
        return 1;

    puts("mount=165 umount2=166 raw+musl=unique-nonexistent-target errors=matched-EPERM-or-ENOENT inputs=source-type-nonnull,data-null child-contained");
    return 0;
}
