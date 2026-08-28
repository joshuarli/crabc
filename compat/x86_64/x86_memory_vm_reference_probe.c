/*
 * Pinned-musl/raw Linux/x86-64 legacy VM-policy reference.
 *
 * This fixture establishes only the private native Rust seam for a raw
 * program-break query, process-wide memory-lock policy, and the legacy
 * remap_file_pages rejection exercised below.  It neither selects a C API
 * for crabc nor claims public x86-64 support.
 *
 * The break check is deliberately allocation-free before its final result is
 * reported.  Linux's raw SYS_brk query and same-address replay leave the
 * break unchanged.  Pinned musl 1.2.6 deliberately exposes only sbrk(0) for
 * a query: its brk(void *) wrapper returns ENOMEM for every request, including
 * the current break.  Treating that explicit C-wrapper difference as a raw
 * kernel result would silently change the native kernel_brk contract.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    PAGE_SIZE_REFERENCE = 4096,
    CHILD_LOCK_AVAILABLE = 0,
    CHILD_LOCK_LIMITED = 64,
};

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(size_t) == 8 &&
                   sizeof(void *) == 8,
               "x86 little-endian LP64 scalar widths");
_Static_assert(SYS_brk == 12, "x86 brk syscall number");
_Static_assert(SYS_mlockall == 151, "x86 mlockall syscall number");
_Static_assert(SYS_munlockall == 152, "x86 munlockall syscall number");
_Static_assert(SYS_remap_file_pages == 216,
               "x86 remap_file_pages syscall number");
_Static_assert(MCL_CURRENT == 0x1 && MCL_FUTURE == 0x2 && MCL_ONFAULT == 0x4,
               "x86 closed mlockall flags");

enum vm_arm {
    RAW_SYSCALL_ARM,
    MUSL_WRAPPER_ARM,
};

static int permitted_mlockall_error(int error)
{
    return error == EPERM || error == ENOMEM || error == EAGAIN;
}

/*
 * This runs before any stdio call in its child.  In particular, it never
 * asks the kernel to move the break, and it does not let an allocator obscure
 * whether the raw query and same-address replay were no-ops.
 */
static int check_brk_query_and_replay(void)
{
    void *raw_before;
    void *raw_replayed;
    void *raw_after;
    void *musl_before;
    void *musl_after;

    raw_before = (void *)(uintptr_t)syscall(SYS_brk, 0);
    if (raw_before == NULL || raw_before == (void *)-1)
        return 10;

    /* musl's sbrk(0) is its non-mutating public query and must agree with
       the raw syscall before either path issues its same-address operation. */
    musl_before = sbrk(0);
    if (musl_before == (void *)-1 || musl_before != raw_before)
        return 11;

    raw_replayed = (void *)(uintptr_t)syscall(SYS_brk, raw_before);
    if (raw_replayed != raw_before)
        return 12;

    /* The pinned musl brk wrapper intentionally rejects even this no-op
       replay.  Its failure must leave the raw break unchanged. */
    errno = 0;
    if (brk(raw_before) != -1 || errno != ENOMEM)
        return 13;

    raw_after = (void *)(uintptr_t)syscall(SYS_brk, 0);
    musl_after = sbrk(0);
    if (raw_after != raw_before || musl_after != raw_before)
        return 14;

    return 0;
}

static int call_mlockall(enum vm_arm arm)
{
    if (arm == RAW_SYSCALL_ARM)
        return (int)syscall(SYS_mlockall, MCL_CURRENT);
    return mlockall(MCL_CURRENT);
}

static int call_munlockall(enum vm_arm arm)
{
    if (arm == RAW_SYSCALL_ARM)
        return (int)syscall(SYS_munlockall);
    return munlockall();
}

/*
 * A failed mlockall can have made a partial change before reporting an
 * environment limit.  Always issue munlockall in this child, then require it
 * to succeed, so either branch leaves no process-wide policy behind.
 */
static int check_mlockall_cleanup(enum vm_arm arm)
{
    int mlockall_result;
    int mlockall_error;

    errno = 0;
    mlockall_result = call_mlockall(arm);
    mlockall_error = errno;

    if (call_munlockall(arm) != 0)
        return -1;
    if (mlockall_result == 0)
        return CHILD_LOCK_AVAILABLE;
    if (permitted_mlockall_error(mlockall_error))
        return CHILD_LOCK_LIMITED;
    return -1;
}

static int check_anonymous_remap_rejected(enum vm_arm arm)
{
    void *mapping;
    long remap_result;
    int remap_error;
    int unmap_result;

    mapping = mmap(NULL, PAGE_SIZE_REFERENCE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return -1;

    errno = 0;
    if (arm == RAW_SYSCALL_ARM) {
        remap_result = syscall(SYS_remap_file_pages, mapping,
                               PAGE_SIZE_REFERENCE, 0, 0, 0);
    } else {
        remap_result = remap_file_pages(mapping, PAGE_SIZE_REFERENCE, 0, 0, 0);
    }
    remap_error = errno;
    unmap_result = munmap(mapping, PAGE_SIZE_REFERENCE);

    if (unmap_result != 0)
        return -1;
    return remap_result == -1 && remap_error == EINVAL ? 0 : -1;
}

static int run_vm_arm(enum vm_arm arm)
{
    int lock_state = check_mlockall_cleanup(arm);

    if (lock_state != CHILD_LOCK_AVAILABLE && lock_state != CHILD_LOCK_LIMITED)
        return 20;
    if (check_anonymous_remap_rejected(arm) != 0)
        return 21;
    return lock_state;
}

static int run_in_child(int (*operation)(void))
{
    int status;
    pid_t child = fork();

    if (child < 0)
        return -1;
    if (child == 0)
        _exit(operation());

    while (waitpid(child, &status, 0) == -1) {
        if (errno != EINTR)
            return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_raw_vm_arm(void)
{
    return run_vm_arm(RAW_SYSCALL_ARM);
}

static int run_musl_vm_arm(void)
{
    return run_vm_arm(MUSL_WRAPPER_ARM);
}

static const char *lock_state_name(int state)
{
    return state == CHILD_LOCK_AVAILABLE ? "available" : "limited";
}

int main(void)
{
    int raw_lock_state;
    int musl_lock_state;

    if (run_in_child(check_brk_query_and_replay) != 0)
        return 1;

    raw_lock_state = run_in_child(run_raw_vm_arm);
    musl_lock_state = run_in_child(run_musl_vm_arm);
    if ((raw_lock_state != CHILD_LOCK_AVAILABLE &&
         raw_lock_state != CHILD_LOCK_LIMITED) ||
        (musl_lock_state != CHILD_LOCK_AVAILABLE &&
         musl_lock_state != CHILD_LOCK_LIMITED))
        return 2;

    printf("brk=12 raw=query+same-address-replay musl=sbrk(0)-query+brk=ENOMEM mlockall=151 munlockall=152 raw-mlockall=%s musl-mlockall=%s remap_file_pages=216 anonymous-one-page=EINVAL child-contained\n",
           lock_state_name(raw_lock_state), lock_state_name(musl_lock_state));
    return 0;
}
