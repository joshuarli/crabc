/*
 * Public-override regression for musl 1.2.6 syscall-facing weak aliases.
 *
 * A valid application may provide strong definitions for these public names.
 * Before the alias correction, the native static archive defines all fourteen
 * names strongly and rejects this one-object program with duplicate symbols.
 * After the weak-alias correction this same object also proves that ordinary
 * public calls resolve to the application while selected libc implementation
 * paths retain their musl-shaped internal bodies. Each override remains a
 * viable Linux implementation where startup or the selected C allocator may
 * use the ordinary spelling before main; counters, rather than artificial
 * error returns, identify application interposition. The runner supplies one
 * regular pathname so static and chrooted shared executions see identical
 * filesystem inputs.
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <search.h>
#include <semaphore.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/timeb.h>
#include <time.h>
#include <unistd.h>

extern int __fxstat(int, int, struct stat *);
extern int __fxstatat(int, int, const char *, struct stat *, int);

#define PAGE_BYTES 4096U

/* Linux x86-64 rt_sigaction uses this compact ordering, unlike musl's
 * public struct sigaction. Keep this ordinary application override usable
 * during startup as well as for the source-owned sigignore/siginterrupt
 * checks below. */
struct kernel_sigaction {
    void (*handler)(int);
    unsigned long flags;
    void (*restorer)(void);
    unsigned long mask;
};

_Static_assert(sizeof(struct kernel_sigaction) == 32,
    "x86-64 kernel sigaction layout");

__asm__(
    ".text\n"
    ".hidden override_signal_restorer\n"
    ".type override_signal_restorer,@function\n"
    "override_signal_restorer:\n"
    "mov $15, %rax\n"
    "syscall\n"
    "ud2\n"
    ".size override_signal_restorer, .-override_signal_restorer\n"
);

extern void override_signal_restorer(void);

static int clock_gettime_calls;
static int clock_nanosleep_calls;
static int dup3_calls;
static int fstat_calls;
static int fstatat_calls;
static int fstatfs_calls;
static int lseek_calls;
static int madvise_calls;
static int mmap_calls;
static int mprotect_calls;
static int munmap_calls;
static int statfs_calls;
static int sysinfo_calls;
static int sigaction_calls;

#define CHECK(expression) do { if (!(expression)) return __LINE__; } while (0)

int clock_gettime(clockid_t clock_id, struct timespec *output)
{
    ++clock_gettime_calls;
    return (int)syscall(SYS_clock_gettime, clock_id, output);
}

int clock_nanosleep(clockid_t clock_id, int flags,
    const struct timespec *request, struct timespec *remaining)
{
    ++clock_nanosleep_calls;
    {
        long result = syscall(SYS_clock_nanosleep, clock_id, flags, request, remaining);
        return result < 0 ? errno : (int)result;
    }
}

int dup3(int old_descriptor, int new_descriptor, int flags)
{
    ++dup3_calls;
    return (int)syscall(SYS_dup3, old_descriptor, new_descriptor, flags);
}

int fstat(int descriptor, struct stat *output)
{
    ++fstat_calls;
    return (int)syscall(SYS_fstat, descriptor, output);
}

int fstatat(int directory_descriptor, const char *path, struct stat *output, int flags)
{
    ++fstatat_calls;
    return (int)syscall(SYS_newfstatat, directory_descriptor, path, output, flags);
}

int fstatfs(int descriptor, struct statfs *output)
{
    ++fstatfs_calls;
    return (int)syscall(SYS_fstatfs, descriptor, output);
}

off_t lseek(int descriptor, off_t offset, int whence)
{
    ++lseek_calls;
    return (off_t)syscall(SYS_lseek, descriptor, offset, whence);
}

int madvise(void *address, size_t length, int advice)
{
    ++madvise_calls;
    return (int)syscall(SYS_madvise, address, length, advice);
}

void *mmap(void *address, size_t length, int protection, int flags,
    int descriptor, off_t offset)
{
    ++mmap_calls;
    return (void *)syscall(SYS_mmap, address, length, protection, flags, descriptor, offset);
}

int mprotect(void *address, size_t length, int protection)
{
    ++mprotect_calls;
    return (int)syscall(SYS_mprotect, address, length, protection);
}

int munmap(void *address, size_t length)
{
    ++munmap_calls;
    return (int)syscall(SYS_munmap, address, length);
}

int statfs(const char *path, struct statfs *output)
{
    ++statfs_calls;
    return (int)syscall(SYS_statfs, path, output);
}

int sysinfo(struct sysinfo *output)
{
    ++sysinfo_calls;
    return (int)syscall(SYS_sysinfo, output);
}

int sigaction(int signal_number, const struct sigaction *action,
    struct sigaction *old_action)
{
    struct kernel_sigaction kernel_action;
    struct kernel_sigaction old_kernel_action;
    const struct kernel_sigaction *kernel_action_pointer = NULL;
    struct kernel_sigaction *old_kernel_action_pointer = NULL;
    int result;

    ++sigaction_calls;
    if (action != NULL) {
        kernel_action.handler = action->sa_handler;
        kernel_action.flags = (unsigned long)(long)action->sa_flags | SA_RESTORER;
        kernel_action.restorer = override_signal_restorer;
        kernel_action.mask = action->sa_mask.__bits[0];
        kernel_action_pointer = &kernel_action;
    }
    if (old_action != NULL) {
        old_kernel_action_pointer = &old_kernel_action;
    }
    result = (int)syscall(SYS_rt_sigaction, signal_number, kernel_action_pointer,
        old_kernel_action_pointer, sizeof(unsigned long));
    if (result == 0 && old_action != NULL) {
        old_action->sa_handler = old_kernel_action.handler;
        old_action->sa_mask.__bits[0] = old_kernel_action.mask;
        old_action->sa_flags = (int)old_kernel_action.flags;
    }
    return result;
}

static int compare_keys(const void *left, const void *right)
{
    const int left_value = *(const int *)left;
    const int right_value = *(const int *)right;
    return (left_value > right_value) - (left_value < right_value);
}

int main(int argc, char **argv)
{
    struct timespec time = { 0, 0 };
    struct timespec immediate = { 0, 0 };
    struct stat metadata;
    struct statfs filesystem;
    struct sysinfo information;
    struct sigaction action;
    struct statvfs view;
    struct timeb legacy;
    double loads[3];
    sem_t semaphore;
    void *root = NULL;
    void *mapping;
    int key = 1;
    int descriptor;
    int duplicate;
    int calls_before;
    int shared_link;

    shared_link = argc == 3 && argv[2][0] == 's' && argv[2][1] == 'h'
        && argv[2][2] == 'a' && argv[2][3] == 'r' && argv[2][4] == 'e'
        && argv[2][5] == 'd' && argv[2][6] == '\0';
    CHECK(argc == 2 || shared_link);

    descriptor = open(argv[1], O_RDONLY);
    CHECK(descriptor >= 0);

    calls_before = clock_gettime_calls;
    CHECK(clock_gettime(CLOCK_REALTIME, &time) == 0 && clock_gettime_calls > calls_before);
    calls_before = clock_nanosleep_calls;
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &immediate, NULL) == 0
        && clock_nanosleep_calls > calls_before);
    calls_before = dup3_calls;
    duplicate = dup3(descriptor, descriptor + 32, O_CLOEXEC);
    CHECK(duplicate >= 0 && dup3_calls > calls_before);
    CHECK(close(duplicate) == 0);
    calls_before = fstat_calls;
    CHECK(fstat(descriptor, &metadata) == 0 && fstat_calls > calls_before);
    calls_before = fstatat_calls;
    CHECK(fstatat(AT_FDCWD, argv[1], &metadata, 0) == 0 && fstatat_calls > calls_before);
    calls_before = fstatfs_calls;
    CHECK(fstatfs(descriptor, &filesystem) == 0 && fstatfs_calls > calls_before);
    calls_before = lseek_calls;
    CHECK(lseek(descriptor, 0, SEEK_CUR) >= 0 && lseek_calls > calls_before);
    calls_before = mmap_calls;
    mapping = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED && mmap_calls > calls_before);
    calls_before = mprotect_calls;
    CHECK(mprotect(mapping, PAGE_BYTES, PROT_READ | PROT_WRITE) == 0
        && mprotect_calls > calls_before);
    calls_before = madvise_calls;
    CHECK(madvise(mapping, PAGE_BYTES, MADV_NORMAL) == 0 && madvise_calls > calls_before);
    calls_before = munmap_calls;
    CHECK(munmap(mapping, PAGE_BYTES) == 0 && munmap_calls > calls_before);
    calls_before = statfs_calls;
    CHECK(statfs(argv[1], &filesystem) == 0 && statfs_calls > calls_before);
    calls_before = sysinfo_calls;
    CHECK(sysinfo(&information) == 0 && sysinfo_calls > calls_before);
    calls_before = sysinfo_calls;
    CHECK(getloadavg(loads, 3) == 3
        && (shared_link ? sysinfo_calls == calls_before : sysinfo_calls > calls_before));
    calls_before = sigaction_calls;
    CHECK(sigaction(SIGUSR1, NULL, &action) == 0 && sigaction_calls > calls_before);

    calls_before = fstat_calls;
    CHECK(__fxstat(0, descriptor, &metadata) == 0
        && (shared_link ? fstat_calls == calls_before : fstat_calls > calls_before));
    calls_before = fstatat_calls;
    CHECK(__fxstatat(0, AT_FDCWD, argv[1], &metadata, 0) == 0
        && (shared_link ? fstatat_calls == calls_before : fstatat_calls > calls_before));
    calls_before = statfs_calls;
    CHECK(statvfs(argv[1], &view) == 0 && statfs_calls == calls_before);
    calls_before = fstatfs_calls;
    CHECK(fstatvfs(descriptor, &view) == 0 && fstatfs_calls == calls_before);

    CHECK(sem_init(&semaphore, 0, 0) == 0);
    time.tv_sec = 0;
    time.tv_nsec = 0;
    calls_before = clock_gettime_calls;
    CHECK(sem_timedwait(&semaphore, &time) == -1);
    CHECK(clock_gettime_calls == calls_before);
    CHECK(sem_destroy(&semaphore) == 0);

    calls_before = sigaction_calls;
    CHECK(signal(SIGUSR1, SIG_IGN) != SIG_ERR && sigaction_calls == calls_before);
    CHECK(signal(SIGUSR1, SIG_DFL) != SIG_ERR && sigaction_calls == calls_before);
    calls_before = sigaction_calls;
    CHECK(sigignore(SIGUSR1) == 0
        && (shared_link ? sigaction_calls == calls_before : sigaction_calls > calls_before));
    calls_before = sigaction_calls;
    CHECK(sigaction(SIGUSR1, NULL, &action) == 0
        && action.sa_handler == SIG_IGN && sigaction_calls > calls_before);
    calls_before = sigaction_calls;
    CHECK(siginterrupt(SIGUSR1, 1) == 0
        && (shared_link ? sigaction_calls == calls_before : sigaction_calls > calls_before));
    calls_before = clock_gettime_calls;
    CHECK(ftime(&legacy) == 0);
    CHECK(shared_link ? clock_gettime_calls == calls_before : clock_gettime_calls > calls_before);

    calls_before = mmap_calls;
    CHECK(tsearch(&key, &root, compare_keys) != NULL && mmap_calls == calls_before);
    tdestroy(root, NULL);
    CHECK(close(descriptor) == 0);

    CHECK(write(STDOUT_FILENO, "owned-syscall-alias-override-ok\n", 32) == 32);
    return 0;
}
