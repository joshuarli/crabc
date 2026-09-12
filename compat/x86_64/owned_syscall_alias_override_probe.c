/*
 * Public-override regression for musl 1.2.6 syscall-facing weak aliases.
 *
 * A valid application may provide strong definitions for these public names.
 * Before the alias correction, the native static archive defines all fourteen
 * names strongly and rejects this one-object program with duplicate symbols.
 * After the weak-alias correction this same object also proves that ordinary
 * public calls resolve to the application while selected libc implementation
 * paths retain their musl-shaped internal bodies.  The runner supplies one
 * regular pathname so static and chrooted shared executions see identical
 * filesystem inputs.
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stddef.h>
#include <search.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/timeb.h>
#include <time.h>
#include <unistd.h>

extern int __fxstat(int, int, struct stat *);
extern int __fxstatat(int, int, const char *, struct stat *, int);

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
    (void)clock_id;
    ++clock_gettime_calls;
    if (output != NULL) {
        output->tv_sec = 123;
        output->tv_nsec = 456000000;
    }
    return 71;
}

int clock_nanosleep(clockid_t clock_id, int flags,
    const struct timespec *request, struct timespec *remaining)
{
    (void)clock_id;
    (void)flags;
    (void)request;
    (void)remaining;
    ++clock_nanosleep_calls;
    return 72;
}

int dup3(int old_descriptor, int new_descriptor, int flags)
{
    (void)old_descriptor;
    (void)new_descriptor;
    (void)flags;
    ++dup3_calls;
    return 73;
}

int fstat(int descriptor, struct stat *output)
{
    (void)descriptor;
    (void)output;
    ++fstat_calls;
    return 74;
}

int fstatat(int directory_descriptor, const char *path, struct stat *output, int flags)
{
    (void)directory_descriptor;
    (void)path;
    (void)output;
    (void)flags;
    ++fstatat_calls;
    return 75;
}

int fstatfs(int descriptor, struct statfs *output)
{
    (void)descriptor;
    (void)output;
    ++fstatfs_calls;
    return 76;
}

off_t lseek(int descriptor, off_t offset, int whence)
{
    (void)descriptor;
    (void)offset;
    (void)whence;
    ++lseek_calls;
    return 77;
}

int madvise(void *address, size_t length, int advice)
{
    (void)address;
    (void)length;
    (void)advice;
    ++madvise_calls;
    return 78;
}

void *mmap(void *address, size_t length, int protection, int flags,
    int descriptor, off_t offset)
{
    (void)address;
    (void)length;
    (void)protection;
    (void)flags;
    (void)descriptor;
    (void)offset;
    ++mmap_calls;
    return MAP_FAILED;
}

int mprotect(void *address, size_t length, int protection)
{
    (void)address;
    (void)length;
    (void)protection;
    ++mprotect_calls;
    return 79;
}

int munmap(void *address, size_t length)
{
    (void)address;
    (void)length;
    ++munmap_calls;
    return 80;
}

int statfs(const char *path, struct statfs *output)
{
    (void)path;
    (void)output;
    ++statfs_calls;
    return 81;
}

int sysinfo(struct sysinfo *output)
{
    (void)output;
    ++sysinfo_calls;
    return 82;
}

int sigaction(int signal_number, const struct sigaction *action,
    struct sigaction *old_action)
{
    (void)signal_number;
    (void)action;
    (void)old_action;
    ++sigaction_calls;
    return 83;
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
    struct stat metadata;
    struct statfs filesystem;
    struct sysinfo information;
    struct sigaction action;
    struct statvfs view;
    struct timeb legacy;
    sem_t semaphore;
    void *root = NULL;
    int key = 1;
    int descriptor;

    CHECK(argc == 2);

    CHECK(clock_gettime(CLOCK_REALTIME, &time) == 71 && clock_gettime_calls == 1);
    CHECK(clock_nanosleep(CLOCK_REALTIME, 0, &time, NULL) == 72 && clock_nanosleep_calls == 1);
    CHECK(dup3(1, 2, 0) == 73 && dup3_calls == 1);
    CHECK(fstat(0, &metadata) == 74 && fstat_calls == 1);
    CHECK(fstatat(AT_FDCWD, argv[1], &metadata, 0) == 75 && fstatat_calls == 1);
    CHECK(fstatfs(0, &filesystem) == 76 && fstatfs_calls == 1);
    CHECK(lseek(0, 0, SEEK_CUR) == 77 && lseek_calls == 1);
    CHECK(madvise(NULL, 0, MADV_NORMAL) == 78 && madvise_calls == 1);
    CHECK(mmap(NULL, 0, 0, 0, -1, 0) == MAP_FAILED && mmap_calls == 1);
    CHECK(mprotect(NULL, 0, 0) == 79 && mprotect_calls == 1);
    CHECK(munmap(NULL, 0) == 80 && munmap_calls == 1);
    CHECK(statfs(argv[1], &filesystem) == 81 && statfs_calls == 1);
    CHECK(sysinfo(&information) == 82 && sysinfo_calls == 1);
    CHECK(sigaction(SIGUSR1, NULL, &action) == 83 && sigaction_calls == 1);

    descriptor = open(argv[1], O_RDONLY);
    CHECK(descriptor >= 0);
    CHECK(__fxstat(0, descriptor, &metadata) == 74 && fstat_calls == 2);
    CHECK(__fxstatat(0, AT_FDCWD, argv[1], &metadata, 0) == 75 && fstatat_calls == 2);
    CHECK(statvfs(argv[1], &view) == 0 && statfs_calls == 1);
    CHECK(fstatvfs(descriptor, &view) == 0 && fstatfs_calls == 1);
    CHECK(close(descriptor) == 0);

    CHECK(sem_init(&semaphore, 0, 0) == 0);
    time.tv_sec = 0;
    time.tv_nsec = 0;
    CHECK(sem_timedwait(&semaphore, &time) == -1);
    CHECK(clock_gettime_calls == 1);
    CHECK(sem_destroy(&semaphore) == 0);

    CHECK(signal(SIGUSR1, SIG_IGN) != SIG_ERR && sigaction_calls == 1);
    CHECK(signal(SIGUSR1, SIG_DFL) != SIG_ERR && sigaction_calls == 1);
    CHECK(ftime(&legacy) == 0);
    CHECK(legacy.time == 123 && legacy.millitm == 456 && clock_gettime_calls == 2);

    CHECK(tsearch(&key, &root, compare_keys) != NULL && mmap_calls == 1);
    tdestroy(root, NULL);

    CHECK(write(STDOUT_FILENO, "owned-syscall-alias-override-ok\n", 32) == 32);
    return 0;
}
