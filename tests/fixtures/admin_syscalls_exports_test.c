#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern int prctl(int, ...);
extern int personality(unsigned long);
extern int setns(int, int);
extern int unshare(int);
extern int membarrier(int, unsigned int, int);
extern int memfd_create(const char *, unsigned int);
extern ssize_t readahead(int, off_t, size_t);
extern int sync_file_range(int, off_t, off_t, unsigned int);
extern int syncfs(int);

struct statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
};

/* Keep this layout in lockstep with Linux's architecture-independent statx ABI. */
struct statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct statx_timestamp stx_atime;
    struct statx_timestamp stx_btime;
    struct statx_timestamp stx_ctime;
    struct statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint32_t stx_dio_mem_align;
    uint32_t stx_dio_offset_align;
    uint64_t __spare3[12];
};

extern int statx(int, const char *, int, unsigned int, struct statx *);

#define MFD_CLOEXEC 0x0001U
#define PR_GET_NAME 16
#define PR_SET_NAME 15
#define PR_GET_NO_NEW_PRIVS 39
#define MEMBARRIER_CMD_QUERY 0
#define STATX_TYPE 0x00000001U
#define STATX_SIZE 0x00000200U
#define STATX_BASIC_STATS 0x000007ffU

int main(void)
{
    char path[] = "/tmp/crabc-c-abi-admin-XXXXXX";
    const char payload[] = "admin syscall test\n";
    char old_name[16] = { 0 };
    char new_name[] = "crabc-c-abi-admin";
    char observed_name[16] = { 0 };
    struct statx stx;
    int fd = -1;
    int memfd = -1;
    int result = 1;
    int membarrier_mask;

    if (sizeof stx != 256)
        goto cleanup;
    if (prctl(PR_GET_NAME, old_name) != 0)
        goto cleanup;
    if (prctl(PR_SET_NAME, new_name) != 0)
        goto cleanup;
    if (prctl(PR_GET_NAME, observed_name) != 0 ||
        strcmp(observed_name, new_name) != 0)
        goto cleanup;
    if (prctl(PR_SET_NAME, old_name) != 0)
        goto cleanup;
    if (prctl(PR_GET_NO_NEW_PRIVS) != 0)
        goto cleanup;

    /* Querying does not change the process personality.  Some CI sandboxes
     * deny personality(2) through seccomp even though the syscall exists. */
    errno = 0;
    if (personality(~0UL) < 0 && errno != EPERM && errno != ENOSYS)
        goto cleanup;

    /* These invalid calls exercise errno conversion without changing state.
     * Namespace syscalls are commonly denied by CI seccomp profiles. */
    errno = 0;
    if (setns(-1, 0) != -1 ||
        (errno != EBADF && errno != EPERM && errno != ENOSYS))
        goto cleanup;
    errno = 0;
    if (unshare(-1) != -1 ||
        (errno != EINVAL && errno != EPERM && errno != ENOSYS))
        goto cleanup;

    membarrier_mask = membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
    if (membarrier_mask < 0 && errno != ENOSYS)
        goto cleanup;

    fd = mkstemp(path);
    if (fd < 0)
        goto cleanup;
    if (write(fd, payload, sizeof payload - 1) != (ssize_t)(sizeof payload - 1))
        goto cleanup;
    if (readahead(fd, 0, sizeof payload - 1) != 0)
        goto cleanup;
    if (sync_file_range(fd, 0, sizeof payload - 1, 1U | 4U) != 0)
        goto cleanup;
    if (syncfs(fd) != 0)
        goto cleanup;

    memset(&stx, 0, sizeof stx);
    if (statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &stx) != 0 ||
        (stx.stx_mask & (STATX_TYPE | STATX_SIZE)) != (STATX_TYPE | STATX_SIZE) ||
        (stx.stx_mode & S_IFMT) != S_IFREG ||
        stx.stx_size != sizeof payload - 1)
        goto cleanup;

    memfd = memfd_create("crabc-c-abi-admin", MFD_CLOEXEC);
    if (memfd < 0)
        goto cleanup;
    if (write(memfd, payload, sizeof payload - 1) != (ssize_t)(sizeof payload - 1))
        goto cleanup;

    result = 0;

cleanup:
    if (memfd >= 0)
        close(memfd);
    if (fd >= 0)
        close(fd);
    if (path[0])
        unlink(path);
    if (result == 0)
        puts("c-abi admin syscalls exports ok");
    return result;
}
