#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            goto cleanup; \
        } \
    } while (0)

static int check_prlimit(void)
{
    struct rlimit limit;

    errno = 0;
    if (prlimit(0, RLIMIT_NOFILE, NULL, &limit) != 0 ||
        limit.rlim_max < limit.rlim_cur)
        return 0;

    errno = 0;
    if (prlimit(0, -1, NULL, &limit) != -1 || errno != EINVAL)
        return 0;

    errno = 0;
    if (prlimit(0, RLIMIT_NOFILE, NULL, (struct rlimit *)1) != -1 ||
        errno != EFAULT)
        return 0;
    return 1;
}

static int check_process_vm(void)
{
    char source[] = "process-vm-source";
    char destination[sizeof source] = { 0 };
    char replacement[] = "process-vm-write";
    struct iovec local = { destination, sizeof destination };
    struct iovec remote = { source, sizeof source };

    errno = 0;
    if (process_vm_readv(getpid(), &local, 1, &remote, 1, 0) !=
            (ssize_t)sizeof source ||
        strcmp(destination, source) != 0)
        return 0;

    local.iov_base = replacement;
    local.iov_len = sizeof replacement;
    remote.iov_len = sizeof replacement;
    if (process_vm_writev(getpid(), &local, 1, &remote, 1, 0) !=
            (ssize_t)sizeof replacement ||
        strcmp(source, replacement) != 0)
        return 0;

    errno = 0;
    if (process_vm_readv(getpid(), NULL, 1, &remote, 1, 0) != -1 ||
        errno != EFAULT)
        return 0;
    return 1;
}

int main(void)
{
    const size_t page = 4096;
    void *mapping = MAP_FAILED;
    void *file_mapping = MAP_FAILED;
    int fd = -1;
    char path[] = "/tmp/crabc-c-abi-remap-XXXXXX";
    int result = 1;

    CHECK(check_prlimit(), "prlimit");
    CHECK(check_process_vm(), "process_vm");

    mapping = mmap(NULL, page, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED, "mmap lock");
    errno = 0;
    CHECK(mlock2(mapping, page, MLOCK_ONFAULT) == 0, "mlock2");
    CHECK(munlock(mapping, page) == 0, "munlock");
    errno = 0;
    CHECK(mlock2(mapping, page, 2U) == -1 && errno == EINVAL,
          "mlock2 errno");

    fd = mkstemp(path);
    CHECK(fd >= 0, "mkstemp");
    CHECK(ftruncate(fd, (off_t)(page * 2)) == 0, "ftruncate");
    CHECK(pwrite(fd, "A", 1, 0) == 1 && pwrite(fd, "B", 1, (off_t)page) == 1,
          "pwrite");
    file_mapping = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, 0);
    CHECK(file_mapping != MAP_FAILED, "mmap file");
    /* Linux requires the legacy prot argument to be zero. */
    CHECK(remap_file_pages(file_mapping, page, 0, 1, 0) == 0,
          "remap_file_pages");
    CHECK(*(char *)file_mapping == 'B', "remap contents");

    errno = 0;
    CHECK(remap_file_pages(file_mapping, page, PROT_READ, 0, 1) == -1 &&
              errno == EINVAL,
          "remap_file_pages errno");
    result = 0;

cleanup:
    if (file_mapping != MAP_FAILED)
        munmap(file_mapping, page * 2);
    if (mapping != MAP_FAILED)
        munmap(mapping, page);
    if (fd >= 0)
        close(fd);
    unlink(path);
    if (result == 0)
        puts("c-abi kernel resource ops ok");
    return result;
}
