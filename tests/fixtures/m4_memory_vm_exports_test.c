#define _GNU_SOURCE 1

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

extern int mincore(void *, size_t, unsigned char *);
extern int madvise(void *, size_t, int);
extern void *mremap(void *, size_t, size_t, int, ...);

#define MREMAP_MAYMOVE 1

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            goto cleanup; \
        } \
    } while (0)

static int permitted_lock_error(int error)
{
    return error == EPERM || error == ENOMEM || error == EAGAIN || error == EINVAL;
}

int main(void)
{
    const size_t page = 4096;
    unsigned char resident = 0;
    void *mapping = MAP_FAILED;
    void *resized = MAP_FAILED;
    int locked = 0;
    int all_locked = 0;
    int result = 1;

    mapping = mmap(NULL, page, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED, "mmap");
    ((unsigned char *)mapping)[0] = 0x5a;

    CHECK(mprotect(mapping, page, PROT_READ) == 0, "mprotect read");
    errno = 0;
    CHECK(mprotect(mapping, page, 0x80) == -1 &&
              errno == EINVAL,
          "mprotect errno");
    CHECK(mprotect(mapping, page, PROT_READ | PROT_WRITE) == 0,
          "mprotect write");

    CHECK(mincore(mapping, page, &resident) == 0 && (resident & 1),
          "mincore");
    CHECK(madvise(mapping, page, POSIX_MADV_NORMAL) == 0, "madvise");
    CHECK(posix_madvise(mapping, page, POSIX_MADV_NORMAL) == 0,
          "posix_madvise");
    CHECK(msync(mapping, page, MS_SYNC) == 0, "msync");

    errno = 0;
    if (mlock(mapping, page) == 0) {
        locked = 1;
        CHECK(munlock(mapping, page) == 0, "munlock");
    } else {
        CHECK(permitted_lock_error(errno), "mlock permitted error");
    }

    errno = 0;
    if (mlockall(MCL_CURRENT) == 0) {
        all_locked = 1;
        CHECK(munlockall() == 0, "munlockall");
    } else {
        CHECK(permitted_lock_error(errno), "mlockall permitted error");
    }

    resized = mremap(mapping, page, page * 2, MREMAP_MAYMOVE);
    CHECK(resized != MAP_FAILED, "mremap");
    mapping = resized;
    ((unsigned char *)mapping)[page] = 0xa5;
    CHECK(munmap(mapping, page * 2) == 0, "munmap resized");
    mapping = MAP_FAILED;
    result = 0;
    puts("m4 memory vm ok");

cleanup:
    (void)locked;
    (void)all_locked;
    if (mapping != MAP_FAILED)
        munmap(mapping, page);
    return result;
}
