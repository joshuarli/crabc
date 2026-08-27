/* Pinned-musl/raw Linux/x86-64 global sync ABI reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { PAYLOAD_SIZE = 6 };

_Static_assert(SYS_sync == 162, "x86 sync syscall number");
_Static_assert(sizeof(int) == 4, "x86 int width");
_Static_assert(sizeof(long) == 8, "x86 LP64 long width");

int main(void)
{
    static const unsigned char payload[PAYLOAD_SIZE] = {
        'c', 'r', 'a', 'b', 'c', '!'};
    char template[] = "/tmp/crabc-x86-sync-XXXXXX";
    struct stat status;
    int fd = -1;
    int result = 0;

    fd = mkstemp(template);
    if (fd < 0)
        return 10;
    if (unlink(template) != 0) {
        result = 11;
        goto cleanup;
    }
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)) {
        result = 12;
        goto cleanup;
    }
    if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload)) {
        result = 13;
        goto cleanup;
    }

    /*
     * musl's sync has no status result. Its normal return and the raw
     * syscall's zero result establish only this global kernel ABI boundary.
     * Neither call measures writeback duration or media/cache durability.
     */
    sync();

    /* Keep a disposable regular file dirty for the raw global request too. */
    if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload)) {
        result = 14;
        goto cleanup;
    }
    if (syscall(SYS_sync) != 0) {
        result = 15;
        goto cleanup;
    }

cleanup:
    /* This also handles failures before the initial unlink. */
    (void)unlink(template);
    if (fd >= 0 && close(fd) != 0 && result == 0)
        result = 20;
    if (result != 0)
        return result;

    puts("syscall=162 musl=returned raw=0 dirty-regular-file=used "
         "timing=unproved durability=unproved");
    return 0;
}
