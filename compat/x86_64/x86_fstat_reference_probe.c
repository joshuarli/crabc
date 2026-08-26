/* Pinned-musl Linux/x86-64 fstat behavior reference. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    char path[128];
    if (snprintf(path, sizeof(path), "/tmp/crabc-x86-fstat-reference-%ld",
                 (long)getpid()) < 0) return 1;
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    struct stat value;
    int status = 0;
    if (fd < 0) return 2;
    if (fchmod(fd, 0640) != 0) {
        status = 3;
        goto cleanup;
    }
    if (ftruncate(fd, 37) != 0) {
        status = 4;
        goto cleanup;
    }
    if (fstat(fd, &value) != 0) {
        status = 5;
        goto cleanup;
    }
    if (!S_ISREG(value.st_mode) || value.st_size != 37 ||
        (value.st_mode & 0777) != 0640 || value.st_nlink < 1 ||
        value.st_atim.tv_nsec < 0 || value.st_atim.tv_nsec >= 1000000000L ||
        value.st_mtim.tv_nsec < 0 || value.st_mtim.tv_nsec >= 1000000000L ||
        value.st_ctim.tv_nsec < 0 || value.st_ctim.tv_nsec >= 1000000000L) {
        status = 6;
        goto cleanup;
    }
cleanup:
    if (close(fd) != 0 && status == 0) status = 7;
    if (unlink(path) != 0 && status == 0) status = 8;
    if (status != 0) return status;
    puts("regular=size37=mode0640=timespec-valid");
    return 0;
}
