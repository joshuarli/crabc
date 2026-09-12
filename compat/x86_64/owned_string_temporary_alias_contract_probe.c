/* Pinned-musl observable contract for the five selected string/temp aliases.
 * argv[1] is a private existing directory supplied by the harness. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

int main(int argc, char **argv)
{
    char copied[16] = { 0 };
    char padded[16] = { 0xa5 };
    const char searched[] = "abca";
    const unsigned char bytes[] = { 1, 2, 3, 2, 1 };
    char path[4096];
    char original[4096];
    struct stat status;
    int descriptor;
    int length;

    CHECK(argc == 2);
    CHECK(stpcpy(copied, "copy") == copied + 4 && !strcmp(copied, "copy"));
    CHECK(stpncpy(padded, "pad", 6) == padded + 3 &&
        !memcmp(padded, "pad\0\0\0", 6));
    CHECK(strchrnul(searched, 'z') == searched + 4 &&
        strchrnul(searched, 'c') == searched + 2);
    CHECK(memrchr(bytes, 2, sizeof bytes) == bytes + 3 &&
        memrchr(bytes, 4, sizeof bytes) == NULL);

    length = snprintf(path, sizeof path, "%s/alias-XXXXXX.tail", argv[1]);
    CHECK(length > 0 && (size_t)length < sizeof path);
    memcpy(original, path, (size_t)length + 1);
    descriptor = mkostemps(path, 5, O_CLOEXEC);
    CHECK(descriptor >= 0);
    CHECK(!memcmp(path, original, (size_t)length - 11));
    CHECK(!strcmp(path + length - 5, ".tail"));
    CHECK(memcmp(path + length - 11, "XXXXXX", 6));
    CHECK(!fstat(descriptor, &status) && S_ISREG(status.st_mode) &&
        (status.st_mode & 0777) == 0600 &&
        (fcntl(descriptor, F_GETFL) & O_ACCMODE) == O_RDWR &&
        !!(fcntl(descriptor, F_GETFD) & FD_CLOEXEC));
    CHECK(unlink(path) == 0 && fstat(descriptor, &status) == 0 &&
        status.st_nlink == 0 && close(descriptor) == 0);

    CHECK(puts("owned-string-temporary-alias-contract-ok") >= 0);
    return 0;
}
