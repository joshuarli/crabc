/* Pinned-musl observable contract for installed temporary-object ownership.
 * argv[1] is a private existing directory supplied by the harness. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    char path[4096], original[4096];
    mode_t prior_mask = umask(0027);
    for (int kind = 0; kind < 4; kind++) {
        int suffix = kind >= 2 ? 4 : 0;
        int count = snprintf(path, sizeof path, "%s/file-XXXXXX%s", argv[1], suffix ? ".end" : "");
        CHECK(count > 0 && (size_t)count < sizeof path);
        memcpy(original, path, count + 1);
        errno = 66;
        int fd = kind == 0 ? mkstemp(path)
            : kind == 1 ? mkostemp(path, O_WRONLY | O_CLOEXEC | O_APPEND)
            : kind == 2 ? mkstemps(path, suffix)
            : mkostemps(path, suffix, O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0 && errno == 66);
        CHECK(!memcmp(path, original, count - suffix - 6));
        CHECK(!strcmp(path + count - suffix, original + count - suffix));
        CHECK(memcmp(path + count - suffix - 6, "XXXXXX", 6));
        struct stat st;
        CHECK(!fstat(fd, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600);
        CHECK((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR);
        CHECK(!!(fcntl(fd, F_GETFD) & FD_CLOEXEC) == (kind == 1 || kind == 3));
        CHECK(!!(fcntl(fd, F_GETFL) & O_APPEND) == (kind == 1));
        CHECK(write(fd, "owned", 5) == 5 && lseek(fd, 0, SEEK_SET) == 0);
        char got[5];
        CHECK(read(fd, got, sizeof got) == sizeof got && !memcmp(got, "owned", sizeof got));
        CHECK(unlink(path) == 0 && fstat(fd, &st) == 0 && st.st_nlink == 0);
        CHECK(close(fd) == 0);
    }

    CHECK(snprintf(path, sizeof path, "%s/dir-XXXXXX", argv[1]) > 0);
    errno = 67;
    CHECK(mkdtemp(path) == path && errno == 67);
    struct stat st;
    CHECK(!stat(path, &st) && S_ISDIR(st.st_mode) && (st.st_mode & 0777) == 0700);
    CHECK(rmdir(path) == 0);

    const char *invalid[] = {"", "XXXXX", "XXXXXY", "XXXXXX.end"};
    for (unsigned i = 0; i < sizeof invalid / sizeof *invalid; i++) {
        strcpy(path, invalid[i]);
        errno = 0;
        CHECK(mkstemp(path) == -1 && errno == EINVAL && !strcmp(path, invalid[i]));
        errno = 0;
        CHECK(mkdtemp(path) == NULL && errno == EINVAL && !strcmp(path, invalid[i]));
    }
    strcpy(path, "XXXXXX.end");
    errno = 0;
    CHECK(mkstemps(path, -1) == -1 && errno == EINVAL && !strcmp(path, "XXXXXX.end"));
    errno = 0;
    CHECK(mkostemps(path, INT_MAX, 0) == -1 && errno == EINVAL && !strcmp(path, "XXXXXX.end"));

    CHECK(snprintf(path, sizeof path, "%s/missing/XXXXXX.end", argv[1]) > 0);
    strcpy(original, path);
    errno = 0;
    CHECK(mkostemps(path, 4, O_CLOEXEC) == -1 && errno == ENOENT && !strcmp(path, original));
    CHECK(snprintf(path, sizeof path, "%s/missing/XXXXXX", argv[1]) > 0);
    strcpy(original, path);
    errno = 0;
    CHECK(mkdtemp(path) == NULL && errno == ENOENT && !strcmp(path, original));
    umask(prior_mask);
    CHECK(write(1, "owned-temp-ok\n", 14) == 14);
    return 0;
}
