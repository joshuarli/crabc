#define _GNU_SOURCE 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

static int has_name(const char *buf, int len, const char *wanted)
{
    int pos = 0;
    while (pos < len) {
        const struct dirent *entry = (const struct dirent *)(buf + pos);
        if (entry->d_reclen < 19 || pos + entry->d_reclen > len)
            return 0;
        if (strcmp(entry->d_name, wanted) == 0)
            return 1;
        pos += entry->d_reclen;
    }
    return 0;
}

static int test_vectors(void)
{
    char name[] = "/tmp/crabc-m4-advanced-io-XXXXXX";
    char first[] = "ab";
    char second[] = "cd";
    char synced[] = "EF";
    char tail[] = "G";
    char read_back[7] = { 0 };
    char current_back[2] = { 0 };
    struct iovec first_vec[] = {
        { first, sizeof first - 1 },
        { second, sizeof second - 1 },
    };
    struct iovec synced_vec[] = {
        { synced, sizeof synced - 1 },
    };
    struct iovec tail_vec[] = {
        { tail, sizeof tail - 1 },
    };
    struct iovec read_vec[] = {
        { read_back, 3 },
        { read_back + 3, 4 },
    };
    struct iovec current_vec[] = {
        { current_back, 1 },
    };
    int fd = mkstemp(name);

    CHECK(fd >= 0, "mkstemp");
    CHECK(pwritev2(fd, first_vec, 2, 0, 0) == 4, "pwritev2");
    CHECK(lseek(fd, 0, SEEK_CUR) == 0, "pwritev2 changed offset");
    CHECK(pwritev2(fd, synced_vec, 1, 4, RWF_DSYNC) == 2,
          "pwritev2 flags");
    CHECK(preadv2(fd, read_vec, 2, 0, 0) == 6, "preadv2");
    CHECK(memcmp(read_back, "abcdEF", 6) == 0, "preadv2 data");

    CHECK(lseek(fd, 6, SEEK_SET) == 6, "lseek current write");
    CHECK(pwritev2(fd, tail_vec, 1, -1, 0) == 1,
          "pwritev2 current offset");
    CHECK(lseek(fd, 6, SEEK_SET) == 6, "lseek current read");
    CHECK(preadv2(fd, current_vec, 1, -1, 0) == 1 && current_back[0] == 'G',
          "preadv2 current offset");

    errno = 0;
    CHECK(preadv2(-1, current_vec, 1, 0, 0) == -1 && errno == EBADF,
          "preadv2 error");
    errno = 0;
    CHECK(pwritev2(-1, tail_vec, 1, 0, RWF_DSYNC) == -1 && errno == EBADF,
          "pwritev2 error");

    CHECK(close(fd) == 0, "close vector file");
    unlink(name);
    return 0;
}

static int test_directory_calls(void)
{
    char dir_name[] = "/tmp/crabc-m4-advanced-dents-XXXXXX";
    char file_name[256];
    char buffer[4096];
    int fd;
    int result;
    ssize_t posix_result;

    CHECK(mkdtemp(dir_name) != NULL, "mkdtemp");
    CHECK(snprintf(file_name, sizeof file_name, "%s/entry", dir_name) > 0,
          "directory path");
    fd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0 && close(fd) == 0, "directory entry");

    fd = open(dir_name, O_RDONLY | O_DIRECTORY);
    CHECK(fd >= 0, "getdents open");
    result = getdents(fd, (struct dirent *)buffer, sizeof buffer);
    CHECK(result > 0 && has_name(buffer, result, "entry"), "getdents");
    CHECK(close(fd) == 0, "getdents close");

    fd = open(dir_name, O_RDONLY | O_DIRECTORY);
    CHECK(fd >= 0, "posix_getdents open");
    posix_result = posix_getdents(fd, buffer, sizeof buffer, 0);
    CHECK(posix_result > 0 && has_name(buffer, (int)posix_result, "entry"),
          "posix_getdents");
    errno = 0;
    CHECK(posix_getdents(fd, buffer, sizeof buffer, 1) == -1 &&
              errno == EOPNOTSUPP,
          "posix_getdents flags");
    CHECK(close(fd) == 0, "posix_getdents close");

    errno = 0;
    CHECK(getdents(-1, (struct dirent *)buffer, sizeof buffer) == -1 &&
              errno == EBADF,
          "getdents error");
    errno = 0;
    CHECK(posix_close(-1, 0) == -1 && errno == EBADF, "posix_close error");

    fd = open(dir_name, O_RDONLY | O_DIRECTORY);
    CHECK(fd >= 0, "posix_close open");
    CHECK(posix_close(fd, 0) == 0, "posix_close");

    unlink(file_name);
    CHECK(rmdir(dir_name) == 0, "rmdir");
    return 0;
}

int main(void)
{
    if (test_vectors() != 0)
        return 1;
    if (test_directory_calls() != 0)
        return 2;
    puts("m4 advanced io exports ok");
    return 0;
}
