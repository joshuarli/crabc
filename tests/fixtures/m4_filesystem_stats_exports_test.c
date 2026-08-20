#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/* Keep these declarations local to the fixture: the public header slice does
 * not yet expose the historical Linux statfs/timeb/utime headers, but the
 * exported functions and their 64-bit layouts are part of the ABI under test.
 */
struct statfs {
    unsigned long f_type;
    unsigned long f_bsize;
    unsigned long f_blocks;
    unsigned long f_bfree;
    unsigned long f_bavail;
    unsigned long f_files;
    unsigned long f_ffree;
    int f_fsid[2];
    unsigned long f_namelen;
    unsigned long f_frsize;
    unsigned long f_flags;
    unsigned long f_spare[4];
};

struct utimbuf {
    time_t actime;
    time_t modtime;
};

struct timeb {
    time_t time;
    unsigned short millitm;
    short timezone;
    short dstflag;
};

extern int statfs(const char *, struct statfs *);
extern int fstatfs(int, struct statfs *);
extern int lutimes(const char *, const struct timeval[2]);
extern int utime(const char *, const struct utimbuf *);
extern int ftime(struct timeb *);

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            goto cleanup; \
        } \
    } while (0)

int main(void)
{
    char file_name[] = "/tmp/crabc-m4-stat-XXXXXX";
    char link_name[256] = { 0 };
    struct statfs path_fs;
    struct statfs fd_fs;
    struct utimbuf legacy_times = { 123456789, 123456790 };
    struct timeval link_times[2] = {
        { 222222222, 333000 },
        { 222222223, 444000 },
    };
    struct timeval invalid_times[2] = {
        { 0, 1000000 },
        { 0, 0 },
    };
    struct timeb now;
    int file = -1;
    int result = 1;

    file = mkstemp(file_name);
    CHECK(file >= 0, "mkstemp");
    CHECK(statfs(file_name, &path_fs) == 0, "statfs path");
    CHECK(path_fs.f_bsize != 0 && path_fs.f_blocks != 0, "statfs values");
    errno = 0;
    CHECK(statfs("/tmp/crabc-m4-stat-missing", &path_fs) == -1 &&
              errno == ENOENT,
          "statfs errno");
    CHECK(fstatfs(file, &fd_fs) == 0, "fstatfs");
    CHECK(fd_fs.f_bsize == path_fs.f_bsize &&
              fd_fs.f_type == path_fs.f_type,
          "statfs/fstatfs consistency");

    CHECK(utime(file_name, &legacy_times) == 0, "utime");
    /* `struct stat` layout verification belongs to M5. This M4 fixture
     * exercises utime's native syscall success/error boundary directly. */

    CHECK(snprintf(link_name, sizeof link_name, "%s.link", file_name) > 0,
          "link path");
    CHECK(symlink(file_name, link_name) == 0, "symlink");
    CHECK(lutimes(link_name, link_times) == 0, "lutimes");
    errno = 0;
    CHECK(lutimes(link_name, invalid_times) == -1 && errno == EINVAL,
          "lutimes validation");

    memset(&now, 0, sizeof now);
    CHECK(ftime(&now) == 0 && now.time > 0 && now.millitm < 1000,
          "ftime");

    result = 0;
    puts("m4 filesystem stats exports ok");

cleanup:
    if (file >= 0)
        close(file);
    unlink(file_name);
    if (link_name[0])
        unlink(link_name);
    return result;
}
