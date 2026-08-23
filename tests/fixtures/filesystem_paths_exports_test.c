#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

extern int flock(int, int);
extern int futimes(int, const struct timeval[2]);
extern int futimesat(int, const char *, const struct timeval[2]);

#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            goto cleanup; \
        } \
    } while (0)

int main(void)
{
    char file_name[] = "/tmp/crabc-c-abi-paths-file-XXXXXX";
    char dir_name[256] = { 0 };
    char link_name[256] = { 0 };
    char fifo_name[256] = { 0 };
    char node_name[256] = { 0 };
    char remove_dir_name[256] = { 0 };
    char cwd_before[256];
    char cwd_after[256];
    const char fifo_at_name[] = "fifo-at";
    const char node_at_name[] = "node-at";
    struct timeval times[2] = {
        { 1234, 456000 },
        { 1235, 789000 },
    };
    int file = -1;
    int dir = -1;
    int result = 1;

    file = mkstemp(file_name);
    CHECK(file >= 0, "mkstemp");
    CHECK(snprintf(dir_name, sizeof dir_name, "%s.dir", file_name) > 0,
          "directory path");
    CHECK(snprintf(link_name, sizeof link_name, "%s.link", file_name) > 0,
          "link path");
    CHECK(snprintf(fifo_name, sizeof fifo_name, "%s.fifo", file_name) > 0,
          "fifo path");
    CHECK(snprintf(node_name, sizeof node_name, "%s.node", file_name) > 0,
          "node path");
    CHECK(snprintf(remove_dir_name, sizeof remove_dir_name, "%s.remove-dir", file_name) > 0,
          "remove directory path");

    CHECK(faccessat(AT_FDCWD, file_name, F_OK, 0) == 0, "faccessat");
    CHECK(eaccess(file_name, F_OK) == 0 && euidaccess(file_name, F_OK) == 0,
          "effective access");
    errno = 0;
    CHECK(faccessat(AT_FDCWD, "/tmp/crabc-c-abi-paths-missing", F_OK, 0) == -1 &&
              errno == ENOENT,
          "faccessat errno");
    errno = 0;
    CHECK(eaccess("/tmp/crabc-c-abi-paths-missing", F_OK) == -1 && errno == ENOENT,
          "effective access errno");

    CHECK(mkdir(dir_name, 0700) == 0, "mkdir");
    CHECK(mkdir(remove_dir_name, 0700) == 0, "mkdir remove directory");
    CHECK(remove(remove_dir_name) == 0, "remove empty directory");
    // O_DIRECTORY is not needed after mkdir: a read-only directory fd is
    // sufficient for fchdir and avoids depending on the incomplete header's
    // architecture-specific flag value.
    dir = open(dir_name, O_RDONLY, 0);
    CHECK(dir >= 0, "open directory");
    CHECK(getcwd(cwd_before, sizeof cwd_before) != NULL, "getcwd before");
    CHECK(fchdir(dir) == 0, "fchdir");
    CHECK(getcwd(cwd_after, sizeof cwd_after) != NULL &&
              strcmp(cwd_after, dir_name) == 0,
          "fchdir destination");
    CHECK(chdir(cwd_before) == 0, "restore cwd");

    CHECK(symlink(file_name, link_name) == 0, "symlink");
    errno = 0;
    CHECK(open(link_name, O_RDONLY | O_NOFOLLOW) == -1 && errno == ELOOP,
          "open nofollow");
    CHECK(faccessat(AT_FDCWD, link_name, F_OK, AT_SYMLINK_NOFOLLOW) == 0,
          "faccessat2 flags");
    errno = 0;
    CHECK(lchmod(link_name, 0777) == -1 && errno == ENOTSUP,
          "lchmod unsupported");

    CHECK(mkfifoat(dir, fifo_at_name, 0600) == 0, "mkfifoat");
    CHECK(mknodat(dir, node_at_name, S_IFIFO | 0600, 0) == 0, "mknodat");
    CHECK(mkfifo(fifo_name, 0600) == 0, "mkfifo");
    CHECK(mknod(node_name, S_IFIFO | 0600, 0) == 0, "mknod");
    CHECK(faccessat(AT_FDCWD, fifo_name, F_OK, 0) == 0 &&
              faccessat(AT_FDCWD, node_name, F_OK, 0) == 0,
          "fifo paths");

    CHECK(flock(file, LOCK_EX | LOCK_NB) == 0, "flock lock");
    CHECK(flock(file, LOCK_UN) == 0, "flock unlock");
    CHECK(lockf(file, F_TLOCK, 1) == 0, "lockf lock");
    CHECK(lockf(file, F_ULOCK, 1) == 0, "lockf unlock");

    CHECK(utimes(file_name, times) == 0, "utimes");
    CHECK(futimes(file, NULL) == 0, "futimes");
    CHECK(futimesat(AT_FDCWD, file_name, NULL) == 0, "futimesat");

    result = 0;
    puts("c-abi filesystem paths ok");

cleanup:
    if (dir >= 0) {
        unlinkat(dir, fifo_at_name, 0);
        unlinkat(dir, node_at_name, 0);
        close(dir);
    }
    if (file >= 0)
        close(file);
    unlink(file_name);
    if (link_name[0]) unlink(link_name);
    if (fifo_name[0]) unlink(fifo_name);
    if (node_name[0]) unlink(node_name);
    if (remove_dir_name[0]) rmdir(remove_dir_name);
    if (dir_name[0]) rmdir(dir_name);
    return result;
}
