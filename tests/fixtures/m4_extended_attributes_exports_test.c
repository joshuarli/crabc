#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/xattr.h>

extern int close(int);
extern int unlink(const char *);

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "xattr: %s (errno=%d)\n", message, errno); \
            return 1; \
        } \
    } while (0)

/* A container may use a filesystem without user xattr support.  Report that
 * kernel result explicitly; callers must not mistake it for a passing probe. */
static int xattr_unavailable(void)
{
    return errno == EOPNOTSUPP || errno == ENOSYS;
}

static int has_name(const char *list, ssize_t length, const char *wanted)
{
    size_t wanted_length = strlen(wanted);
    ssize_t offset = 0;

    while (offset < length) {
        size_t current_length = strlen(list + offset);
        if (current_length == wanted_length &&
            !memcmp(list + offset, wanted, wanted_length))
            return 1;
        offset += (ssize_t)current_length + 1;
    }
    return 0;
}

int main(void)
{
    static const char path[] = "/tmp/crabc-m4-xattr-test";
    static const char path_name[] = "user.crabc_m4_path";
    static const char link_name[] = "user.crabc_m4_link";
    static const char fd_name[] = "user.crabc_m4_fd";
    static const char path_value[] = "path-value";
    static const char link_value[] = "link-value";
    static const char fd_value[] = "fd-value";
    char value[32];
    char names[256];
    ssize_t length;
    int fd;

    unlink(path);
    fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(fd >= 0, "open writable /tmp regular file");

    errno = 0;
    if (setxattr(path, path_name, path_value, sizeof(path_value) - 1,
                 XATTR_CREATE) < 0) {
        if (xattr_unavailable()) {
            printf("m4 xattr unavailable errno=%d\n", errno);
            close(fd);
            unlink(path);
            return 77;
        }
        CHECK(0, "setxattr");
    }
    CHECK(lsetxattr(path, link_name, link_value, sizeof(link_value) - 1,
                    XATTR_CREATE) == 0,
          "lsetxattr");
    CHECK(fsetxattr(fd, fd_name, fd_value, sizeof(fd_value) - 1,
                    XATTR_CREATE) == 0,
          "fsetxattr");

    memset(value, 0, sizeof(value));
    CHECK(getxattr(path, path_name, NULL, 0) == (ssize_t)(sizeof(path_value) - 1),
          "getxattr size query");
    CHECK(getxattr(path, path_name, value, sizeof(value)) ==
              (ssize_t)(sizeof(path_value) - 1) &&
              !memcmp(value, path_value, sizeof(path_value) - 1),
          "getxattr value");

    memset(value, 0, sizeof(value));
    CHECK(lgetxattr(path, link_name, value, sizeof(value)) ==
              (ssize_t)(sizeof(link_value) - 1) &&
              !memcmp(value, link_value, sizeof(link_value) - 1),
          "lgetxattr value");

    memset(value, 0, sizeof(value));
    CHECK(fgetxattr(fd, fd_name, value, sizeof(value)) ==
              (ssize_t)(sizeof(fd_value) - 1) &&
              !memcmp(value, fd_value, sizeof(fd_value) - 1),
          "fgetxattr value");

    length = listxattr(path, NULL, 0);
    CHECK(length >= 0 && length <= (ssize_t)sizeof(names),
          "listxattr size query");
    CHECK(listxattr(path, names, sizeof(names)) == length &&
              has_name(names, length, path_name) &&
              has_name(names, length, link_name) &&
              has_name(names, length, fd_name),
          "listxattr names");

    length = llistxattr(path, names, sizeof(names));
    CHECK(length >= 0 && has_name(names, length, path_name) &&
              has_name(names, length, link_name) &&
              has_name(names, length, fd_name),
          "llistxattr names");
    length = flistxattr(fd, names, sizeof(names));
    CHECK(length >= 0 && has_name(names, length, path_name) &&
              has_name(names, length, link_name) &&
              has_name(names, length, fd_name),
          "flistxattr names");

    CHECK(removexattr(path, path_name) == 0, "removexattr");
    CHECK(lremovexattr(path, link_name) == 0, "lremovexattr");
    CHECK(fremovexattr(fd, fd_name) == 0, "fremovexattr");

    errno = 0;
    CHECK(getxattr(path, path_name, value, sizeof(value)) == -1 &&
              errno == ENODATA,
          "removed xattr errno");
    CHECK(listxattr(path, names, sizeof(names)) == 0, "empty listxattr");

    CHECK(close(fd) == 0, "close");
    CHECK(unlink(path) == 0, "unlink");
    puts("m4 extended attributes exports ok");
    return 0;
}
