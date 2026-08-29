#define _GNU_SOURCE 1

#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <ulimit.h>
#include <unistd.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    char path_value[32];
    char truncated[4];
    struct rlimit limit;
    static const struct {
        int selector;
        long value;
    } expected_pathconf_values[] = {
        { _PC_LINK_MAX, 8 },
        { _PC_MAX_CANON, 255 },
        { _PC_MAX_INPUT, 255 },
        { _PC_NAME_MAX, 255 },
        { _PC_PATH_MAX, 4096 },
        { _PC_PIPE_BUF, 4096 },
        { _PC_CHOWN_RESTRICTED, 1 },
        { _PC_NO_TRUNC, 1 },
        { _PC_VDISABLE, 0 },
        { _PC_SYNC_IO, 1 },
        { _PC_ASYNC_IO, -1 },
        { _PC_PRIO_IO, -1 },
        { _PC_SOCK_MAXBUF, -1 },
        { _PC_FILESIZEBITS, 64 },
        { _PC_REC_INCR_XFER_SIZE, 4096 },
        { _PC_REC_MAX_XFER_SIZE, 4096 },
        { _PC_REC_MIN_XFER_SIZE, 4096 },
        { _PC_REC_XFER_ALIGN, 4096 },
        { _PC_ALLOC_SIZE_MIN, 4096 },
        { _PC_SYMLINK_MAX, -1 },
        { _PC_2_SYMLINKS, 1 },
    };
    size_t path_len;
    long current_blocks;
    size_t index;

    path_len = confstr(_CS_PATH, NULL, 0);
    CHECK(path_len == sizeof "/bin:/usr/bin", "confstr query");
    CHECK(confstr(_CS_PATH, path_value, sizeof path_value) == path_len,
          "confstr copy length");
    CHECK(path_value[0] == '/' && path_value[4] == ':' &&
              path_value[path_len - 1] == '\0',
          "confstr copy value");
    CHECK(confstr(_CS_PATH, truncated, sizeof truncated) == path_len &&
              truncated[sizeof truncated - 1] == '\0',
          "confstr truncation");
    errno = 0;
    CHECK(confstr(123456, path_value, sizeof path_value) == 0 &&
              errno == EINVAL,
          "confstr invalid selector");

    for (index = 0; index < sizeof expected_pathconf_values /
            sizeof expected_pathconf_values[0]; ++index) {
        errno = E2BIG;
        CHECK(pathconf(NULL, expected_pathconf_values[index].selector) ==
                  expected_pathconf_values[index].value &&
                  errno == E2BIG,
              "pathconf musl table");
        errno = E2BIG;
        CHECK(fpathconf(-1, expected_pathconf_values[index].selector) ==
                  expected_pathconf_values[index].value &&
                  errno == E2BIG,
              "fpathconf musl table");
    }

    errno = 0;
    CHECK(pathconf(NULL, -1) == -1 && errno == EINVAL,
          "pathconf invalid selector errno");
    errno = 0;
    CHECK(fpathconf(-1, _PC_2_SYMLINKS + 1) == -1 && errno == EINVAL,
          "fpathconf invalid selector errno");

    CHECK(getrlimit(RLIMIT_FSIZE, &limit) == 0, "getrlimit file size");
    current_blocks = (long)(limit.rlim_cur / 512);
    CHECK(ulimit(UL_GETFSIZE) == current_blocks, "ulimit query");
    CHECK(ulimit(999) == current_blocks, "ulimit unknown command");

    puts("c-abi path configuration exports ok");
    return 0;
}
