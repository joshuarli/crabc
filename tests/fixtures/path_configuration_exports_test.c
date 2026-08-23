#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
    size_t path_len;
    long name_limit;
    long block_size;
    long current_blocks;
    int file;

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

    errno = 0;
    name_limit = pathconf("/tmp", _PC_NAME_MAX);
    CHECK(name_limit > 0 && name_limit <= NAME_MAX, "pathconf name limit");
    block_size = pathconf("/tmp", _PC_REC_INCR_XFER_SIZE);
    CHECK(block_size > 0, "pathconf filesystem block size");
    file = open("/tmp", O_RDONLY, 0);
    CHECK(file >= 0, "open pathconf directory");
    CHECK(fpathconf(file, _PC_NAME_MAX) == name_limit, "fpathconf name limit");
    CHECK(fpathconf(file, _PC_REC_INCR_XFER_SIZE) == block_size,
          "fpathconf filesystem block size");
    close(file);

    errno = 0;
    CHECK(pathconf("/tmp/crabc-c-abi-pathconf-missing", _PC_NAME_MAX) == -1 &&
              errno == ENOENT,
          "pathconf missing path errno");
    errno = 0;
    CHECK(fpathconf(-1, _PC_NAME_MAX) == -1 && errno == EBADF,
          "fpathconf invalid descriptor errno");
    errno = 0;
    CHECK(pathconf("/tmp", -1) == -1 && errno == EINVAL,
          "pathconf invalid selector errno");
    errno = 123;
    CHECK(pathconf("/tmp", _PC_ASYNC_IO) == -1 && errno == 123,
          "pathconf indeterminate errno");

    CHECK(getrlimit(RLIMIT_FSIZE, &limit) == 0, "getrlimit file size");
    current_blocks = (long)(limit.rlim_cur / 512);
    CHECK(ulimit(UL_GETFSIZE) == current_blocks, "ulimit query");
    CHECK(ulimit(999) == current_blocks, "ulimit unknown command");

    puts("c-abi path configuration exports ok");
    return 0;
}
