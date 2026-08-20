#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct handle_buffer {
    struct file_handle handle;
    unsigned char bytes[MAX_HANDLE_SZ];
};

int main(void)
{
    char path[] = "/tmp/crabc-m4-file-handle-XXXXXX";
    struct handle_buffer storage;
    int mount_id = 0;
    int fd;
    int result;

    fd = mkstemp(path);
    if (fd < 0)
        return 1;
    close(fd);
    memset(&storage, 0, sizeof storage);
    storage.handle.handle_bytes = MAX_HANDLE_SZ;
    errno = 0;
    result = name_to_handle_at(AT_FDCWD, path, &storage.handle, &mount_id, 0);
    if (result == 0) {
        /* Opening a raw handle needs CAP_DAC_READ_SEARCH.  A success is still
         * valid in an unusually privileged runner; close its returned fd. */
        result = open_by_handle_at(-1, &storage.handle, O_RDONLY);
        if (result >= 0)
            close(result);
        else if (errno != EPERM && errno != EBADF && errno != EACCES)
            goto fail;
    } else if (errno != EOPNOTSUPP && errno != ENOSYS && errno != EPERM &&
        errno != EOVERFLOW) {
        goto fail;
    }

    errno = 0;
    if (name_to_handle_at(AT_FDCWD, path, NULL, NULL, 0) != -1 ||
        (errno != EFAULT && errno != EOPNOTSUPP && errno != EPERM))
        goto fail;
    errno = 0;
    if (open_by_handle_at(-1, NULL, O_RDONLY) != -1 ||
        (errno != EFAULT && errno != EBADF && errno != EPERM))
        goto fail;
    unlink(path);
    puts("m4 file handle exports ok");
    return 0;

fail:
    unlink(path);
    return 2;
}
