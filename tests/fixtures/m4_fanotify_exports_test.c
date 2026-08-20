#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/fanotify.h>
#include <unistd.h>

int main(void)
{
    int fd;

    errno = 0;
    if (fanotify_mark(-1, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, "/") != -1 ||
        errno != EBADF)
        return 1;

    errno = 0;
    fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY);
    if (fd >= 0) {
        if (close(fd) != 0)
            return 2;
    } else if (errno != EPERM && errno != ENOSYS && errno != EINVAL) {
        return 3;
    }
    puts("m4 fanotify exports ok");
    return 0;
}
