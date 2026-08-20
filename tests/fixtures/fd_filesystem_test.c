#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char path[] = "/tmp/crabc-foundation-fd-test";

static int fail(const char *name)
{
    puts(name);
    unlink(path);
    return 1;
}

int main(void)
{
    char bytes[7] = { 0 };
    struct stat st;
    int fd;

    unlink(path);
    fd = openat(AT_FDCWD, path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0)
        return fail("openat");
    if (write(fd, "abc", 3) != 3 || pwrite(fd, "XYZ", 3, 3) != 3)
        return fail("write");
    if (pread(fd, bytes, 6, 0) != 6 || memcmp(bytes, "abcXYZ", 6) != 0)
        return fail("pread");
    if (fstat(fd, &st) != 0 || st.st_size != 6)
        return fail("fstat");
    if (close(fd) != 0)
        return fail("close");
    if (fstatat(AT_FDCWD, path, &st, 0) != 0 || st.st_size != 6)
        return fail("fstatat");
    if (lstat(path, &st) != 0 || st.st_size != 6)
        return fail("lstat");
    if (unlink(path) != 0)
        return fail("unlink");
    errno = 0;
    if (openat(AT_FDCWD, path, O_RDONLY) != -1 || errno != ENOENT)
        return fail("openat-error");

    puts("fd filesystem ok");
    return 0;
}
