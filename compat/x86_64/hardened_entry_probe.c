#include <fcntl.h>
#include <unistd.h>

__attribute__((constructor)) static void mark_constructor(void)
{
    int fd = open("/marker", O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}

int main(void)
{
    return 0;
}
