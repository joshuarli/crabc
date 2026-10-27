#include <fcntl.h>
#include <unistd.h>

extern int hardened_supplied(void);

__attribute__((constructor)) static void initialize(void)
{
    int fd = open("/import-marker", O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}

int hardened_import_value(void)
{
    return hardened_supplied();
}
