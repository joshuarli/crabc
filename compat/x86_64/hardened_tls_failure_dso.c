#include <fcntl.h>
#include <unistd.h>

_Thread_local int hardened_fault_tls = 41;

__attribute__((constructor)) static void initialize(void)
{
    if (hardened_fault_tls != 41) _exit(2);
    int fd = open("/tls-rejected-marker", O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}
