#include <fcntl.h>
#include <unistd.h>

_Thread_local int hardened_fault_tls = 41;
/* A generation view is sized from the module image. Make this one larger than
 * a loader pool chunk and smaller than the image's whole map span, so the
 * probe can fail exactly the TLS generation allocation. */
_Thread_local unsigned char hardened_fault_padding[16512];

__attribute__((constructor)) static void initialize(void)
{
    if (hardened_fault_tls != 41) _exit(2);
    int fd = open("/tls-rejected-marker", O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}
