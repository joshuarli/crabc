static int initialized;

#ifdef CRABC_BAD_DSO
#include <fcntl.h>
#include <unistd.h>
#endif

__attribute__((constructor)) static void initialize(void)
{
#ifdef CRABC_BAD_DSO
    int fd = open("/rejected-marker", O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
#endif
    initialized = 7;
}

int hardened_fixture_initialized(void)
{
    return initialized;
}
