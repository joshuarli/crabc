static int initialized;

#ifdef CRABC_BAD_DSO
#include <fcntl.h>
#include <unistd.h>
unsigned char hardened_bad_storage[32] = {1};
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
