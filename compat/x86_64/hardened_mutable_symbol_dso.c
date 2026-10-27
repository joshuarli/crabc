#include <fcntl.h>
#include <unistd.h>

pid_t (*mutable_function)(void) = getpid;

__attribute__((constructor)) static void initialize(void)
{
    int fd = open("/symbol-mutable-marker", O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}

int symbol_mutate(void)
{
    if (!mutable_function || mutable_function() <= 0) return 0;
    mutable_function = 0;
    return mutable_function == 0;
}
