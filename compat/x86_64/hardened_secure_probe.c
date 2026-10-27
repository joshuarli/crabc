#include <sys/auxv.h>
#include <unistd.h>

int main(void)
{
    return getauxval(AT_SECURE) == 1 && getuid() == 65534 && geteuid() == 0 ? 0 : 1;
}
