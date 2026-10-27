#include <dlfcn.h>
#include <unistd.h>

int main(void)
{
    void *handle = dlopen("/usr/lib/import-probe.so", RTLD_LAZY);
    return !handle || access("/import-marker", F_OK) != 0 || dlclose(handle) != 0;
}
