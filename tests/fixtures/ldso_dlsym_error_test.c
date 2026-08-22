#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    const char *name = "crabc_lua_missing_symbol";
    const char *error;

    if (dlsym(0, name) != 0)
        return 1;
    error = dlerror();
    if (error == 0 || strstr(error, name) == 0)
        return 2;
    if (dlerror() != 0)
        return 3;
    write(1, "dlsym error name ok\n", 20);
    return 0;
}
