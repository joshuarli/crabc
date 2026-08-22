#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * `dlopen` receives an explicit pathname here, rather than the special NULL
 * main-program handle.  Linux has already mapped the executable for PT_INTERP
 * entry, but musl treats this request as a separate dlopen object.
 */
int main(void)
{
    char executable[4096];
    ssize_t executable_length = readlink("/proc/self/exe", executable,
        sizeof(executable) - 1);
    if (executable_length <= 0)
        return 1;
    executable[executable_length] = '\0';

    void *handle = dlopen(executable, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return 2;

    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL)
        return 3;

    char line[8192];
    int executable_mappings = 0;
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, " r-xp ") != NULL
            && strstr(line, executable) != NULL)
            executable_mappings++;
    }
    if (fclose(maps) != 0)
        return 4;
    if (executable_mappings != 2)
        return 5;
    if (dlclose(handle) != 0)
        return 6;

    puts("main-self-dlopen=ok");
    return 0;
}
