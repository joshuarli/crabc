#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * The kernel maps the main PIE before entering its PT_INTERP loader.  A
 * loader must relocate that image in place, rather than leaving a second
 * executable mapping of the same file behind.
 */
int main(void)
{
    char executable[4096];
    ssize_t executable_length = readlink("/proc/self/exe", executable,
        sizeof(executable) - 1);
    if (executable_length <= 0)
        return 1;
    executable[executable_length] = '\0';

    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL)
        return 2;

    char line[8192];
    int executable_mappings = 0;
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, " r-xp ") != NULL
            && strstr(line, executable) != NULL)
            executable_mappings++;
    }
    if (fclose(maps) != 0)
        return 3;
    if (executable_mappings != 1)
        return 4;

    puts("kernel-main-image=ok");
    return 0;
}
