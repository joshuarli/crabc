#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int count_alias_mappings(const char *maps)
{
    static const char *const aliases[] = {
        "libpthread.so", "libm.so", "librt.so", "libcrypt.so",
        "libdl.so", "libresolv.so", "libutil.so",
    };
    int count = 0;

    for (size_t i = 0; i < sizeof aliases / sizeof aliases[0]; i++) {
        const char *cursor = maps;
        while ((cursor = strstr(cursor, aliases[i])) != 0) {
            count++;
            cursor += strlen(aliases[i]);
        }
    }
    return count;
}

int main(void)
{
    char maps[65537];
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0)
        return 1;
    ssize_t n = read(fd, maps, sizeof maps - 1);
    close(fd);
    if (n < 0)
        return 2;
    maps[n] = '\0';

    /* Each loaded object has two file-backed mappings.  The executable is
     * linked against seven distinct DT_NEEDED aliases of libc.so, so more
     * than three alias-named mappings proves at least one duplicate load. */
    return count_alias_mappings(maps) > 3;
}
