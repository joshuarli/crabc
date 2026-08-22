/* C header-only probe used by the Lua adapter-sysroot harness. */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int crabc_lua_header_probe(void)
{
    struct stat status;
    unsigned char bytes[sizeof(uint64_t)];

    memset(bytes, 0, sizeof(bytes));
    status.st_size = (off_t)sizeof(bytes);
    return (int)(status.st_size + O_CLOEXEC + O_DIRECTORY + errno + bytes[0]);
}
