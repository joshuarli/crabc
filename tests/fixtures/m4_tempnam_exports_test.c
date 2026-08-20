#define _GNU_SOURCE 1

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *name = tempnam("/tmp", "crabc-prefix");

    if (!name || strncmp(name, "/tmp/crabc", 10) != 0)
        return 1;
    errno = 0;
    if (access(name, F_OK) != -1 || errno != ENOENT)
        return 2;
    free(name);
    puts("m4 tempnam exports ok");
    return 0;
}
