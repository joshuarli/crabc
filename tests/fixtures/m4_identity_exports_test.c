#define _GNU_SOURCE
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    struct passwd *entry = getpwuid(geteuid());
    char supplied[L_cuserid];
    char *internal;

    if (!entry || !entry->pw_name || strlen(entry->pw_name) >= L_cuserid)
        return 1;
    memset(supplied, 'x', sizeof supplied);
    if (cuserid(supplied) != supplied || strcmp(supplied, entry->pw_name))
        return 2;
    internal = cuserid(NULL);
    if (!internal || strcmp(internal, entry->pw_name))
        return 3;

    puts("m4 identity exports ok");
    return 0;
}
