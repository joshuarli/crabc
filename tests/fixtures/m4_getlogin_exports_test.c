#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    const char *prior = getenv("LOGNAME");
    char saved[128];
    char result[32];
    char short_result[4];
    int had_prior = prior != NULL;

    if (had_prior) {
        if (strlen(prior) >= sizeof saved)
            return 1;
        strcpy(saved, prior);
    }
    if (setenv("LOGNAME", "crabc-login", 1) != 0)
        return 2;
    if (!getlogin() || strcmp(getlogin(), "crabc-login") ||
        getlogin_r(result, sizeof result) != 0 || strcmp(result, "crabc-login"))
        return 3;
    if (getlogin_r(short_result, sizeof short_result) != ERANGE)
        return 4;
    if (unsetenv("LOGNAME") != 0 || getlogin() != NULL ||
        getlogin_r(result, sizeof result) != ENXIO)
        return 5;
    if (had_prior) {
        if (setenv("LOGNAME", saved, 1) != 0)
            return 6;
    }

    puts("m4 getlogin exports ok");
    return 0;
}
