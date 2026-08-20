#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char first_copy[4096];
    char *first = getusershell();
    char *rewound;
    char *reopened;

    if (!first || first[0] != '/')
        return 1;
    strcpy(first_copy, first);
    setusershell();
    rewound = getusershell();
    if (!rewound || strcmp(rewound, first_copy) != 0)
        return 2;
    endusershell();
    reopened = getusershell();
    if (!reopened || strcmp(reopened, first_copy) != 0)
        return 3;
    endusershell();
    puts("m4 usershell exports ok");
    return 0;
}
