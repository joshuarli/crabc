#include <sys/auxv.h>
#include <stdio.h>

int main(void) {
    printf("%s\n", (const char *)getauxval(AT_EXECFN));
    return 0;
}
