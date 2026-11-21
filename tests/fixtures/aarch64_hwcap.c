#include <sys/auxv.h>
#include <stdio.h>

int main(void) {
    printf("%lx %lx\n", getauxval(AT_HWCAP), getauxval(AT_HWCAP2));
    return 0;
}
