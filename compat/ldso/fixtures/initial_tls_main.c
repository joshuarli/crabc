#include <stdio.h>

extern int initial_tls_get(void);

int main(void)
{
    int first = initial_tls_get();
    int second = initial_tls_get();
    printf("initial-tls=%d,%d\n", first, second);
    return 0;
}
