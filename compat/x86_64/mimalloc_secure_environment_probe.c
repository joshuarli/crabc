#include <stdlib.h>

int main(void) {
    void *volatile p = malloc(123);
    if (!p) return 1;
    free(p);
    return 0;
}
