#define _GNU_SOURCE 1
#include <string.h>
#include <strings.h>

volatile int crabc_memcmp_observed_order;
volatile int crabc_bcmp_observed_difference;

int main(int argc, char **argv) {
    const char *left = argc > 1 ? argv[1] : "left";
    const char *right = argc > 2 ? argv[2] : "right";
    crabc_memcmp_observed_order = memcmp(left, right, 1);
    crabc_bcmp_observed_difference = bcmp(left, right, 1);
    return 0;
}
