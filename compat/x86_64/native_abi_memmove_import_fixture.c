#define _GNU_SOURCE 1
#include <stdlib.h>
#include <string.h>
#include <strings.h>

volatile unsigned char crabc_memmove_observed_byte;
volatile char *crabc_memmove_observed_path;

int main(int argc, char **argv) {
    char bytes[32] = "overlapping bytes";
    char path[4096];
    memmove(bytes + 1, bytes, argc > 1 ? 8 : 9);
    bcopy(bytes + 1, bytes, 7);
    crabc_memmove_observed_byte = (unsigned char)bytes[0];
    crabc_memmove_observed_path = realpath(argc > 1 ? argv[1] : ".", path);
    return crabc_memmove_observed_path == 0;
}
