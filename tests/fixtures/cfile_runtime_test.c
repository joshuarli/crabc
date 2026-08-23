#include <stdio.h>

extern int crabc_rs_cfile_direct_probe(unsigned char *, size_t);

int main(void)
{
    unsigned char buffer[64] = {0};
    int result = crabc_rs_cfile_direct_probe(buffer, sizeof buffer);
    if (result != 0) {
        printf("compat cfile runtime FAIL %d\n", result);
        return 1;
    }
    puts("compat cfile runtime ok");
    return 0;
}
