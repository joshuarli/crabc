#include "stdio.h"
#include "math.h"
#include "sys/types.h"

int main(void) {
    printf("inf='%09f' INF='%09F'\n", INFINITY, INFINITY);
    printf("pos='%3$c%1$c%4$c%4$c%2$c'\n", 'e', 'o', 'h', 'l');
    printf("long='%2$0*1$.*3$Lf'\n", 9, 1234.56789L, 3);
    printf("short='%hd' char='%hhd'\n", 123456, 737);
    printf("g='%*g'\n", -5, 15.1);
    printf("hex='%.4a'\n", 1.4208);
    printf("size='%zd' unsigned='%zu'\n", (ssize_t)-7, (size_t)9);
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%3$c%1$c%4$c%4$c%2$c", 'e', 'o', 'h', 'l');
    printf("buffer='%s'\n", buffer);
    return 0;
}
