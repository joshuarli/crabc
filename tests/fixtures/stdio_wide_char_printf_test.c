#include "stdio.h"
#include "wchar.h"

int main(void) {
    static const wchar_t path[] = L"/etc/alpine-release";
    char padded[8];
    int padded_len = snprintf(padded, sizeof padded, "%5lc", path[0]);
    if (padded_len != 5 || padded[0] != ' ' || padded[1] != ' ' ||
        padded[2] != ' ' || padded[3] != ' ' || padded[4] != '/') {
        return 1;
    }
    for (size_t i = 0; path[i] != L'\0'; i++) {
        printf("%lc", path[i]);
    }
    printf(": ASCII text\n");
    return 0;
}
