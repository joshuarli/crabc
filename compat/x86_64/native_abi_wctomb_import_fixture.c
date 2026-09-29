#include <stdio.h>
#include <wchar.h>

int main(void)
{
    char buffer[8];
    wchar_t value = 0;
    if (wctomb(buffer, L'A') != 1)
        return 7;
    return fwscanf(stdin, L"%lc", &value) < 0;
}
