#include <stdio.h>
#include <wchar.h>

int main(void)
{
    wchar_t value = 0;
    return fwscanf(stdin, L"%lc", &value) < 0;
}
