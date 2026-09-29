#include <stdio.h>
#include <wchar.h>

int main(void)
{
    if (btowc('A') != L'A')
        return 7;
    return wprintf(L"%lc", L'A') < 0;
}
