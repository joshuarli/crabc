#include <stdio.h>
#include <wchar.h>

int main(void)
{
    return wprintf(L"%lc", L'A') < 0;
}
