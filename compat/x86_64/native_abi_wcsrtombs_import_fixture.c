#include <stdlib.h>
#include <wchar.h>

int main(void)
{
    char buffer[8];
    const wchar_t *source = L"A";
    mbstate_t state = {0};
    if (wcstombs(buffer, source, sizeof buffer) != 1)
        return 7;
    if (wcsrtombs(buffer, &source, sizeof buffer, &state) != 1)
        return 8;
    return buffer[0] != 'A';
}
