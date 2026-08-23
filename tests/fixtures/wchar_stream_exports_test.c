#include <stdio.h>
#include <string.h>
#include <wchar.h>

int main(void)
{
    const char *input = "A\303\251" "B";
    const char *incomplete = "\342";
    const char *incomplete_begin = incomplete;
    const char *cursor = input;
    wchar_t wide[4];
    const wchar_t *wide_cursor;
    char bytes[8] = { 0 };
    wchar_t tokens[] = L",first::second";
    wchar_t *save = NULL;
    wchar_t *token;
    mbstate_t state = { 0 };

    if (mbsnrtowcs(wide, &cursor, strlen(input), 4, &state) != 3 ||
        cursor != input + strlen(input) || wide[0] != L'A' || wide[1] != 0xe9 ||
        wide[2] != L'B')
        return 1;
    wide_cursor = wide;
    state = (mbstate_t){ 0 };
    if (wcsnrtombs(bytes, &wide_cursor, 3, sizeof bytes, &state) != strlen(input) ||
        wide_cursor != wide + 3 || memcmp(bytes, input, strlen(input)))
        return 2;
    cursor = input;
    state = (mbstate_t){ 0 };
    if (mbsnrtowcs(wide, &cursor, strlen(input), 1, &state) != 1 ||
        cursor != input + 1 || wide[0] != L'A')
        return 3;
    state = (mbstate_t){ 0 };
    if (mbsnrtowcs(wide, &incomplete, 1, 4, &state) != 0 ||
        incomplete != incomplete_begin)
        return 4;
    token = wcstok(tokens, L":,", &save);
    if (!token || wcscmp(token, L"first"))
        return 5;
    token = wcstok(NULL, L":,", &save);
    if (!token || wcscmp(token, L"second") || wcstok(NULL, L":,", &save) != NULL)
        return 6;
    puts("c-abi wchar stream exports ok");
    return 0;
}
