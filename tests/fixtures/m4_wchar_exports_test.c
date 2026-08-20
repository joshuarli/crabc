#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

extern wchar_t *wmemchr(const wchar_t *, wchar_t, size_t);
extern int wmemcmp(const wchar_t *, const wchar_t *, size_t);
extern wchar_t *wmemcpy(wchar_t *, const wchar_t *, size_t);
extern wchar_t *wmemmove(wchar_t *, const wchar_t *, size_t);
extern wchar_t *wmemset(wchar_t *, wchar_t, size_t);
extern wchar_t *wcpcpy(wchar_t *, const wchar_t *);
extern wchar_t *wcpncpy(wchar_t *, const wchar_t *, size_t);
extern wchar_t *wcswcs(const wchar_t *, const wchar_t *);
extern wint_t fgetwc_unlocked(FILE *);
extern wint_t fputwc_unlocked(wchar_t, FILE *);
extern int fputws_unlocked(const wchar_t *, FILE *);
extern wint_t getwc_unlocked(FILE *);
extern wint_t putwc_unlocked(wchar_t, FILE *);
extern wint_t __fgetwc_unlocked(FILE *);
extern wint_t __fputwc_unlocked(wchar_t, FILE *);

static int call_vwprintf(const wchar_t *format, ...)
{
    va_list args;
    int result;
    va_start(args, format);
    result = vwprintf(format, args);
    va_end(args);
    return result;
}

int main(void) {
    wchar_t source[] = { L'a', L'b', L'c', L'd', 0 };
    wchar_t work[8] = { 0 };
    wchar_t overlap[] = { L'a', L'b', L'c', L'd', 0 };

    if (wmemcpy(work, source, 4) != work) return 1;
    if (wmemcmp(work, source, 4) != 0) return 2;
    if (wmemchr(work, L'c', 4) != work + 2) return 3;
    if (wmemchr(work, L'x', 4) != NULL) return 4;
    if (wmemset(work + 4, L'Z', 2) != work + 4) return 5;
    if (work[4] != L'Z' || work[5] != L'Z') return 6;
    if (wmemmove(overlap + 1, overlap, 4) != overlap + 1) return 7;
    if (overlap[1] != L'a' || overlap[2] != L'b' || overlap[3] != L'c' || overlap[4] != L'd') return 8;

    {
        wchar_t copied[8] = { 0 };
        wchar_t limited[8] = { L'X', L'X', L'X', L'X', L'X', L'X', L'X', 0 };
        if (wcpcpy(copied, source) != copied + 4 || wcscmp(copied, source) != 0) return 9;
        if (wcpncpy(limited, source, 3) != limited + 3) return 10;
        if (limited[0] != L'a' || limited[1] != L'b' || limited[2] != L'c' || limited[3] != L'X') return 11;
        if (wcpncpy(limited, source, 8) != limited + 4 || limited[4] != 0) return 12;
    }

    {
        wchar_t haystack[] = { L'p', L'r', L'e', L'f', L'i', L'x', 0 };
        wchar_t needle[] = { L'f', L'i', L'x', 0 };
        if (wcswcs(haystack, needle) != haystack + 3) return 13;
        if (wcswcs(haystack, L"no") != NULL) return 14;
    }

    if (wcwidth(L'A') != 1 || wcwidth(L'\n') != -1) return 15;
    if (wcwidth((wchar_t)0x0301) != 0 || wcwidth((wchar_t)0x4e00) != 2) return 16;
    {
        wchar_t width[] = { L'A', (wchar_t)0x0301, (wchar_t)0x4e00, 0 };
        if (wcswidth(width, 3) != 3 || wcswidth(width, 2) != 1) return 17;
    }

    {
        FILE *stream = tmpfile();
        if (!stream) return 18;
        if (fputws_unlocked(L"ab", stream) != 0) return 19;
        if (fputwc_unlocked(L'c', stream) != L'c') return 20;
        if (putwc_unlocked(L'd', stream) != L'd') return 21;
        if (__fputwc_unlocked(L'e', stream) != L'e') return 22;
        if (fflush(stream) != 0) return 23;
        rewind(stream);
        if (fgetwc_unlocked(stream) != L'a') return 24;
        if (getwc(stream) != L'b') return 25;
        if (getwc_unlocked(stream) != L'c') return 26;
        if (__fgetwc_unlocked(stream) != L'd') return 27;
        if (fgetwc_unlocked(stream) != L'e') return 28;
        fclose(stream);
    }

    if (wprintf(L"W") != 1 || call_vwprintf(L"%d", 7) != 1) return 29;
    puts("m4 wchar exports ok");
    return 0;
}
