/* Static x86-64 ctype ABI and behavior fixture. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <ctype.h>

typedef int (*ctype_fn)(int);

static int expected_class(unsigned kind, int c)
{
    int ascii = c >= 0 && c <= 127;
    int letter = ascii && ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
    int digit = ascii && c >= '0' && c <= '9';
    int space = ascii && ((c >= '\t' && c <= '\r') || c == ' ');
    int punct = ascii && c >= '!' && c <= '~' && !letter && !digit;

    switch (kind) {
    case 0: return letter || digit;
    case 1: return letter;
    case 2: return ascii && (c == ' ' || c == '\t');
    case 3: return ascii && (c <= 31 || c == 127);
    case 4: return digit;
    case 5: return ascii && c >= 33 && c <= 126;
    case 6: return ascii && c >= 'a' && c <= 'z';
    case 7: return ascii && c >= 32 && c <= 126;
    case 8: return punct;
    case 9: return space;
    case 10: return ascii && c >= 'A' && c <= 'Z';
    case 11: return digit || (ascii && ((c >= 'A' && c <= 'F') ||
        (c >= 'a' && c <= 'f')));
    case 12: return ascii;
    default: return 0;
    }
}

static int check_classification(void)
{
    static const ctype_fn functions[] = {
        isalnum, isalpha, isblank, iscntrl, isdigit, isgraph,
        islower, isprint, ispunct, isspace, isupper, isxdigit, isascii
    };
    int value;
    unsigned kind;

    for (kind = 0; kind < sizeof(functions) / sizeof(functions[0]); ++kind) {
        for (value = -1; value <= 255; ++value) {
            int actual = functions[kind](value) != 0;
            if (actual != expected_class(kind, value))
                return 1 + (int)kind;
        }
    }
    return 0;
}

static int check_conversion(void)
{
    static const ctype_fn lower = tolower;
    static const ctype_fn upper = toupper;
    int value;

    for (value = -1; value <= 255; ++value) {
        int expected_lower = value >= 'A' && value <= 'Z' ? value + 32 : value;
        int expected_upper = value >= 'a' && value <= 'z' ? value - 32 : value;
        if (lower(value) != expected_lower || upper(value) != expected_upper)
            return 1;
        if (toascii(value) != (value & 0x7f))
            return 2;
    }
    return 0;
}

int crabc_x86_64_ctype_probe(void)
{
    int status = check_classification();
    if (status != 0)
        return 10 + status;
    status = check_conversion();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_CTYPE_FREESTANDING
int main(void)
{
    return crabc_x86_64_ctype_probe();
}
#endif
