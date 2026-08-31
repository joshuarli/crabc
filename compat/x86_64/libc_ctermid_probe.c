/* Static x86-64 ctermid C ABI and behavior fixture.
 *
 * The selected historical leaf either copies the fixed `/dev/tty` spelling
 * into a caller-owned L_ctermid buffer or returns its immutable static
 * spelling. It does not open that pathname or inspect terminal state.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdio.h>

_Static_assert(L_ctermid == 20, "musl L_ctermid value");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ctermid),
    char *(*)(char *)), "ctermid declaration");

static const char expected_ctermid[] = "/dev/tty";

static int check_spelling(const char *value)
{
    unsigned index;

    for (index = 0; index < sizeof(expected_ctermid); ++index) {
        if (value[index] != expected_ctermid[index])
            return 1;
    }
    return 0;
}

int crabc_x86_64_ctermid_probe(void)
{
    char buffer[L_ctermid];
    char *result;
    unsigned index;

    result = ctermid((char *)0);
    if (result == (char *)0)
        return 1;
    if (check_spelling(result) != 0)
        return 2;

    for (index = 0; index < sizeof(buffer); ++index)
        buffer[index] = (char)0x5a;
    result = ctermid(buffer);
    if (result != buffer)
        return 3;
    if (check_spelling(buffer) != 0)
        return 4;
    for (index = sizeof(expected_ctermid); index < sizeof(buffer); ++index) {
        if ((unsigned char)buffer[index] != 0x5aU)
            return 5;
    }

    return 0;
}

#ifndef CRABC_CTERMID_FREESTANDING
int main(void)
{
    return crabc_x86_64_ctermid_probe();
}
#endif
