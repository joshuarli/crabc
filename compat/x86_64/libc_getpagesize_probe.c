/* Static Linux/x86-64 getpagesize C ABI and behavior fixture. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*getpagesize_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&getpagesize),
    getpagesize_signature), "getpagesize declaration");

static int check_fixed_x86_page_size(void)
{
    getpagesize_signature indirect = getpagesize;

    if (getpagesize() != 4096)
        return 1;
    if (indirect() != 4096)
        return 2;
    return 0;
}

int crabc_x86_64_getpagesize_probe(void)
{
    return check_fixed_x86_page_size();
}

#ifndef CRABC_GETPAGESIZE_FREESTANDING
int main(void)
{
    return crabc_x86_64_getpagesize_probe();
}
#endif
