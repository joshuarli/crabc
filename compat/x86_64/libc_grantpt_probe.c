/* Static x86-64 grantpt C ABI and pinned-musl behavior fixture.
 *
 * Pinned musl's legacy Linux wrapper is a no-op success for every integer
 * descriptor. The same project-header body first checks that behavior through
 * musl and then through a true static crabc archive; it does not allocate,
 * unlock, name, or inspect a PTY.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <stdlib.h>

#ifndef CRABC_GRANTPT_FREESTANDING
#include <errno.h>
#endif

typedef int (*grantpt_signature)(int);

_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
    "x86 int ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&grantpt),
    grantpt_signature), "grantpt declaration");

static int check_noop_results(void)
{
    const grantpt_signature invoke = grantpt;

#ifndef CRABC_GRANTPT_FREESTANDING
    errno = 313;
    if (grantpt(-1) != 0 || errno != 313)
        return 1;
    errno = 313;
    if (invoke(INT32_MIN) != 0 || errno != 313)
        return 2;
    errno = 313;
    if (grantpt(0) != 0 || errno != 313)
        return 3;
    errno = 313;
    return invoke(INT32_MAX) == 0 && errno == 313 ? 0 : 4;
#else
    if (grantpt(-1) != 0)
        return 1;
    if (invoke(INT32_MIN) != 0)
        return 2;
    if (grantpt(0) != 0)
        return 3;
    return invoke(INT32_MAX) == 0 ? 0 : 4;
#endif
}

int crabc_x86_64_grantpt_probe(void)
{
    return check_noop_results();
}

#ifndef CRABC_GRANTPT_FREESTANDING
int main(void)
{
    return crabc_x86_64_grantpt_probe();
}
#endif
