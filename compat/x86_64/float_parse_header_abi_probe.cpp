/*
 * Native Linux/x86-64 C++17 declaration and linkage probe for C-locale
 * floating parser entry points.
 *
 * The `used` references deliberately leave undefined names in this object.
 * The runner verifies that <stdlib.h> requests the unmangled C spellings
 * strtof, strtod, strtold, and atof, including the independent x87
 * extended-precision result type.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) || \
    defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE) || \
    defined(_LARGEFILE64_SOURCE)
#error "this probe intentionally uses the strict base header surface"
#endif

#include <stdlib.h>

using crabc_strtof_signature = float (*)(const char *__restrict,
    char **__restrict);
using crabc_strtod_signature = double (*)(const char *__restrict,
    char **__restrict);
using crabc_strtold_signature = long double (*)(const char *__restrict,
    char **__restrict);
using crabc_atof_signature = double (*)(const char *);

static_assert(sizeof(float) == 4 && sizeof(double) == 8 &&
    sizeof(long double) == 16 && alignof(long double) == 16,
    "x86-64 IEEE-754 and x87 binary80 widths");
static_assert(__is_same(decltype(&strtof), crabc_strtof_signature),
    "strtof C++ declaration");
static_assert(__is_same(decltype(&strtod), crabc_strtod_signature),
    "strtod C++ declaration");
static_assert(__is_same(decltype(&strtold), crabc_strtold_signature),
    "strtold C++ declaration");
static_assert(__is_same(decltype(&atof), crabc_atof_signature),
    "atof C++ declaration");

/* `used` preserves the header-requested references for C-linkage inspection. */
__attribute__((used)) static crabc_strtof_signature crabc_float_parse_strtof =
    &strtof;
__attribute__((used)) static crabc_strtod_signature crabc_float_parse_strtod =
    &strtod;
__attribute__((used)) static crabc_strtold_signature crabc_float_parse_strtold =
    &strtold;
__attribute__((used)) static crabc_atof_signature crabc_float_parse_atof =
    &atof;

int crabc_x86_64_float_parse_header_abi_probe_cpp()
{
    return 0;
}
