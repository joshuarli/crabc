/*
 * Native Linux/x86-64 C11 declaration probe for C-locale floating parser
 * entry points.
 *
 * Pinned musl 1.2.6 is the declaration oracle.  This intentionally uses the
 * strict base <stdlib.h> surface, where strtof, strtod, strtold, and atof
 * are unconditional declarations. The x87 binary80 result signature is
 * checked directly rather than inferred from float/double.
 *
 * The runner compiles this source against both header trees.  It does not
 * link a C runtime or imply that the rest of <stdlib.h> is owned.
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

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef float (*crabc_strtof_signature)(const char *restrict,
    char **restrict);
typedef double (*crabc_strtod_signature)(const char *restrict,
    char **restrict);
typedef long double (*crabc_strtold_signature)(const char *restrict,
    char **restrict);
typedef double (*crabc_atof_signature)(const char *);

_Static_assert(sizeof(float) == 4 && sizeof(double) == 8 &&
    sizeof(long double) == 16 && _Alignof(long double) == 16,
    "x86-64 IEEE-754 and x87 binary80 widths");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtof), crabc_strtof_signature),
    "strtof declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtod), crabc_strtod_signature),
    "strtod declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtold), crabc_strtold_signature),
    "strtold declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&atof), crabc_atof_signature),
    "atof declaration");

static crabc_strtof_signature crabc_float_parse_strtof = &strtof;
static crabc_strtod_signature crabc_float_parse_strtod = &strtod;
static crabc_strtold_signature crabc_float_parse_strtold = &strtold;
static crabc_atof_signature crabc_float_parse_atof = &atof;

int crabc_x86_64_float_parse_header_abi_probe(void)
{
    (void)crabc_float_parse_strtof;
    (void)crabc_float_parse_strtod;
    (void)crabc_float_parse_strtold;
    (void)crabc_float_parse_atof;
    return 0;
}
