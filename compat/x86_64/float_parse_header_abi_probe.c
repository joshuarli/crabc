/*
 * Native Linux/x86-64 C11 declaration probe for the complete staged
 * numeric.parse-float-locale entry-point family.
 *
 * Pinned musl 1.2.6 is the declaration oracle.  This intentionally uses the
 * GNU/POSIX declaration profile because the capability includes the
 * locale-argument and legacy conversion spellings alongside the strict-base
 * narrow and wide conversion names. The x87 binary80 result signatures are
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

#include <inttypes.h>
#include <locale.h>
#include <stdlib.h>
#include <wchar.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef float (*crabc_strtof_signature)(const char *restrict,
    char **restrict);
typedef double (*crabc_strtod_signature)(const char *restrict,
    char **restrict);
typedef long double (*crabc_strtold_signature)(const char *restrict,
    char **restrict);
typedef double (*crabc_atof_signature)(const char *);
typedef char *(*crabc_ecvt_signature)(double, int, int *, int *);
typedef char *(*crabc_fcvt_signature)(double, int, int *, int *);
typedef char *(*crabc_gcvt_signature)(double, int, char *);
typedef int (*crabc_getsubopt_signature)(char **, char *const *, char **);
typedef float (*crabc_strtof_l_signature)(const char *restrict,
    char **restrict, locale_t);
typedef double (*crabc_strtod_l_signature)(const char *restrict,
    char **restrict, locale_t);
typedef long double (*crabc_strtold_l_signature)(const char *restrict,
    char **restrict, locale_t);
typedef float (*crabc_wcstof_signature)(const wchar_t *restrict,
    wchar_t **restrict);
typedef double (*crabc_wcstod_signature)(const wchar_t *restrict,
    wchar_t **restrict);
typedef long double (*crabc_wcstold_signature)(const wchar_t *restrict,
    wchar_t **restrict);
typedef long (*crabc_wcstol_signature)(const wchar_t *restrict,
    wchar_t **restrict, int);
typedef unsigned long (*crabc_wcstoul_signature)(const wchar_t *restrict,
    wchar_t **restrict, int);
typedef long long (*crabc_wcstoll_signature)(const wchar_t *restrict,
    wchar_t **restrict, int);
typedef unsigned long long (*crabc_wcstoull_signature)(const wchar_t *restrict,
    wchar_t **restrict, int);
typedef intmax_t (*crabc_wcstoimax_signature)(const wchar_t *restrict,
    wchar_t **restrict, int);
typedef uintmax_t (*crabc_wcstoumax_signature)(const wchar_t *restrict,
    wchar_t **restrict, int);

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
_Static_assert(CRABC_TYPE_IS(__typeof__(&ecvt), crabc_ecvt_signature),
    "ecvt declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&fcvt), crabc_fcvt_signature),
    "fcvt declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&gcvt), crabc_gcvt_signature),
    "gcvt declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&getsubopt), crabc_getsubopt_signature),
    "getsubopt declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtof_l), crabc_strtof_l_signature),
    "strtof_l declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtod_l), crabc_strtod_l_signature),
    "strtod_l declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&strtold_l), crabc_strtold_l_signature),
    "strtold_l declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstof), crabc_wcstof_signature),
    "wcstof declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstod), crabc_wcstod_signature),
    "wcstod declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstold), crabc_wcstold_signature),
    "wcstold declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstol), crabc_wcstol_signature),
    "wcstol declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstoul), crabc_wcstoul_signature),
    "wcstoul declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstoll), crabc_wcstoll_signature),
    "wcstoll declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstoull), crabc_wcstoull_signature),
    "wcstoull declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstoimax), crabc_wcstoimax_signature),
    "wcstoimax declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstoumax), crabc_wcstoumax_signature),
    "wcstoumax declaration");

static crabc_strtof_signature crabc_float_parse_strtof = &strtof;
static crabc_strtod_signature crabc_float_parse_strtod = &strtod;
static crabc_strtold_signature crabc_float_parse_strtold = &strtold;
static crabc_atof_signature crabc_float_parse_atof = &atof;
static crabc_ecvt_signature crabc_float_parse_ecvt = &ecvt;
static crabc_fcvt_signature crabc_float_parse_fcvt = &fcvt;
static crabc_gcvt_signature crabc_float_parse_gcvt = &gcvt;
static crabc_getsubopt_signature crabc_float_parse_getsubopt = &getsubopt;
static crabc_strtof_l_signature crabc_float_parse_strtof_l = &strtof_l;
static crabc_strtod_l_signature crabc_float_parse_strtod_l = &strtod_l;
static crabc_strtold_l_signature crabc_float_parse_strtold_l = &strtold_l;
static crabc_wcstof_signature crabc_float_parse_wcstof = &wcstof;
static crabc_wcstod_signature crabc_float_parse_wcstod = &wcstod;
static crabc_wcstold_signature crabc_float_parse_wcstold = &wcstold;
static crabc_wcstol_signature crabc_float_parse_wcstol = &wcstol;
static crabc_wcstoul_signature crabc_float_parse_wcstoul = &wcstoul;
static crabc_wcstoll_signature crabc_float_parse_wcstoll = &wcstoll;
static crabc_wcstoull_signature crabc_float_parse_wcstoull = &wcstoull;
static crabc_wcstoimax_signature crabc_float_parse_wcstoimax = &wcstoimax;
static crabc_wcstoumax_signature crabc_float_parse_wcstoumax = &wcstoumax;

int crabc_x86_64_float_parse_header_abi_probe(void)
{
    (void)crabc_float_parse_strtof;
    (void)crabc_float_parse_strtod;
    (void)crabc_float_parse_strtold;
    (void)crabc_float_parse_atof;
    (void)crabc_float_parse_ecvt;
    (void)crabc_float_parse_fcvt;
    (void)crabc_float_parse_gcvt;
    (void)crabc_float_parse_getsubopt;
    (void)crabc_float_parse_strtof_l;
    (void)crabc_float_parse_strtod_l;
    (void)crabc_float_parse_strtold_l;
    (void)crabc_float_parse_wcstof;
    (void)crabc_float_parse_wcstod;
    (void)crabc_float_parse_wcstold;
    (void)crabc_float_parse_wcstol;
    (void)crabc_float_parse_wcstoul;
    (void)crabc_float_parse_wcstoll;
    (void)crabc_float_parse_wcstoull;
    (void)crabc_float_parse_wcstoimax;
    (void)crabc_float_parse_wcstoumax;
    return 0;
}
