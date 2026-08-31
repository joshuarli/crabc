/*
 * Native Linux/x86-64 C++17 declaration and linkage probe for the complete
 * staged numeric.parse-float-locale entry-point family.
 *
 * The `used` references deliberately leave undefined names in this object.
 * The runner verifies that the four participating headers request all twenty
 * public names with unmangled C linkage, including independent x87
 * extended-precision results, locale_t, wchar_t, and intmax_t.
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

using crabc_strtof_signature = float (*)(const char *__restrict,
    char **__restrict);
using crabc_strtod_signature = double (*)(const char *__restrict,
    char **__restrict);
using crabc_strtold_signature = long double (*)(const char *__restrict,
    char **__restrict);
using crabc_atof_signature = double (*)(const char *);
using crabc_ecvt_signature = char *(*)(double, int, int *, int *);
using crabc_fcvt_signature = char *(*)(double, int, int *, int *);
using crabc_gcvt_signature = char *(*)(double, int, char *);
using crabc_getsubopt_signature = int (*)(char **, char *const *, char **);
using crabc_strtof_l_signature = float (*)(const char *__restrict,
    char **__restrict, locale_t);
using crabc_strtod_l_signature = double (*)(const char *__restrict,
    char **__restrict, locale_t);
using crabc_strtold_l_signature = long double (*)(const char *__restrict,
    char **__restrict, locale_t);
using crabc_wcstof_signature = float (*)(const wchar_t *__restrict,
    wchar_t **__restrict);
using crabc_wcstod_signature = double (*)(const wchar_t *__restrict,
    wchar_t **__restrict);
using crabc_wcstold_signature = long double (*)(const wchar_t *__restrict,
    wchar_t **__restrict);
using crabc_wcstol_signature = long (*)(const wchar_t *__restrict,
    wchar_t **__restrict, int);
using crabc_wcstoul_signature = unsigned long (*)(const wchar_t *__restrict,
    wchar_t **__restrict, int);
using crabc_wcstoll_signature = long long (*)(const wchar_t *__restrict,
    wchar_t **__restrict, int);
using crabc_wcstoull_signature = unsigned long long (*)(
    const wchar_t *__restrict, wchar_t **__restrict, int);
using crabc_wcstoimax_signature = intmax_t (*)(const wchar_t *__restrict,
    wchar_t **__restrict, int);
using crabc_wcstoumax_signature = uintmax_t (*)(const wchar_t *__restrict,
    wchar_t **__restrict, int);

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
static_assert(__is_same(decltype(&ecvt), crabc_ecvt_signature), "ecvt C++ declaration");
static_assert(__is_same(decltype(&fcvt), crabc_fcvt_signature), "fcvt C++ declaration");
static_assert(__is_same(decltype(&gcvt), crabc_gcvt_signature), "gcvt C++ declaration");
static_assert(__is_same(decltype(&getsubopt), crabc_getsubopt_signature), "getsubopt C++ declaration");
static_assert(__is_same(decltype(&strtof_l), crabc_strtof_l_signature), "strtof_l C++ declaration");
static_assert(__is_same(decltype(&strtod_l), crabc_strtod_l_signature), "strtod_l C++ declaration");
static_assert(__is_same(decltype(&strtold_l), crabc_strtold_l_signature), "strtold_l C++ declaration");
static_assert(__is_same(decltype(&wcstof), crabc_wcstof_signature), "wcstof C++ declaration");
static_assert(__is_same(decltype(&wcstod), crabc_wcstod_signature), "wcstod C++ declaration");
static_assert(__is_same(decltype(&wcstold), crabc_wcstold_signature), "wcstold C++ declaration");
static_assert(__is_same(decltype(&wcstol), crabc_wcstol_signature), "wcstol C++ declaration");
static_assert(__is_same(decltype(&wcstoul), crabc_wcstoul_signature), "wcstoul C++ declaration");
static_assert(__is_same(decltype(&wcstoll), crabc_wcstoll_signature), "wcstoll C++ declaration");
static_assert(__is_same(decltype(&wcstoull), crabc_wcstoull_signature), "wcstoull C++ declaration");
static_assert(__is_same(decltype(&wcstoimax), crabc_wcstoimax_signature), "wcstoimax C++ declaration");
static_assert(__is_same(decltype(&wcstoumax), crabc_wcstoumax_signature), "wcstoumax C++ declaration");

/* `used` preserves the header-requested references for C-linkage inspection. */
__attribute__((used)) static crabc_strtof_signature crabc_float_parse_strtof =
    &strtof;
__attribute__((used)) static crabc_strtod_signature crabc_float_parse_strtod =
    &strtod;
__attribute__((used)) static crabc_strtold_signature crabc_float_parse_strtold =
    &strtold;
__attribute__((used)) static crabc_atof_signature crabc_float_parse_atof =
    &atof;
__attribute__((used)) static crabc_ecvt_signature crabc_float_parse_ecvt = &ecvt;
__attribute__((used)) static crabc_fcvt_signature crabc_float_parse_fcvt = &fcvt;
__attribute__((used)) static crabc_gcvt_signature crabc_float_parse_gcvt = &gcvt;
__attribute__((used)) static crabc_getsubopt_signature crabc_float_parse_getsubopt = &getsubopt;
__attribute__((used)) static crabc_strtof_l_signature crabc_float_parse_strtof_l = &strtof_l;
__attribute__((used)) static crabc_strtod_l_signature crabc_float_parse_strtod_l = &strtod_l;
__attribute__((used)) static crabc_strtold_l_signature crabc_float_parse_strtold_l = &strtold_l;
__attribute__((used)) static crabc_wcstof_signature crabc_float_parse_wcstof = &wcstof;
__attribute__((used)) static crabc_wcstod_signature crabc_float_parse_wcstod = &wcstod;
__attribute__((used)) static crabc_wcstold_signature crabc_float_parse_wcstold = &wcstold;
__attribute__((used)) static crabc_wcstol_signature crabc_float_parse_wcstol = &wcstol;
__attribute__((used)) static crabc_wcstoul_signature crabc_float_parse_wcstoul = &wcstoul;
__attribute__((used)) static crabc_wcstoll_signature crabc_float_parse_wcstoll = &wcstoll;
__attribute__((used)) static crabc_wcstoull_signature crabc_float_parse_wcstoull = &wcstoull;
__attribute__((used)) static crabc_wcstoimax_signature crabc_float_parse_wcstoimax = &wcstoimax;
__attribute__((used)) static crabc_wcstoumax_signature crabc_float_parse_wcstoumax = &wcstoumax;

int crabc_x86_64_float_parse_header_abi_probe_cpp()
{
    return 0;
}
