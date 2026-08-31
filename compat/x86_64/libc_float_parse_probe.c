/* Static x86-64 floating-conversion behavior fixture.
 *
 * This fixture names the complete allocation-free staged
 * `numeric.parse-float-locale` boundary: narrow and wide floating conversion,
 * wide integer conversion, locale-argument aliases, legacy decimal formatting,
 * and `getsubopt`. Every entry is called through a
 * function pointer so a future freestanding archive cannot satisfy these
 * checks through a compiler builtin or an ambient C runtime.  In particular,
 * `strtold` is observed as its Linux/x86-64 SysV x87 binary80 result, not
 * narrowed through C `double` or Rust `f128`.
 *
 * Pinned behavior oracle: musl 1.2.6, commit 9fa28ece75d8a2191de7c5bb53bed224c5947417:
 * `src/stdlib/{strtod,wcstod,wcstol,atof,ecvt,fcvt,gcvt}.c`,
 * `src/locale/strtod_l.c`, `src/misc/getsubopt.c`, and
 * `src/internal/{floatscan,intscan}.c`.
 * The probe is an oracle-facing behavior fixture, not a source translation.
 */

#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <inttypes.h>
#include <locale.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

extern float __strtof_l(const char *, char **, locale_t);
extern double __strtod_l(const char *, char **, locale_t);
extern long double __strtold_l(const char *, char **, locale_t);

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(float) == 4 && sizeof(double) == 8,
    "x86 binary32/binary64 storage");
_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16,
    "x86 SysV binary80 long-double storage");
_Static_assert(FLT_RADIX == 2 && FLT_MANT_DIG == 24 && DBL_MANT_DIG == 53,
    "x86 binary floating-point precision");
_Static_assert(FLT_MIN_EXP == -125 && FLT_MAX_EXP == 128 &&
    DBL_MIN_EXP == -1021 && DBL_MAX_EXP == 1024,
    "x86 binary floating-point exponent range");
_Static_assert(LDBL_MANT_DIG == 64 && LDBL_MIN_EXP == -16381 &&
    LDBL_MAX_EXP == 16384,
    "x86 x87 binary80 precision and exponent range");

typedef float (*strtof_fn)(const char *, char **);
typedef double (*strtod_fn)(const char *, char **);
typedef long double (*strtold_fn)(const char *, char **);
typedef double (*atof_fn)(const char *);
typedef char *(*ecvt_fn)(double, int, int *, int *);
typedef char *(*fcvt_fn)(double, int, int *, int *);
typedef char *(*gcvt_fn)(double, int, char *);
typedef int (*getsubopt_fn)(char **, char *const *, char **);
typedef float (*strtof_l_fn)(const char *, char **, locale_t);
typedef double (*strtod_l_fn)(const char *, char **, locale_t);
typedef long double (*strtold_l_fn)(const char *, char **, locale_t);
typedef float (*wcstof_fn)(const wchar_t *, wchar_t **);
typedef double (*wcstod_fn)(const wchar_t *, wchar_t **);
typedef long double (*wcstold_fn)(const wchar_t *, wchar_t **);
typedef long (*wcstol_fn)(const wchar_t *, wchar_t **, int);
typedef unsigned long (*wcstoul_fn)(const wchar_t *, wchar_t **, int);
typedef long long (*wcstoll_fn)(const wchar_t *, wchar_t **, int);
typedef unsigned long long (*wcstoull_fn)(const wchar_t *, wchar_t **, int);
typedef intmax_t (*wcstoimax_fn)(const wchar_t *, wchar_t **, int);
typedef uintmax_t (*wcstoumax_fn)(const wchar_t *, wchar_t **, int);
typedef int (*feclearexcept_fn)(int);
typedef int (*fetestexcept_fn)(int);
typedef int (*fegetenv_fn)(fenv_t *);
typedef int (*fegetround_fn)(void);
typedef int (*fesetenv_fn)(const fenv_t *);
typedef int (*fesetround_fn)(int);

/* Keep the entry addresses observable until the call site. This is stronger
 * than merely compiling with `-fno-builtin`: the fixture cannot fold a named
 * conversion into a compiler-provided implementation. */
static strtof_fn volatile strtof_entry = strtof;
static strtod_fn volatile strtod_entry = strtod;
static strtold_fn volatile strtold_entry = strtold;
static atof_fn volatile atof_entry = atof;
static ecvt_fn volatile ecvt_entry = ecvt;
static fcvt_fn volatile fcvt_entry = fcvt;
static gcvt_fn volatile gcvt_entry = gcvt;
static getsubopt_fn volatile getsubopt_entry = getsubopt;
static strtof_l_fn volatile strtof_l_entry = strtof_l;
static strtod_l_fn volatile strtod_l_entry = strtod_l;
static strtold_l_fn volatile strtold_l_entry = strtold_l;
static strtof_l_fn volatile internal_strtof_l_entry = __strtof_l;
static strtod_l_fn volatile internal_strtod_l_entry = __strtod_l;
static strtold_l_fn volatile internal_strtold_l_entry = __strtold_l;
static wcstof_fn volatile wcstof_entry = wcstof;
static wcstod_fn volatile wcstod_entry = wcstod;
static wcstold_fn volatile wcstold_entry = wcstold;
static wcstol_fn volatile wcstol_entry = wcstol;
static wcstoul_fn volatile wcstoul_entry = wcstoul;
static wcstoll_fn volatile wcstoll_entry = wcstoll;
static wcstoull_fn volatile wcstoull_entry = wcstoull;
static wcstoimax_fn volatile wcstoimax_entry = wcstoimax;
static wcstoumax_fn volatile wcstoumax_entry = wcstoumax;

typedef union {
    float value;
    uint32_t bits;
} float_bits;

typedef union {
    double value;
    uint64_t bits;
} double_bits;

/* Only bytes 0 through 9 are defined by the x87 binary80 ABI. The trailing
 * six bytes of Linux/x86-64 `long double` storage are padding, so this probe
 * deliberately never observes them. */
typedef union {
    long double value;
    unsigned char bytes[sizeof(long double)];
} long_double_bits;

#define TEXT_END(text) (sizeof(text) - 1U)

static uint64_t long_double_mantissa(const long_double_bits *value)
{
    uint64_t result = 0;
    int index;

    for (index = 7; index >= 0; index--)
        result = (result << 8) | value->bytes[index];
    return result;
}

static uint16_t long_double_sign_exponent(const long_double_bits *value)
{
    return (uint16_t)value->bytes[8] | ((uint16_t)value->bytes[9] << 8);
}

static size_t c_string_length(const char *text)
{
    size_t length = 0;

    while (text[length] != '\0')
        length++;
    return length;
}

static int expect_float(strtof_fn parse, const char *input, uint32_t expected_bits,
    size_t expected_end, int initial_errno, int expected_errno)
{
    char *end = NULL;
    float_bits value;

    errno = initial_errno;
    value.value = parse(input, &end);
    if (value.bits != expected_bits)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_double(strtod_fn parse, const char *input,
    uint64_t expected_bits, size_t expected_end, int initial_errno,
    int expected_errno)
{
    char *end = NULL;
    double_bits value;

    errno = initial_errno;
    value.value = parse(input, &end);
    if (value.bits != expected_bits)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_long_double(strtold_fn parse, const char *input,
    uint64_t expected_mantissa, uint16_t expected_sign_exponent,
    size_t expected_end, int initial_errno, int expected_errno)
{
    char *end = NULL;
    long_double_bits value;

    errno = initial_errno;
    value.value = parse(input, &end);
    if (long_double_mantissa(&value) != expected_mantissa)
        return 1;
    if (long_double_sign_exponent(&value) != expected_sign_exponent)
        return 2;
    if (end != input + expected_end)
        return 3;
    return errno == expected_errno ? 0 : 4;
}

static int expect_atof(atof_fn parse, const char *input, uint64_t expected_bits,
    int initial_errno, int expected_errno)
{
    double_bits value;

    errno = initial_errno;
    value.value = parse(input);
    if (value.bits != expected_bits)
        return 1;
    return errno == expected_errno ? 0 : 2;
}

static int expect_float_nan(strtof_fn parse, const char *input,
    size_t expected_end, int initial_errno, int expected_errno)
{
    char *end = NULL;
    float_bits value;

    errno = initial_errno;
    value.value = parse(input, &end);
    if ((value.bits & UINT32_C(0x7f800000)) != UINT32_C(0x7f800000) ||
        (value.bits & UINT32_C(0x007fffff)) == 0)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_double_nan(strtod_fn parse, const char *input,
    size_t expected_end, int initial_errno, int expected_errno)
{
    char *end = NULL;
    double_bits value;

    errno = initial_errno;
    value.value = parse(input, &end);
    if ((value.bits & UINT64_C(0x7ff0000000000000)) !=
            UINT64_C(0x7ff0000000000000) ||
        (value.bits & UINT64_C(0x000fffffffffffff)) == 0)
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int expect_long_double_nan(strtold_fn parse, const char *input,
    size_t expected_end, int initial_errno, int expected_errno)
{
    char *end = NULL;
    long_double_bits value;
    uint64_t mantissa;
    uint16_t sign_exponent;

    errno = initial_errno;
    value.value = parse(input, &end);
    mantissa = long_double_mantissa(&value);
    sign_exponent = long_double_sign_exponent(&value);
    if ((sign_exponent & UINT16_C(0x7fff)) != UINT16_C(0x7fff) ||
        mantissa == UINT64_C(0x8000000000000000))
        return 1;
    if (end != input + expected_end)
        return 2;
    return errno == expected_errno ? 0 : 3;
}

static int check_decimal_and_end_pointer(strtof_fn parse_float,
    strtod_fn parse_double, atof_fn parse_atof)
{
    int status;

    status = expect_double(parse_double, " \t-12.5tail",
        UINT64_C(0xc029000000000000), TEXT_END(" \t-12.5"), EINTR, EINTR);
    if (status != 0)
        return 10 + status;
    status = expect_double(parse_double, ".5",
        UINT64_C(0x3fe0000000000000), TEXT_END(".5"), EDOM, EDOM);
    if (status != 0)
        return 20 + status;
    status = expect_double(parse_double, "1.e2",
        UINT64_C(0x4059000000000000), TEXT_END("1.e2"), EINTR, EINTR);
    if (status != 0)
        return 30 + status;
    status = expect_double(parse_double, "12e+tail",
        UINT64_C(0x4028000000000000), TEXT_END("12"), EDOM, EDOM);
    if (status != 0)
        return 40 + status;
    status = expect_double(parse_double, " \t+", UINT64_C(0), 0, EINTR,
        EINVAL);
    if (status != 0)
        return 50 + status;
    status = expect_double(parse_double, "-0", UINT64_C(0x8000000000000000),
        TEXT_END("-0"), EDOM, EDOM);
    if (status != 0)
        return 60 + status;

    status = expect_float(parse_float, " \t-12.5tail", UINT32_C(0xc1480000),
        TEXT_END(" \t-12.5"), EINTR, EINTR);
    if (status != 0)
        return 70 + status;
    status = expect_float(parse_float, ".5", UINT32_C(0x3f000000),
        TEXT_END(".5"), EDOM, EDOM);
    if (status != 0)
        return 80 + status;
    status = expect_float(parse_float, "12e+tail", UINT32_C(0x41400000),
        TEXT_END("12"), EINTR, EINTR);
    if (status != 0)
        return 90 + status;
    status = expect_float(parse_float, "-0", UINT32_C(0x80000000),
        TEXT_END("-0"), EDOM, EDOM);
    if (status != 0)
        return 100 + status;

    status = expect_atof(parse_atof, " \t-12.5tail",
        UINT64_C(0xc029000000000000), EINTR, EINTR);
    if (status != 0)
        return 110 + status;
    return expect_atof(parse_atof, "0x1.8p+1", UINT64_C(0x4008000000000000),
        EDOM, EDOM) == 0 ? 0 : 120;
}

static int check_special_forms(strtof_fn parse_float, strtod_fn parse_double)
{
    int status;

    status = expect_double(parse_double, "INF", UINT64_C(0x7ff0000000000000),
        TEXT_END("INF"), EINTR, EINTR);
    if (status != 0)
        return 10 + status;
    status = expect_double(parse_double, "infinity!",
        UINT64_C(0x7ff0000000000000), TEXT_END("infinity"), EDOM, EDOM);
    if (status != 0)
        return 20 + status;
    /* Musl accepts the `inf` prefix and stops before the malformed suffix. */
    status = expect_double(parse_double, "infinite",
        UINT64_C(0x7ff0000000000000), TEXT_END("inf"), EINTR, EINTR);
    if (status != 0)
        return 30 + status;
    status = expect_double_nan(parse_double, "nan(payload)",
        TEXT_END("nan(payload)"), EDOM, EDOM);
    if (status != 0)
        return 40 + status;
    /* An unterminated payload is the same accepted `nan` prefix in musl. */
    status = expect_double_nan(parse_double, "nan(", TEXT_END("nan"), EINTR,
        EINTR);
    if (status != 0)
        return 50 + status;

    status = expect_float(parse_float, "-INF?", UINT32_C(0xff800000),
        TEXT_END("-INF"), EDOM, EDOM);
    if (status != 0)
        return 60 + status;
    return expect_float_nan(parse_float, "NAN(payload)",
        TEXT_END("NAN(payload)"), EINTR, EINTR) == 0 ? 0 : 70;
}

static int check_hex_syntax(strtof_fn parse_float, strtod_fn parse_double)
{
    int status;

    status = expect_double(parse_double, "0x1.8p+1tail",
        UINT64_C(0x4008000000000000), TEXT_END("0x1.8p+1"), EINTR, EINTR);
    if (status != 0)
        return 10 + status;
    status = expect_double(parse_double, "-0x0p+0",
        UINT64_C(0x8000000000000000), TEXT_END("-0x0p+0"), EDOM, EDOM);
    if (status != 0)
        return 20 + status;
    /* A malformed binary exponent rolls back to the complete significand. */
    status = expect_double(parse_double, "0x1p+tail",
        UINT64_C(0x3ff0000000000000), TEXT_END("0x1"), EINTR, EINTR);
    if (status != 0)
        return 30 + status;
    /* No hexadecimal digit after `0x` leaves the leading decimal zero only. */
    status = expect_double(parse_double, "0x.p1", UINT64_C(0), TEXT_END("0"),
        EDOM, EDOM);
    if (status != 0)
        return 40 + status;

    return expect_float(parse_float, "0x1p-1", UINT32_C(0x3f000000),
        TEXT_END("0x1p-1"), EINTR, EINTR) == 0 ? 0 : 50;
}

static int check_range_and_boundary(strtof_fn parse_float, strtod_fn parse_double,
    atof_fn parse_atof)
{
    int status;

    status = expect_double(parse_double, "0x1.fffffffffffffp+1023",
        UINT64_C(0x7fefffffffffffff), TEXT_END("0x1.fffffffffffffp+1023"),
        EDOM, EDOM);
    if (status != 0)
        return 10 + status;
    status = expect_double(parse_double, "0x1p+1024",
        UINT64_C(0x7ff0000000000000), TEXT_END("0x1p+1024"), EINTR, EINTR);
    if (status != 0)
        return 20 + status;
    /* x86 musl reaches its scanner ERANGE threshold after target narrowing. */
    status = expect_double(parse_double, "0x1p+1105",
        UINT64_C(0x7ff0000000000000), TEXT_END("0x1p+1105"), EDOM, ERANGE);
    if (status != 0)
        return 25 + status;
    status = expect_double(parse_double, "0x1p-1074", UINT64_C(1),
        TEXT_END("0x1p-1074"), EDOM, EDOM);
    if (status != 0)
        return 30 + status;
    status = expect_double(parse_double, "0x1p-1075", UINT64_C(0),
        TEXT_END("0x1p-1075"), EINTR, ERANGE);
    if (status != 0)
        return 40 + status;
    status = expect_double(parse_double, "1e309", UINT64_C(0x7ff0000000000000),
        TEXT_END("1e309"), EDOM, ERANGE);
    if (status != 0)
        return 50 + status;
    status = expect_double(parse_double, "1e-400", UINT64_C(0),
        TEXT_END("1e-400"), EINTR, ERANGE);
    if (status != 0)
        return 60 + status;

    status = expect_float(parse_float, "0x1.fffffep+127",
        UINT32_C(0x7f7fffff), TEXT_END("0x1.fffffep+127"), EDOM, EDOM);
    if (status != 0)
        return 70 + status;
    status = expect_float(parse_float, "0x1p+128", UINT32_C(0x7f800000),
        TEXT_END("0x1p+128"), EINTR, EINTR);
    if (status != 0)
        return 80 + status;
    status = expect_float(parse_float, "0x1p+278", UINT32_C(0x7f800000),
        TEXT_END("0x1p+278"), EDOM, ERANGE);
    if (status != 0)
        return 85 + status;
    status = expect_float(parse_float, "0x1p-149", UINT32_C(1),
        TEXT_END("0x1p-149"), EDOM, EDOM);
    if (status != 0)
        return 90 + status;
    status = expect_float(parse_float, "0x1p-150", UINT32_C(0),
        TEXT_END("0x1p-150"), EINTR, ERANGE);
    if (status != 0)
        return 100 + status;
    status = expect_float(parse_float, "1e39", UINT32_C(0x7f800000),
        TEXT_END("1e39"), EDOM, ERANGE);
    if (status != 0)
        return 110 + status;
    status = expect_float(parse_float, "1e-50", UINT32_C(0),
        TEXT_END("1e-50"), EINTR, ERANGE);
    if (status != 0)
        return 120 + status;

    return expect_atof(parse_atof, "1e309", UINT64_C(0x7ff0000000000000),
        EDOM, ERANGE) == 0 ? 0 : 130;
}

static int check_binary80_abi(strtold_fn parse_long)
{
    int status;

    status = expect_long_double(parse_long, " \t-12.5tail",
        UINT64_C(0xc800000000000000), UINT16_C(0xc002),
        TEXT_END(" \t-12.5"), EINTR, EINTR);
    if (status != 0)
        return 10 + status;
    /* A malformed decimal exponent rewinds to the complete significand. */
    status = expect_long_double(parse_long, "12e+tail",
        UINT64_C(0xc000000000000000), UINT16_C(0x4002), TEXT_END("12"),
        EDOM, EDOM);
    if (status != 0)
        return 20 + status;
    status = expect_long_double(parse_long, "-0", UINT64_C(0),
        UINT16_C(0x8000), TEXT_END("-0"), EINTR, EINTR);
    if (status != 0)
        return 30 + status;
    status = expect_long_double(parse_long, "0x1.8p+1tail",
        UINT64_C(0xc000000000000000), UINT16_C(0x4000),
        TEXT_END("0x1.8p+1"), EDOM, EDOM);
    if (status != 0)
        return 40 + status;
    status = expect_long_double(parse_long, "0x1p-16445", UINT64_C(1),
        UINT16_C(0), TEXT_END("0x1p-16445"), EINTR, EINTR);
    if (status != 0)
        return 50 + status;
    status = expect_long_double(parse_long, "1e4933",
        UINT64_C(0x8000000000000000), UINT16_C(0x7fff), TEXT_END("1e4933"),
        EINTR, ERANGE);
    if (status != 0)
        return 60 + status;
    /* The x87 hex scanner reaches infinity through its arithmetic path but
     * leaves a pre-existing errno untouched. */
    status = expect_long_double(parse_long, "0x1p+16384",
        UINT64_C(0x8000000000000000), UINT16_C(0x7fff),
        TEXT_END("0x1p+16384"), EINTR, EINTR);
    if (status != 0)
        return 70 + status;
    status = expect_long_double(parse_long, " \t+", UINT64_C(0),
        UINT16_C(0), 0, EINTR, EINVAL);
    if (status != 0)
        return 80 + status;
    return expect_long_double_nan(parse_long, "nan(payload)",
        TEXT_END("nan(payload)"), EDOM, EDOM) == 0 ? 0 : 90;
}

static int expect_double_flags(strtod_fn parse, feclearexcept_fn clear,
    fetestexcept_fn test, const char *input, size_t expected_end,
    int expected_flags)
{
    char *end = NULL;

    if (clear(FE_ALL_EXCEPT) != 0)
        return 1;
    (void)parse(input, &end);
    if (end != input + expected_end)
        return 2;
    return test(FE_ALL_EXCEPT) == expected_flags ? 0 : 3;
}

static int check_exception_flags(strtod_fn parse_double)
{
    const feclearexcept_fn clear = feclearexcept;
    const fetestexcept_fn test = fetestexcept;
    int status;

    status = expect_double_flags(parse_double, clear, test, "0.1",
        TEXT_END("0.1"), FE_INEXACT);
    if (status != 0)
        return 10 + status;
    status = expect_double_flags(parse_double, clear, test, "1e309",
        TEXT_END("1e309"),
        FE_OVERFLOW | FE_INEXACT);
    if (status != 0)
        return 20 + status;
    status = expect_double_flags(parse_double, clear, test, "1e-400",
        TEXT_END("1e-400"),
        FE_UNDERFLOW | FE_INEXACT);
    if (status != 0)
        return 30 + status;
    /* x86 musl's binary80 hex path reports narrowing overflow without errno. */
    status = expect_double_flags(parse_double, clear, test, "0x1p+1024",
        TEXT_END("0x1p+1024"),
        FE_OVERFLOW | FE_INEXACT);
    if (status != 0)
        return 40 + status;
    /* Its hexadecimal underflow retains only the inexact exception. */
    return expect_double_flags(parse_double, clear, test, "0x1p-1075",
        TEXT_END("0x1p-1075"),
        FE_INEXACT) == 0 ? 0 : 50;
}

#if defined(FE_TONEAREST) && defined(FE_DOWNWARD) && defined(FE_UPWARD) && \
    defined(FE_TOWARDZERO)

static const int rounding_modes[] = {
    FE_TONEAREST,
    FE_DOWNWARD,
    FE_UPWARD,
    FE_TOWARDZERO,
};

static int set_and_check_rounding(fesetround_fn set_round,
    fegetround_fn get_round, int round)
{
    if (set_round(round) != 0)
        return 1;
    return get_round() == round ? 0 : 2;
}

static int expect_float_rounding(strtof_fn parse, feclearexcept_fn clear,
    fetestexcept_fn test, fesetround_fn set_round, fegetround_fn get_round,
    const char *input, int round, uint32_t expected_bits,
    int expected_errno, int expected_flags)
{
    const char *volatile source = input;
    char *end = NULL;
    float_bits value;

    if (clear(FE_ALL_EXCEPT) != 0)
        return 1;
    if (set_and_check_rounding(set_round, get_round, round) != 0)
        return 2;
    errno = EINTR;
    value.value = parse(source, &end);
    if (value.bits != expected_bits)
        return 3;
    if (end != input + c_string_length(input))
        return 4;
    if (errno != expected_errno)
        return 5;
    return test(FE_ALL_EXCEPT) == expected_flags ? 0 : 6;
}

static int expect_double_rounding(strtod_fn parse, feclearexcept_fn clear,
    fetestexcept_fn test, fesetround_fn set_round, fegetround_fn get_round,
    const char *input, int round, uint64_t expected_bits,
    int expected_errno, int expected_flags)
{
    const char *volatile source = input;
    char *end = NULL;
    double_bits value;

    if (clear(FE_ALL_EXCEPT) != 0)
        return 1;
    if (set_and_check_rounding(set_round, get_round, round) != 0)
        return 2;
    errno = EINTR;
    value.value = parse(source, &end);
    if (value.bits != expected_bits)
        return 3;
    if (end != input + c_string_length(input))
        return 4;
    if (errno != expected_errno)
        return 5;
    return test(FE_ALL_EXCEPT) == expected_flags ? 0 : 6;
}

static int expect_long_double_rounding(strtold_fn parse,
    feclearexcept_fn clear, fetestexcept_fn test, fesetround_fn set_round,
    fegetround_fn get_round, const char *input, int round,
    uint64_t expected_mantissa, uint16_t expected_sign_exponent,
    int expected_errno, int expected_flags)
{
    const char *volatile source = input;
    char *end = NULL;
    long_double_bits value;

    if (clear(FE_ALL_EXCEPT) != 0)
        return 1;
    if (set_and_check_rounding(set_round, get_round, round) != 0)
        return 2;
    errno = EINTR;
    value.value = parse(source, &end);
    if (long_double_mantissa(&value) != expected_mantissa)
        return 3;
    if (long_double_sign_exponent(&value) != expected_sign_exponent)
        return 4;
    if (end != input + c_string_length(input))
        return 5;
    if (errno != expected_errno)
        return 6;
    return test(FE_ALL_EXCEPT) == expected_flags ? 0 : 7;
}

static int expect_atof_rounding(atof_fn parse, feclearexcept_fn clear,
    fetestexcept_fn test, fesetround_fn set_round, fegetround_fn get_round,
    const char *input, int round, uint64_t expected_bits,
    int expected_errno, int expected_flags)
{
    const char *volatile source = input;
    double_bits value;

    if (clear(FE_ALL_EXCEPT) != 0)
        return 1;
    if (set_and_check_rounding(set_round, get_round, round) != 0)
        return 2;
    errno = EINTR;
    value.value = parse(source);
    if (value.bits != expected_bits)
        return 3;
    if (errno != expected_errno)
        return 4;
    return test(FE_ALL_EXCEPT) == expected_flags ? 0 : 5;
}

struct float_underflow_case {
    const char *input;
    uint32_t bits[4];
    int errnos[4];
    int flags[4];
};

struct double_underflow_case {
    const char *input;
    uint64_t bits[4];
    int errnos[4];
    int flags[4];
};

struct long_double_underflow_case {
    const char *input;
    uint64_t mantissas[4];
    uint16_t sign_exponents[4];
    int errnos[4];
    int flags[4];
};

/* These are directed-rounding boundary results from pinned musl's x87
 * `decfloat`/`hexfloat` paths. They deliberately include its observable
 * signed-zero, errno, and flag outcomes rather than a generic IEEE packer. */
static const struct float_underflow_case float_underflow_cases[] = {
    {
        "1e-45",
        { UINT32_C(0x00000001), UINT32_C(0x80000000),
          UINT32_C(0x00000001), UINT32_C(0x00000000) },
        { EINTR, ERANGE, EINTR, ERANGE },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
    {
        "-1e-45",
        { UINT32_C(0x80000001), UINT32_C(0x80000001),
          UINT32_C(0x00000000), UINT32_C(0x00000000) },
        { EINTR, EINTR, ERANGE, ERANGE },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
    {
        "0x1p-150",
        { UINT32_C(0x00000000), UINT32_C(0x80000000),
          UINT32_C(0x00000001), UINT32_C(0x00000000) },
        { ERANGE, ERANGE, EINTR, ERANGE },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
    {
        "-0x1p-150",
        { UINT32_C(0x00000000), UINT32_C(0x80000001),
          UINT32_C(0x00000000), UINT32_C(0x00000000) },
        { ERANGE, EINTR, ERANGE, ERANGE },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
};

static const struct double_underflow_case double_underflow_cases[] = {
    {
        "1e-400",
        { UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
          UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000) },
        { ERANGE, ERANGE, ERANGE, ERANGE },
        { FE_UNDERFLOW | FE_INEXACT, FE_INEXACT,
          FE_UNDERFLOW | FE_INEXACT, FE_INEXACT },
    },
    {
        "-1e-400",
        { UINT64_C(0x8000000000000000), UINT64_C(0x8000000000000001),
          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000) },
        { ERANGE, ERANGE, ERANGE, ERANGE },
        { FE_UNDERFLOW | FE_INEXACT, FE_UNDERFLOW | FE_INEXACT,
          FE_INEXACT, FE_INEXACT },
    },
    {
        "0x1p-1075",
        { UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
          UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000) },
        { ERANGE, ERANGE, EINTR, ERANGE },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
    {
        "-0x1p-1075",
        { UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000001),
          UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000) },
        { ERANGE, EINTR, ERANGE, ERANGE },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
};

static const struct long_double_underflow_case long_double_underflow_cases[] = {
    {
        "0x1p-16446",
        { UINT64_C(0), UINT64_C(0), UINT64_C(1), UINT64_C(0) },
        { UINT16_C(0), UINT16_C(0x8000), UINT16_C(0), UINT16_C(0) },
        { ERANGE, ERANGE, EINTR, ERANGE },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
    {
        "-0x1p-16446",
        { UINT64_C(0), UINT64_C(1), UINT64_C(0), UINT64_C(0) },
        { UINT16_C(0), UINT16_C(0x8000), UINT16_C(0), UINT16_C(0) },
        { ERANGE, EINTR, ERANGE, ERANGE },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
    {
        "1e-5000",
        { UINT64_C(0), UINT64_C(0), UINT64_C(1), UINT64_C(0) },
        { UINT16_C(0), UINT16_C(0x8000), UINT16_C(0), UINT16_C(0) },
        { ERANGE, ERANGE, ERANGE, ERANGE },
        { FE_UNDERFLOW | FE_INEXACT, FE_INEXACT,
          FE_UNDERFLOW | FE_INEXACT, FE_INEXACT },
    },
    {
        "-1e-5000",
        { UINT64_C(0), UINT64_C(1), UINT64_C(0), UINT64_C(0) },
        { UINT16_C(0x8000), UINT16_C(0x8000), UINT16_C(0), UINT16_C(0) },
        { ERANGE, ERANGE, ERANGE, ERANGE },
        { FE_UNDERFLOW | FE_INEXACT, FE_UNDERFLOW | FE_INEXACT,
          FE_INEXACT, FE_INEXACT },
    },
};

/* Target precision is binary80 for `strtold`, so one bit beyond its 64-bit
 * significand must be decided by the live x87 rounding mode before `st0` is
 * returned to the C caller. */
static const struct long_double_underflow_case long_double_rounding_cases[] = {
    {
        "0x1.0000000000000001p+0",
        { UINT64_C(0x8000000000000000), UINT64_C(0x8000000000000000),
          UINT64_C(0x8000000000000001), UINT64_C(0x8000000000000000) },
        { UINT16_C(0x3fff), UINT16_C(0x3fff),
          UINT16_C(0x3fff), UINT16_C(0x3fff) },
        { EINTR, EINTR, EINTR, EINTR },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
    {
        "0x1.ffffffffffffffffp+0",
        { UINT64_C(0x8000000000000000), UINT64_C(0xffffffffffffffff),
          UINT64_C(0x8000000000000000), UINT64_C(0xffffffffffffffff) },
        { UINT16_C(0x4000), UINT16_C(0x3fff),
          UINT16_C(0x4000), UINT16_C(0x3fff) },
        { EINTR, EINTR, EINTR, EINTR },
        { FE_INEXACT, FE_INEXACT, FE_INEXACT, FE_INEXACT },
    },
};

static int check_underflow_rounding_matrix(strtof_fn parse_float,
    strtod_fn parse_double, strtold_fn parse_long, atof_fn parse_atof)
{
    const feclearexcept_fn clear = feclearexcept;
    const fetestexcept_fn test = fetestexcept;
    const fegetenv_fn get_environment = fegetenv;
    const fegetround_fn get_round = fegetround;
    const fesetenv_fn set_environment = fesetenv;
    const fesetround_fn set_round = fesetround;
    fenv_t saved;
    size_t case_index;
    size_t mode_index;
    int status = 0;

    if (get_environment(&saved) != 0)
        return 1;
    for (case_index = 0;
        case_index < sizeof(float_underflow_cases) / sizeof(float_underflow_cases[0]) &&
        status == 0; case_index++) {
        for (mode_index = 0; mode_index < 4 && status == 0; mode_index++) {
            const struct float_underflow_case *expected =
                &float_underflow_cases[case_index];

            status = expect_float_rounding(parse_float, clear, test, set_round,
                get_round, expected->input, rounding_modes[mode_index],
                expected->bits[mode_index], expected->errnos[mode_index],
                expected->flags[mode_index]);
            if (status != 0)
                status += 10 + (int)(case_index * 40 + mode_index * 7);
        }
    }
    for (case_index = 0;
        case_index < sizeof(double_underflow_cases) / sizeof(double_underflow_cases[0]) &&
        status == 0; case_index++) {
        for (mode_index = 0; mode_index < 4 && status == 0; mode_index++) {
            const struct double_underflow_case *expected =
                &double_underflow_cases[case_index];

            status = expect_double_rounding(parse_double, clear, test, set_round,
                get_round, expected->input, rounding_modes[mode_index],
                expected->bits[mode_index], expected->errnos[mode_index],
                expected->flags[mode_index]);
            if (status != 0)
                status += 190 + (int)(case_index * 40 + mode_index * 7);
        }
    }
    for (case_index = 0;
        case_index < sizeof(long_double_underflow_cases) /
            sizeof(long_double_underflow_cases[0]) && status == 0;
        case_index++) {
        for (mode_index = 0; mode_index < 4 && status == 0; mode_index++) {
            const struct long_double_underflow_case *expected =
                &long_double_underflow_cases[case_index];

            status = expect_long_double_rounding(parse_long, clear, test,
                set_round, get_round, expected->input, rounding_modes[mode_index],
                expected->mantissas[mode_index],
                expected->sign_exponents[mode_index], expected->errnos[mode_index],
                expected->flags[mode_index]);
            if (status != 0)
                status += 370 + (int)(case_index * 40 + mode_index * 8);
        }
    }
    for (case_index = 0;
        case_index < sizeof(long_double_rounding_cases) /
            sizeof(long_double_rounding_cases[0]) && status == 0;
        case_index++) {
        for (mode_index = 0; mode_index < 4 && status == 0; mode_index++) {
            const struct long_double_underflow_case *expected =
                &long_double_rounding_cases[case_index];

            status = expect_long_double_rounding(parse_long, clear, test,
                set_round, get_round, expected->input, rounding_modes[mode_index],
                expected->mantissas[mode_index],
                expected->sign_exponents[mode_index], expected->errnos[mode_index],
                expected->flags[mode_index]);
            if (status != 0)
                status += 540 + (int)(case_index * 40 + mode_index * 8);
        }
    }
    /* `atof` has no end pointer, but must retain strtod's x87-directed
     * underflow result and status behavior. */
    for (mode_index = 0; mode_index < 4 && status == 0; mode_index++) {
        const struct double_underflow_case *expected = &double_underflow_cases[0];

        status = expect_atof_rounding(parse_atof, clear, test, set_round,
            get_round, expected->input, rounding_modes[mode_index],
            expected->bits[mode_index], expected->errnos[mode_index],
            expected->flags[mode_index]);
        if (status != 0)
            status += 650 + (int)(mode_index * 6);
    }
    if (set_environment(&saved) != 0)
        return 2;
    return status;
}

static int check_one_rounding_mode(strtof_fn parse_float, strtod_fn parse_double,
    fesetround_fn set_round, fegetround_fn get_round, int round,
    uint32_t expected_float_positive, uint32_t expected_float_negative,
    uint64_t expected_double_positive, uint64_t expected_double_negative)
{
    int status;

    if (set_and_check_rounding(set_round, get_round, round) != 0)
        return 1;
    status = expect_double(parse_double,
        "1.00000000000000011102230246251565404236316680908203125",
        expected_double_positive,
        TEXT_END("1.00000000000000011102230246251565404236316680908203125"),
        EINTR, EINTR);
    if (status != 0)
        return 10 + status;
    if (set_and_check_rounding(set_round, get_round, round) != 0)
        return 20;
    status = expect_double(parse_double,
        "-1.00000000000000011102230246251565404236316680908203125",
        expected_double_negative,
        TEXT_END("-1.00000000000000011102230246251565404236316680908203125"),
        EDOM, EDOM);
    if (status != 0)
        return 30 + status;
    if (set_and_check_rounding(set_round, get_round, round) != 0)
        return 40;
    status = expect_float(parse_float, "1.000000059604644775390625",
        expected_float_positive, TEXT_END("1.000000059604644775390625"),
        EINTR, EINTR);
    if (status != 0)
        return 50 + status;
    if (set_and_check_rounding(set_round, get_round, round) != 0)
        return 60;
    status = expect_float(parse_float, "-1.000000059604644775390625",
        expected_float_negative, TEXT_END("-1.000000059604644775390625"),
        EDOM, EDOM);
    return status == 0 ? 0 : 70 + status;
}

static int check_rounding_modes(strtof_fn parse_float, strtod_fn parse_double)
{
    const fegetenv_fn get_environment = fegetenv;
    const fegetround_fn get_round = fegetround;
    const fesetenv_fn set_environment = fesetenv;
    const fesetround_fn set_round = fesetround;
    fenv_t saved;
    int status;

    if (get_environment(&saved) != 0)
        return 1;
    status = check_one_rounding_mode(parse_float, parse_double, set_round,
        get_round, FE_TONEAREST, UINT32_C(0x3f800000), UINT32_C(0xbf800000),
        UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000));
    if (status == 0)
        status = check_one_rounding_mode(parse_float, parse_double, set_round,
            get_round, FE_DOWNWARD, UINT32_C(0x3f800000),
            UINT32_C(0xbf800001), UINT64_C(0x3ff0000000000000),
            UINT64_C(0xbff0000000000001));
    if (status == 0)
        status = check_one_rounding_mode(parse_float, parse_double, set_round,
            get_round, FE_UPWARD, UINT32_C(0x3f800001), UINT32_C(0xbf800000),
            UINT64_C(0x3ff0000000000001), UINT64_C(0xbff0000000000000));
    if (status == 0)
        status = check_one_rounding_mode(parse_float, parse_double, set_round,
            get_round, FE_TOWARDZERO, UINT32_C(0x3f800000),
            UINT32_C(0xbf800000), UINT64_C(0x3ff0000000000000),
            UINT64_C(0xbff0000000000000));
    if (set_environment(&saved) != 0)
        return 2;
    return status;
}

#else

static int check_rounding_modes(strtof_fn parse_float, strtod_fn parse_double)
{
    (void)parse_float;
    (void)parse_double;
    return 0;
}

#endif

static int same_text(const char *actual, const char *expected)
{
    size_t index = 0;

    while (actual[index] == expected[index] && expected[index] != '\0')
        index++;
    return actual[index] == expected[index];
}

static size_t wide_string_length(const wchar_t *text)
{
    size_t length = 0;

    while (text[length] != L'\0')
        length++;
    return length;
}

static int check_locale_argument_aliases(void)
{
    const char input[] = " -0x1.8p+1tail";
    const size_t expected_end = TEXT_END(" -0x1.8p+1");
    locale_t ignored_locale = (locale_t)(uintptr_t)UINT64_C(0x1234);
    char *end = NULL;
    float_bits single;
    double_bits paired;
    long_double_bits extended;

    errno = EINTR;
    single.value = strtof_l_entry(input, &end, ignored_locale);
    if (single.bits != UINT32_C(0xc0400000) || end != input + expected_end ||
        errno != EINTR)
        return 1;
    end = NULL;
    paired.value = strtod_l_entry(input, &end, ignored_locale);
    if (paired.bits != UINT64_C(0xc008000000000000) ||
        end != input + expected_end || errno != EINTR)
        return 2;
    end = NULL;
    extended.value = strtold_l_entry(input, &end, ignored_locale);
    if (long_double_mantissa(&extended) != UINT64_C(0xc000000000000000) ||
        long_double_sign_exponent(&extended) != UINT16_C(0xc000) ||
        end != input + expected_end || errno != EINTR)
        return 3;

    end = NULL;
    single.value = internal_strtof_l_entry(input, &end, (locale_t)0);
    if (single.bits != UINT32_C(0xc0400000) || end != input + expected_end)
        return 4;
    end = NULL;
    paired.value = internal_strtod_l_entry(input, &end, (locale_t)0);
    if (paired.bits != UINT64_C(0xc008000000000000) ||
        end != input + expected_end)
        return 5;
    end = NULL;
    extended.value = internal_strtold_l_entry(input, &end, (locale_t)0);
    if (long_double_mantissa(&extended) != UINT64_C(0xc000000000000000) ||
        long_double_sign_exponent(&extended) != UINT16_C(0xc000) ||
        end != input + expected_end)
        return 6;
    if (internal_strtof_l_entry != strtof_l_entry)
        return 7;
    if (internal_strtod_l_entry != strtod_l_entry)
        return 8;
    if (internal_strtold_l_entry != strtold_l_entry)
        return 9;
    return 0;
}

static int check_wide_floating_conversions(void)
{
    static const wchar_t chunked[] =
        L"1.000000000000000000000000000000000000000000000000000000000000000000000tail";
    static const wchar_t unicode_space[] = { 0x2003, L'-', L'1', L'2', L'.', L'5', L'x', 0 };
    static const wchar_t non_ascii[] = { L'1', L'2', 0x00e9, L'3', L'4', 0 };
    wchar_t *end = NULL;
    float_bits single;
    double_bits paired;
    long_double_bits extended;
    size_t end_index;

    errno = EDOM;
    paired.value = wcstod_entry(chunked, &end);
    end_index = wide_string_length(chunked) - 4;
    if (paired.bits != UINT64_C(0x3ff0000000000000))
        return 1;
    if (end != chunked + end_index)
        return 2;
    if (errno != EDOM)
        return 3;

    end = NULL;
    single.value = wcstof_entry(unicode_space, &end);
    if (single.bits != UINT32_C(0xc1480000) || end != unicode_space + 6)
        return 2;
    end = NULL;
    paired.value = wcstod_entry(non_ascii, &end);
    if (paired.bits != UINT64_C(0x4028000000000000) || end != non_ascii + 2)
        return 3;
    end = NULL;
    extended.value = wcstold_entry(L"0x1.8p+1tail", &end);
    if (long_double_mantissa(&extended) != UINT64_C(0xc000000000000000) ||
        long_double_sign_exponent(&extended) != UINT16_C(0x4000) ||
        end != L"0x1.8p+1tail" + TEXT_END("0x1.8p+1"))
        return 4;
    return 0;
}

static int check_wide_integer_conversions(void)
{
    static const wchar_t chunked[] =
        L"0000000000000000000000000000000000000000000000000000000000000000000042tail";
    static const wchar_t overflow[] = L"18446744073709551616x";
    static const wchar_t malformed[] = L" +";
    wchar_t *end = NULL;

    errno = EINTR;
    if (wcstol_entry(chunked, &end, 10) != 42 ||
        end != chunked + wide_string_length(chunked) - 4 || errno != EINTR)
        return 1;
    end = NULL;
    if (wcstoul_entry(L"-1z", &end, 10) != (unsigned long)-1 ||
        end != L"-1z" + 2)
        return 2;
    end = NULL;
    if (wcstoll_entry(L"-9223372036854775808!", &end, 10) !=
            (-INT64_C(9223372036854775807) - 1) ||
        end != L"-9223372036854775808!" + 20)
        return 3;
    errno = EINTR;
    end = NULL;
    if (wcstoull_entry(overflow, &end, 10) != UINT64_MAX ||
        end != overflow + 20 || errno != ERANGE)
        return 4;
    end = NULL;
    if (wcstoimax_entry(L"0x7fffffffffffffff?", &end, 0) != INT64_MAX ||
        end != L"0x7fffffffffffffff?" + 18)
        return 5;
    end = NULL;
    if (wcstoumax_entry(L"0177?", &end, 0) != 127 || end != L"0177?" + 4)
        return 6;
    end = NULL;
    if (wcstoumax_entry(L"0b101?", &end, 0) != 0 || end != L"0b101?" + 1)
        return 7;
    errno = EINTR;
    end = NULL;
    if (wcstol_entry(malformed, &end, 10) != 0 || end != malformed ||
        errno != EINVAL)
        return 8;
    return 0;
}

static int check_legacy_decimal_conversions(void)
{
    char buffer[64];
    char *result;
    int decimal_point;
    int sign;

    result = ecvt_entry(12.5, 4, &decimal_point, &sign);
    if (!same_text(result, "1250"))
        return 1;
    if (decimal_point != 2)
        return 2;
    if (sign != 0)
        return 3;
    result = ecvt_entry(-0.03125, 4, &decimal_point, &sign);
    if (!same_text(result, "3125") || decimal_point != -1 || sign != 1)
        return 2;
    result = ecvt_entry(9.999, 3, &decimal_point, &sign);
    if (!same_text(result, "100") || decimal_point != 2 || sign != 0)
        return 3;
    result = ecvt_entry(1.25, 99, &decimal_point, &sign);
    if (!same_text(result, "125000000000000") || decimal_point != 1 || sign != 0)
        return 4;

    result = fcvt_entry(12.5, 3, &decimal_point, &sign);
    if (!same_text(result, "12500") || decimal_point != 2 || sign != 0)
        return 5;
    result = fcvt_entry(0.00126, 4, &decimal_point, &sign);
    if (!same_text(result, "13") || decimal_point != -2 || sign != 0)
        return 6;
    result = fcvt_entry(0.0001, 2, &decimal_point, &sign);
    if (!same_text(result, "000") || decimal_point != 1 || sign != 0)
        return 7;

    result = gcvt_entry(12345.0, 4, buffer);
    if (result != buffer || !same_text(buffer, "1.234e+04"))
        return 8;
    result = gcvt_entry(12.5, 6, buffer);
    if (result != buffer || !same_text(buffer, "12.5"))
        return 9;
    result = gcvt_entry(0.000012345, 4, buffer);
    if (result != buffer || !same_text(buffer, "1.234e-05"))
        return 10;
    return 0;
}

static int check_getsubopt(void)
{
    char options[] = "ro,size=42,unknown";
    char key_ro[] = "ro";
    char key_size[] = "size";
    char *keys[] = { key_ro, key_size, NULL };
    char *cursor = options;
    char *value = (char *)(uintptr_t)1;

    if (getsubopt_entry(&cursor, keys, &value) != 0 || value != NULL ||
        cursor != options + 3)
        return 1;
    if (getsubopt_entry(&cursor, keys, &value) != 1 ||
        !same_text(value, "42") || cursor != options + 11)
        return 2;
    value = (char *)(uintptr_t)1;
    if (getsubopt_entry(&cursor, keys, &value) != -1 || value != NULL ||
        *cursor != '\0')
        return 3;
    return 0;
}

int crabc_x86_64_float_parse_probe(void)
{
    const strtof_fn parse_float = strtof_entry;
    const strtod_fn parse_double = strtod_entry;
    const strtold_fn parse_long = strtold_entry;
    const atof_fn parse_atof = atof_entry;
    int status;

    status = check_decimal_and_end_pointer(parse_float, parse_double, parse_atof);
    if (status != 0)
        return status;
    status = check_special_forms(parse_float, parse_double);
    if (status != 0)
        return 140 + status;
    status = check_hex_syntax(parse_float, parse_double);
    if (status != 0)
        return 280 + status;
    status = check_range_and_boundary(parse_float, parse_double, parse_atof);
    if (status != 0)
        return 420 + status;
    status = check_binary80_abi(parse_long);
    if (status != 0)
        return 570 + status;
    status = check_exception_flags(parse_double);
    if (status != 0)
        return 760 + status;
    status = check_underflow_rounding_matrix(parse_float, parse_double,
        parse_long, parse_atof);
    if (status != 0)
        return 840 + status;
    status = check_rounding_modes(parse_float, parse_double);
    if (status != 0)
        return 1620 + status;
    status = check_locale_argument_aliases();
    if (status != 0)
        return 1700 + status;
    status = check_wide_floating_conversions();
    if (status != 0)
        return 1720 + status;
    status = check_wide_integer_conversions();
    if (status != 0)
        return 1740 + status;
    status = check_legacy_decimal_conversions();
    if (status != 0)
        return 1760 + status;
    status = check_getsubopt();
    return status == 0 ? 0 : 1780 + status;
}

#ifndef CRABC_FLOAT_PARSE_FREESTANDING
int main(void)
{
    return crabc_x86_64_float_parse_probe();
}
#endif
