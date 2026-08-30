/* Static x86-64 floating-conversion behavior fixture.
 *
 * This fixture names only the allocation-free C-locale conversion boundary:
 * `strtof`, `strtod`, `strtold`, and `atof`.  Every entry is called through a
 * function pointer so a future freestanding archive cannot satisfy these
 * checks through a compiler builtin or an ambient C runtime.  In particular,
 * `strtold` is observed as its Linux/x86-64 SysV x87 binary80 result, not
 * narrowed through C `double` or Rust `f128`.
 *
 * Pinned behavior oracle: musl 1.2.6, commit 9fa28ece75d8a2191de7c5bb53bed224c5947417:
 * `src/stdlib/strtod.c` (`strtox`), `src/stdlib/atof.c` (`atof`), and
 * `src/internal/floatscan.c` (`__floatscan`, `decfloat`, and `hexfloat`).
 * The probe is an oracle-facing behavior fixture, not a source translation.
 */

#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <stdint.h>
#include <stdlib.h>

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
    return status == 0 ? 0 : 1620 + status;
}

#ifndef CRABC_FLOAT_PARSE_FREESTANDING
int main(void)
{
    return crabc_x86_64_float_parse_probe();
}
#endif
