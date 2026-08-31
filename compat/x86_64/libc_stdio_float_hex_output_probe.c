/* Static x86-64 binary64 hexadecimal printf fixture.
 *
 * The shared C body runs first against pinned musl 1.2.6 and then the true
 * dependency-free crabc static candidate. It selects only C-locale `%a`/`%A`
 * byte-buffer output for promoted binary64 arguments; decimal floating,
 * long-double output, and positional directives remain outside this artifact.
 */

#include <errno.h>
#include <fenv.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(double) == 8, "x86 binary64 printf argument");
_Static_assert(sizeof(void *) == 8, "x86-64 SysV pointer width");
_Static_assert(INT_MAX == 2147483647, "x86 printf int return bound");

typedef int (*crabc_snprintf_signature)(char *, size_t, const char *, ...);
typedef int (*crabc_vsnprintf_signature)(char *, size_t, const char *, va_list);

#define CRABC_TYPE_IS(left, right) __builtin_types_compatible_p(left, right)
_Static_assert(CRABC_TYPE_IS(__typeof__(&snprintf), crabc_snprintf_signature),
    "snprintf declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&vsnprintf), crabc_vsnprintf_signature),
    "vsnprintf declaration");

static double double_from_bits(uint64_t bits)
{
    union {
        uint64_t bits;
        double value;
    } representation = { .bits = bits };

    return representation.value;
}

static size_t byte_length(const char *text)
{
    size_t length = 0;
    while (text[length] != '\0')
        ++length;
    return length;
}

static int equal_text(const char *actual, const char *expected)
{
    size_t index = 0;
    for (;;) {
        if (actual[index] != expected[index])
            return 0;
        if (actual[index] == '\0')
            return 1;
        ++index;
    }
}

static int call_vsnprintf(char *output, size_t size, const char *format, ...)
{
    va_list arguments;
    int result;

    va_start(arguments, format);
    result = vsnprintf(output, size, format, arguments);
    va_end(arguments);
    return result;
}

static int check_default_precision_and_rounding(void)
{
    static const char default_expected[] =
        "[0x1p+0][0X1.999999999999AP-4][+0x1p+0][ 0x1p+0][0x1.p+0]";
    static const char rounded_expected[] =
        "0x2.p+0|0x2p+0|0x1.8p+0|0x1.19ap+0|0x1.199999999999a0p+0";
    char output[160];
    int result;

    errno = EINTR;
    result = snprintf(output, sizeof(output), "[%a][%A][%+a][% a][%#a]",
        1.0, 0.1, 1.0, 1.0, 1.0);
    if (result != (int)byte_length(default_expected) ||
        !equal_text(output, default_expected) || errno != EINTR)
        return 1;

    errno = EDOM;
    result = snprintf(output, sizeof(output), "%#.0a|%.0a|%.1a|%.3a|%.14a",
        1.5, 1.5, 1.5, 1.1, 1.1);
    if (result != (int)byte_length(rounded_expected) ||
        !equal_text(output, rounded_expected) || errno != EDOM)
        return 2;

    result = snprintf(output, sizeof(output), "%la", 1.0);
    if (result != 6 || !equal_text(output, "0x1p+0"))
        return 3;

    return 0;
}

static int check_subnormal_special_width_and_truncation(void)
{
    static const char finite_expected[] =
        "[0x1p-1074][0x1p-1022][-0x0p+0]";
    static const char infinity_expected[] =
        "[inf][+inf][ inf][                 inf]";
    static const char nan_expected[] = "[nan][+nan][ nan][NAN]";
    char output[160];
    char small[12];
    double least_subnormal = double_from_bits(UINT64_C(0x0000000000000001));
    double least_normal = double_from_bits(UINT64_C(0x0010000000000000));
    double infinity = double_from_bits(UINT64_C(0x7ff0000000000000));
    double nan = double_from_bits(UINT64_C(0x7ff8000000000001));
    int result;

    errno = EILSEQ;
    result = snprintf(output, sizeof(output), "[%a][%a][%a]",
        least_subnormal, least_normal, -0.0);
    if (result != (int)byte_length(finite_expected) ||
        !equal_text(output, finite_expected) || errno != EILSEQ)
        return 1;

    errno = EINTR;
    result = snprintf(output, sizeof(output), "[%a][%+a][% a][%020a]",
        infinity, infinity, infinity, infinity);
    if (result != (int)byte_length(infinity_expected) ||
        !equal_text(output, infinity_expected) || errno != EINTR)
        return 2;

    errno = EDOM;
    result = snprintf(output, sizeof(output), "[%a][%+a][% a][%A]",
        nan, nan, nan, nan);
    if (result != (int)byte_length(nan_expected) ||
        !equal_text(output, nan_expected) || errno != EDOM)
        return 3;

    errno = EINTR;
    result = snprintf(small, sizeof(small), "[%020a]", 1.0);
    if (result != 22 || !equal_text(small, "[0x00000000") || errno != EINTR)
        return 4;

    return 0;
}

static int check_current_rounding_mode(void)
{
    struct rounding_case {
        int mode;
        const char *expected;
    };
    static const struct rounding_case cases[] = {
        { FE_TONEAREST, "0x2.p+0|0x1.2p+0|-0x2.p+0|-0x1.2p+0" },
        { FE_UPWARD, "0x2.p+0|0x1.2p+0|-0x1.p+0|-0x1.1p+0" },
        { FE_DOWNWARD, "0x1.p+0|0x1.1p+0|-0x2.p+0|-0x1.2p+0" },
        { FE_TOWARDZERO, "0x1.p+0|0x1.1p+0|-0x1.p+0|-0x1.1p+0" },
    };
    char output[96];
    int original = fegetround();
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        int result;

        if (fesetround(cases[index].mode) != 0)
            return 1;
        errno = EINTR;
        result = snprintf(output, sizeof(output), "%#.0a|%.1a|%#.0a|%.1a",
            1.5, 1.1, -1.5, -1.1);
        if (result != (int)byte_length(cases[index].expected) ||
            !equal_text(output, cases[index].expected) || errno != EINTR ||
            fegetround() != cases[index].mode) {
            (void)fesetround(original);
            return 2 + (int)index;
        }
    }
    if (fesetround(original) != 0 || fegetround() != original)
        return 6;

    return 0;
}

static int check_count_overflow_is_bounded(void)
{
    int result;

    errno = 0;
    result = snprintf(NULL, 0, "%.2147483647a", 1.0);
    if (result != -1 || errno != EOVERFLOW)
        return 1;

    return 0;
}

static int check_varargs_and_count_store(void)
{
    static const char forwarded_expected[] =
        "0x1p+0/0x1p+1/0x1.8p+1/0x1p+2/0x1.4p+2/0x1.8p+2/"
        "0x1.cp+2/0x1p+3/0x1.2p+3";
    static const char sequential_expected[] =
        "[          0x1.19ap+0/7/0x1p+1]";
    char output[192];
    int count = -1;
    int result;

    errno = EILSEQ;
    result = call_vsnprintf(output, sizeof(output), "%a/%a/%a/%a/%a/%a/%a/%a/%a",
        1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0);
    if (result != (int)byte_length(forwarded_expected) ||
        !equal_text(output, forwarded_expected) || errno != EILSEQ)
        return 1;

    errno = EDOM;
    result = snprintf(output, sizeof(output), "[%*.*a/%d/%la]",
        20, 3, 1.1, 7, 2.0);
    if (result != (int)byte_length(sequential_expected) ||
        !equal_text(output, sequential_expected) || errno != EDOM)
        return 2;

    errno = EINTR;
    result = snprintf(output, sizeof(output), "a%a%n", 1.0, &count);
    if (result != 7 || !equal_text(output, "a0x1p+0") || count != 7 ||
        errno != EINTR)
        return 3;

    return 0;
}

#ifdef CRABC_STDIO_FLOAT_HEX_OUTPUT_FREESTANDING
static int check_candidate_limitations(void)
{
    char output[32] = { 'X', '\0' };
    int result;

    errno = 0;
    result = snprintf(output, sizeof(output), "%f", 1.0);
    if (result != -1 || errno != EINVAL)
        return 1;

    errno = 0;
    result = snprintf(output, sizeof(output), "%La", 1.0L);
    if (result != -1 || errno != EINVAL)
        return 2;

    errno = 0;
    result = snprintf(output, sizeof(output), "%3$a", 1.0);
    if (result != -1 || errno != EINVAL)
        return 3;

    return 0;
}
#endif

int crabc_x86_64_stdio_float_hex_output_probe(void)
{
    int status = check_default_precision_and_rounding();
    if (status != 0)
        return status;
    status = check_subnormal_special_width_and_truncation();
    if (status != 0)
        return 100 + status;
    status = check_current_rounding_mode();
    if (status != 0)
        return 200 + status;
    status = check_count_overflow_is_bounded();
    if (status != 0)
        return 300 + status;
    status = check_varargs_and_count_store();
    if (status != 0)
        return 400 + status;
#ifdef CRABC_STDIO_FLOAT_HEX_OUTPUT_FREESTANDING
    status = check_candidate_limitations();
    if (status != 0)
        return 500 + status;
#endif
    return 0;
}

#ifndef CRABC_STDIO_FLOAT_HEX_OUTPUT_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_float_hex_output_probe();
}
#endif
