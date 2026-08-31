/* Static x86-64 byte-string stdio format/scan behavior fixture.
 *
 * The fixture deliberately exercises only the closed no-FILE slice owned by
 * libc/src/c_abi/x86_64/stdio_format_scan.rs.  Its shared body first runs
 * against pinned musl, then runs as a true -nostdlib static candidate whose
 * extra checks ratchet deliberate rejections.  No fixture helper calls an
 * ambient formatting, scanning, allocation, or string API.
 */

#include <errno.h>
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

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(long long) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(size_t) == 8, "x86 size_t width");

typedef int (*crabc_snprintf_signature)(char *, size_t, const char *, ...);
typedef int (*crabc_vsnprintf_signature)(char *, size_t, const char *, va_list);
typedef int (*crabc_sprintf_signature)(char *, const char *, ...);
typedef int (*crabc_vsprintf_signature)(char *, const char *, va_list);
typedef int (*crabc_sscanf_signature)(const char *, const char *, ...);
typedef int (*crabc_vsscanf_signature)(const char *, const char *, va_list);

#define CRABC_TYPE_IS(left, right) __builtin_types_compatible_p(left, right)
_Static_assert(CRABC_TYPE_IS(__typeof__(&snprintf), crabc_snprintf_signature),
    "snprintf declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&vsnprintf), crabc_vsnprintf_signature),
    "vsnprintf declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&sprintf), crabc_sprintf_signature),
    "sprintf declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&vsprintf), crabc_vsprintf_signature),
    "vsprintf declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&sscanf), crabc_sscanf_signature),
    "sscanf declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&vsscanf), crabc_vsscanf_signature),
    "vsscanf declaration");

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

static int call_vsprintf(char *output, const char *format, ...)
{
    va_list arguments;
    int result;

    va_start(arguments, format);
    result = vsprintf(output, format, arguments);
    va_end(arguments);
    return result;
}

static int call_vsscanf(const char *input, const char *format, ...)
{
    va_list arguments;
    int result;

    va_start(arguments, format);
    result = vsscanf(input, format, arguments);
    va_end(arguments);
    return result;
}

static int check_formatting(void)
{
    static const char expected[] =
        "id=-00042 hex=0x2a oct=011 word=alp   char=Z %";
    char output[128];
    char truncated[5];
    char variadic[32];
    char full[64];
    char edge[64];
    char one[1] = { 'X' };
    signed char narrow_count = -1;
    long wide_count = -1;
    int overflow_count = 123;
    int result;

    errno = EINTR;
    result = snprintf(output, sizeof(output),
        "id=%+06d hex=%#x oct=%#o word=%-5.3s char=%c %%",
        -42, 0x2aU, 9U, "alpha", 'Z');
    if (result != (int)byte_length(expected) || !equal_text(output, expected))
        return 1;
    if (errno != EINTR)
        return 2;

    errno = EDOM;
    result = snprintf(truncated, sizeof(truncated), "abcdef");
    if (result != 6 || !equal_text(truncated, "abcd") || errno != EDOM)
        return 3;

    errno = EILSEQ;
    result = snprintf((char *)0, 0, "[%d]", 42);
    if (result != 4 || errno != EILSEQ)
        return 4;

    errno = EINTR;
    result = call_vsnprintf(variadic, sizeof(variadic), "[%0*d/%.*s]",
        5, 7, 2, "xyz");
    if (result != 10 || !equal_text(variadic, "[00007/xy]") || errno != EINTR)
        return 5;

    errno = EDOM;
    result = sprintf(full, "%hhd/%lld/%zu", -7, 1234567890123LL, (size_t)9);
    if (result != 18 || !equal_text(full, "-7/1234567890123/9") || errno != EDOM)
        return 6;

    errno = EILSEQ;
    result = call_vsprintf(full, "%#08x", 0x2aU);
    if (result != 8 || !equal_text(full, "0x00002a") || errno != EILSEQ)
        return 7;

    errno = EDOM;
    result = snprintf(edge, sizeof(edge), "%#x|%#.3o|%#.0o|%08.3d",
        0U, 1U, 0U, 7);
    if (result != 16 || !equal_text(edge, "0|001|0|     007") || errno != EDOM)
        return 8;

    errno = EINTR;
    result = snprintf(edge, sizeof(edge), "ab%hhncd%ln",
        &narrow_count, &wide_count);
    if (result != 4 || !equal_text(edge, "abcd") || narrow_count != 2 ||
        wide_count != 4 || errno != EINTR)
        return 9;

    errno = EILSEQ;
    result = snprintf(one, sizeof(one), "xy");
    if (result != 2 || one[0] != '\0' || errno != EILSEQ)
        return 10;

    errno = EDOM;
    result = call_vsnprintf(edge, sizeof(edge), "[%*.*d]", -5, -1, 7);
    if (result != 7 || !equal_text(edge, "[7    ]") || errno != EDOM)
        return 11;

    errno = 0;
    one[0] = 'X';
    result = snprintf(one, sizeof(one), "%2147483648d%n", 7, &overflow_count);
    if (result != -1 || one[0] != '\0' || overflow_count != 123 ||
        errno != EOVERFLOW)
        return 12;

    return 0;
}

static int check_scanning(void)
{
    int decimal = 0;
    int automatic = 0;
    unsigned int octal = 0;
    unsigned int decimal_unsigned = 0;
    unsigned int hexadecimal = 0;
    unsigned int negative_unsigned = 0;
    signed char narrow_signed = 0;
    unsigned short narrow_unsigned = 0;
    long long wide_signed = 0;
    size_t sized = 0;
    char word[8] = { 0 };
    char character = '\0';
    char chars[3] = { 0, 0, 0 };
    char partial_chars[2] = { 'X', 'Y' };
    int consumed = -1;
    int untouched = 123;
    long long_count = 0;
    intmax_t intmax_count = 0;
    ptrdiff_t difference_count = 0;
    int result;

    errno = EINTR;
    result = sscanf(" -42 0x2a 075 word Q", "%d %i %o %4s %c",
        &decimal, &automatic, &octal, word, &character);
    if (result != 5 || decimal != -42 || automatic != 42 || octal != 61 ||
        !equal_text(word, "word") || character != 'Q' || errno != EINTR)
        return 1;

    errno = EDOM;
    result = call_vsscanf("7 ignored 0x10", "%u %*s %x",
        &decimal_unsigned, &hexadecimal);
    if (result != 2 || decimal_unsigned != 7U || hexadecimal != 16U || errno != EDOM)
        return 2;

    result = sscanf("xyz", "%3c", chars);
    if (result != 1 || chars[0] != 'x' || chars[1] != 'y' || chars[2] != 'z')
        return 3;

    result = sscanf("12ab", "%2u%n", &decimal_unsigned, &consumed);
    if (result != 1 || decimal_unsigned != 12U || consumed != 2)
        return 4;

    result = sscanf("-1", "%u", &negative_unsigned);
    if (result != 1 || negative_unsigned != UINT_MAX)
        return 5;

    result = sscanf("-7 65535 1234567890123 9", "%hhd %hu %lld %zu",
        &narrow_signed, &narrow_unsigned, &wide_signed, &sized);
    if (result != 4 || narrow_signed != -7 || narrow_unsigned != 65535U ||
        wide_signed != 1234567890123LL || sized != (size_t)9)
        return 6;

    result = sscanf("24,2a", "%d,%x", &decimal, &hexadecimal);
    if (result != 2 || decimal != 24 || hexadecimal != 42U)
        return 7;

    result = sscanf("x", "%d", &untouched);
    if (result != 0 || untouched != 123)
        return 8;

    result = sscanf("", "%d", &decimal);
    if (result != EOF)
        return 9;

    errno = EILSEQ;
    hexadecimal = 99U;
    result = sscanf("0xg", "%x", &hexadecimal);
    if (result != 0 || hexadecimal != 99U || errno != EILSEQ)
        return 10;

    errno = EDOM;
    hexadecimal = 99U;
    result = sscanf("0x1", "%2x", &hexadecimal);
    if (result != 0 || hexadecimal != 99U || errno != EDOM)
        return 11;

    character = '\0';
    result = sscanf(" %Q", "%%%c", &character);
    if (result != 1 || character != 'Q')
        return 12;

    result = sscanf("8 9 10", "%ld %jd %td",
        &long_count, &intmax_count, &difference_count);
    if (result != 3 || long_count != 8 || intmax_count != 9 ||
        difference_count != 10)
        return 13;

    result = sscanf("a", "%2c", partial_chars);
    if (result != 0 || partial_chars[0] != 'a' || partial_chars[1] != 'Y')
        return 14;

    return 0;
}

#ifdef CRABC_STDIO_FORMAT_SCAN_FREESTANDING
static int check_candidate_limitations(void)
{
    char output[32] = { 'X', '\0' };
    float floating = 91.0F;
    void *pointer = (void *)0;
    int result;

    errno = 0;
    result = snprintf(output, sizeof(output), "%f", 1.0);
    if (result != -1 || errno != EINVAL)
        return 1;

    errno = 0;
    result = snprintf(output, sizeof(output), "%p", (void *)(uintptr_t)1);
    if (result != -1 || errno != EINVAL)
        return 2;

    errno = 0;
    result = snprintf(output, sizeof(output), "%2$d", 1, 2);
    if (result != -1 || errno != EINVAL)
        return 3;

    errno = 0;
    result = sscanf("1.0", "%f", &floating);
    if (result != 0 || floating != 91.0F || errno != EINVAL)
        return 4;

    errno = 0;
    result = sscanf("abc", "%[a-z]", output);
    if (result != 0 || errno != EINVAL)
        return 5;

    errno = 0;
    result = sscanf("0x1", "%p", &pointer);
    if (result != 0 || pointer != (void *)0 || errno != EINVAL)
        return 6;

    return 0;
}
#endif

int crabc_x86_64_stdio_format_scan_probe(void)
{
    int status = check_formatting();
    if (status != 0)
        return status;
    status = check_scanning();
    if (status != 0)
        return 100 + status;
#ifdef CRABC_STDIO_FORMAT_SCAN_FREESTANDING
    status = check_candidate_limitations();
    if (status != 0)
        return 200 + status;
#endif
    return 0;
}

#ifndef CRABC_STDIO_FORMAT_SCAN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_format_scan_probe();
}
#endif
