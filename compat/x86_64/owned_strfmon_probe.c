/* One installed-header object for musl and the owned x86 strfmon entries. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <locale.h>
#include <monetary.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef ssize_t (*strfmon_signature)(char *restrict, size_t,
    const char *restrict, ...);
typedef ssize_t (*strfmon_l_signature)(char *restrict, size_t, locale_t,
    const char *restrict, ...);

_Static_assert(sizeof(ssize_t) == sizeof(long), "native x86 ssize_t ABI");
_Static_assert(_Alignof(ssize_t) == _Alignof(long), "native x86 ssize_t alignment");
_Static_assert(sizeof(locale_t) == sizeof(void *), "native x86 locale_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strfmon),
    strfmon_signature), "installed strfmon declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strfmon_l),
    strfmon_l_signature), "installed strfmon_l declaration");

static strfmon_signature public_strfmon = strfmon;
static strfmon_l_signature public_strfmon_l = strfmon_l;

struct guarded_output {
    uint64_t before;
    unsigned char output[128];
    uint64_t after;
};

static void fail(void) { _Exit(127); }
#define CHECK(expression) do { if (!(expression)) fail(); } while (0)

static void initialize(struct guarded_output *guarded)
{
    memset(guarded, 0x55, sizeof *guarded);
    guarded->before = UINT64_C(0x0123456789abcdef);
    guarded->after = UINT64_C(0xfedcba9876543210);
}

static unsigned checksum(const unsigned char *input, size_t count)
{
    unsigned result = 0;
    for (size_t index = 0; index != count; ++index)
        result = result * 33u + input[index];
    return result;
}

static void record(const char *entry, const char *name, size_t capacity,
    ssize_t result, int error, const struct guarded_output *guarded)
{
    CHECK(guarded->before == UINT64_C(0x0123456789abcdef));
    CHECK(guarded->after == UINT64_C(0xfedcba9876543210));
    for (size_t index = capacity; index != sizeof guarded->output; ++index)
        CHECK(guarded->output[index] == 0x55);

    printf("%s %s n=%zd errno=%d checksum=%08x bytes=", entry, name,
        result, error, checksum(guarded->output, sizeof guarded->output));
    for (size_t index = 0; index != sizeof guarded->output; ++index)
        printf("%02x", guarded->output[index]);
    putchar('\n');
}

static void plain_cases(void)
{
    struct guarded_output guarded;
    ssize_t result;
    int error;

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon(NULL, 0, "%i", 1.0);
    error = errno;
    CHECK(result == 0 && error == EDOM);
    record("strfmon", "zero", 0, result, error, &guarded);

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon((char *)guarded.output, sizeof guarded.output,
        "A%#3.2i/B%7.0n/C%%", 12.5, -3.75);
    error = errno;
    CHECK(result >= 0 && error == EDOM);
    record("strfmon", "multiple", sizeof guarded.output, result, error, &guarded);

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon((char *)guarded.output, sizeof guarded.output,
        "%=0^(!-+12#4.3i|%+8.1n", 7.5, -8.25);
    error = errno;
    CHECK(result >= 0 && error == EDOM);
    record("strfmon", "flags-width-precision", sizeof guarded.output,
        result, error, &guarded);

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon((char *)guarded.output, sizeof guarded.output,
        "literal %% capacity");
    error = errno;
    CHECK(result >= 0 && error == EDOM);
    record("strfmon", "literal", sizeof guarded.output, result, error, &guarded);

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon((char *)guarded.output, 4, "ABCDE");
    error = errno;
    CHECK(result == 4 && error == EDOM);
    record("strfmon", "literal-boundary", 4, result, error, &guarded);

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon((char *)guarded.output, 4, "%i", 9.5);
    error = errno;
    CHECK(result == -1 && error == E2BIG);
    record("strfmon", "truncated", 4, result, error, &guarded);
}

static void localized_cases(locale_t c_locale, locale_t utf8_locale)
{
    struct guarded_output guarded;
    ssize_t result;
    int error;

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon_l(NULL, 0, c_locale, "%i", 1.0);
    error = errno;
    CHECK(result == 0 && error == EDOM);
    record("strfmon_l-c", "zero", 0, result, error, &guarded);

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon_l((char *)guarded.output, sizeof guarded.output,
        c_locale, "A%#3.2i/B%7.0n/C%%", 12.5, -3.75);
    error = errno;
    CHECK(result >= 0 && error == EDOM);
    record("strfmon_l-c", "multiple", sizeof guarded.output, result, error, &guarded);

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon_l((char *)guarded.output, sizeof guarded.output,
        utf8_locale, "%=0^(!-+12#4.3i|%+8.1n", 7.5, -8.25);
    error = errno;
    CHECK(result >= 0 && error == EDOM);
    record("strfmon_l-c-utf8", "flags-width-precision",
        sizeof guarded.output, result, error, &guarded);

    initialize(&guarded);
    errno = EDOM;
    result = public_strfmon_l((char *)guarded.output, 1, utf8_locale,
        "%i", 9.5);
    error = errno;
    CHECK(result == -1 && error == E2BIG);
    record("strfmon_l-c-utf8", "truncated", 1, result, error, &guarded);
}

int crabc_x86_64_owned_strfmon_probe(void)
{
    locale_t c_locale;
    locale_t utf8_locale;

    CHECK(setlocale(LC_ALL, "C.UTF-8") != NULL);
    c_locale = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    utf8_locale = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    CHECK(c_locale != (locale_t)0 && utf8_locale != (locale_t)0);

    plain_cases();
    localized_cases(c_locale, utf8_locale);

    freelocale(utf8_locale);
    freelocale(c_locale);
    puts("strfmon-ok");
    return 0;
}

#ifndef CRABC_OWNED_STRFMON_COMPONENT_FREESTANDING
int main(void)
{
    return crabc_x86_64_owned_strfmon_probe();
}
#endif
