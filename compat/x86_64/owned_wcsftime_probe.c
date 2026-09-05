/* One installed-header object for musl and the owned x86 wcsftime entries. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

extern size_t __wcsftime_l(wchar_t *restrict, size_t,
    const wchar_t *restrict, const struct tm *restrict, locale_t);

typedef size_t (*wcsftime_signature)(wchar_t *restrict, size_t,
    const wchar_t *restrict, const struct tm *restrict);
typedef size_t (*wcsftime_l_signature)(wchar_t *restrict, size_t,
    const wchar_t *restrict, const struct tm *restrict, locale_t);

_Static_assert(sizeof(wchar_t) == 4 && _Alignof(wchar_t) == 4,
    "native x86 wchar_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wcsftime),
    wcsftime_signature), "installed wcsftime declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wcsftime_l),
    wcsftime_l_signature), "installed wcsftime_l declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&__wcsftime_l),
    wcsftime_l_signature), "musl internal wcsftime_l declaration");

static wcsftime_signature public_wcsftime = wcsftime;
static wcsftime_l_signature public_wcsftime_l = wcsftime_l;
static wcsftime_l_signature internal_wcsftime_l = __wcsftime_l;
static locale_t selected_locale;

struct guarded_output {
    uint64_t before;
    wchar_t output[128];
    uint64_t after;
};

typedef size_t (*formatter)(wchar_t *, size_t, const wchar_t *,
    const struct tm *);

static void fail(void) { _Exit(127); }
#define CHECK(expression) do { if (!(expression)) fail(); } while (0)

static int wide_equal(const wchar_t *left, const wchar_t *right)
{
    while (*left || *right) {
        if (*left != *right) return 0;
        left++;
        right++;
    }
    return 1;
}

static unsigned checksum(const wchar_t *input, size_t count)
{
    unsigned result = 0;
    for (size_t index = 0; index != count; ++index)
        result = result * 33u + (unsigned)input[index];
    return result;
}

static size_t plain(wchar_t *output, size_t capacity, const wchar_t *format,
    const struct tm *time)
{
    return public_wcsftime(output, capacity, format, time);
}

static size_t localized(wchar_t *output, size_t capacity,
    const wchar_t *format, const struct tm *time)
{
    return public_wcsftime_l(output, capacity, format, time, selected_locale);
}

static size_t internal_localized(wchar_t *output, size_t capacity,
    const wchar_t *format, const struct tm *time)
{
    return internal_wcsftime_l(output, capacity, format, time, selected_locale);
}

static void observe(const char *entry, formatter format, const char *name,
    const wchar_t *input, size_t capacity, const struct tm *time,
    size_t expected_result, const wchar_t *expected_output)
{
    const wchar_t untouched = (wchar_t)0x55555555u;
    struct guarded_output guarded;
    memset(&guarded, 0x55, sizeof guarded);
    guarded.before = UINT64_C(0x0123456789abcdef);
    guarded.after = UINT64_C(0xfedcba9876543210);
    errno = EDOM;
    size_t result = format(capacity ? guarded.output : NULL, capacity, input, time);
    int error = errno;
    CHECK(guarded.before == UINT64_C(0x0123456789abcdef));
    CHECK(guarded.after == UINT64_C(0xfedcba9876543210));
    for (size_t index = capacity; index != sizeof guarded.output / sizeof *guarded.output; ++index)
        CHECK(guarded.output[index] == untouched);
    CHECK(result == expected_result);
    if (capacity) CHECK(wide_equal(guarded.output, expected_output));
    printf("%s %s n=%zu errno=%d checksum=%u\n", entry, name, result,
        error, checksum(guarded.output, sizeof guarded.output / sizeof *guarded.output));
}

static void run_suite(const char *entry, formatter format)
{
    const struct tm calendar = {
        .tm_sec = 5, .tm_min = 4, .tm_hour = 13, .tm_mday = 29,
        .tm_mon = 1, .tm_year = 124, .tm_wday = 4, .tm_yday = 59,
        .tm_isdst = 0, .tm_gmtoff = 0, .tm_zone = "UTC",
    };
    const struct tm extended_year = {
        .tm_year = 8100, .tm_isdst = 0, .tm_gmtoff = 0, .tm_zone = "UTC",
    };

    observe(entry, format, "zero", L"%Y", 0, &calendar, 0, L"");
    observe(entry, format, "calendar", L"%Y-%m-%d %H:%M:%S %z %Z%n%t%%",
        64, &calendar, 29, L"2024-02-29 13:04:05 +0000 \n\t%");
    observe(entry, format, "truncated", L"%Y", 4, &calendar, 0, L"202");
    observe(entry, format, "extended-year", L"%+5Y", 16, &extended_year,
        6, L"+10000");
    observe(entry, format, "invalid", L"pre%Qpost", 16, &calendar, 0, L"pre");
    observe(entry, format, "wide-literal", L"\u03a9%Y", 16, &calendar, 5,
        L"\u03a92024");
    observe(entry, format, "wide-conversion", L"pre%\u0141post", 16,
        &calendar, 0, L"pre");
}

int main(void)
{
    CHECK(setlocale(LC_ALL, "C.UTF-8") != NULL);
    CHECK(setenv("TZ", "UTC0", 1) == 0);
    tzset();
    selected_locale = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    CHECK(selected_locale != (locale_t)0);
    CHECK(public_wcsftime_l == internal_wcsftime_l);
    puts("wcsftime-alias-address-ok");

    run_suite("wcsftime", plain);
    run_suite("wcsftime_l", localized);
    run_suite("__wcsftime_l", internal_localized);

    freelocale(selected_locale);
    puts("wcsftime-ok");
    return 0;
}
