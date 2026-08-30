/* Static x86-64 C locale and multibyte behavior fixture.
 *
 * The fixture deliberately stays within the retained named C/POSIX/C.UTF-8
 * profile. It exercises the stateful C ABI through project headers first,
 * then runs unchanged against pinned musl and the selected freestanding
 * crabc-libc archive candidate.
 */

#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(wchar_t) == 4, "x86 wchar_t width");
_Static_assert((wchar_t)-1 < 0, "x86 wchar_t signedness");
_Static_assert(CHAR_MAX == 127 && CHAR_MIN == -128,
    "x86 plain char is signed");
_Static_assert(sizeof(wint_t) == 4, "x86 wint_t width");
_Static_assert(sizeof(mbstate_t) == 8, "x86 mbstate_t size");
_Static_assert(_Alignof(mbstate_t) == 4, "x86 mbstate_t alignment");

static int text_equal(const char *left, const char *right)
{
    while (*left == *right) {
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
    return 0;
}

static int empty_text(const char *text)
{
    return text != NULL && text[0] == '\0';
}

static int check_lconv(void)
{
    struct lconv *value = localeconv();

    if (value == NULL || !text_equal(value->decimal_point, ".") ||
        !empty_text(value->thousands_sep) || !empty_text(value->grouping) ||
        !empty_text(value->int_curr_symbol) || !empty_text(value->currency_symbol) ||
        !empty_text(value->mon_decimal_point) ||
        !empty_text(value->mon_thousands_sep) || !empty_text(value->mon_grouping) ||
        !empty_text(value->positive_sign) || !empty_text(value->negative_sign))
        return 1;

    if (value->int_frac_digits != CHAR_MAX || value->frac_digits != CHAR_MAX ||
        value->p_cs_precedes != CHAR_MAX || value->p_sep_by_space != CHAR_MAX ||
        value->n_cs_precedes != CHAR_MAX || value->n_sep_by_space != CHAR_MAX ||
        value->p_sign_posn != CHAR_MAX || value->n_sign_posn != CHAR_MAX ||
        value->int_p_cs_precedes != CHAR_MAX ||
        value->int_p_sep_by_space != CHAR_MAX ||
        value->int_n_cs_precedes != CHAR_MAX ||
        value->int_n_sep_by_space != CHAR_MAX ||
        value->int_p_sign_posn != CHAR_MAX ||
        value->int_n_sign_posn != CHAR_MAX)
        return 2;
    return 0;
}

static int check_named_locale_selection(void)
{
    const char mixed[] = "C.UTF-8;C;C;C;C;C";
    char *name;
    int status;

    name = setlocale(LC_ALL, "C");
    if (name == NULL || !text_equal(name, "C") || MB_CUR_MAX != 1)
        return 1;
    if (!text_equal(setlocale(LC_ALL, NULL), "C"))
        return 2;
    status = check_lconv();
    if (status != 0)
        return 10 + status;

    name = setlocale(LC_CTYPE, "C.UTF-8");
    if (name == NULL || !text_equal(name, "C.UTF-8") || MB_CUR_MAX != 4)
        return 20;
    name = setlocale(LC_NUMERIC, "C.UTF-8");
    if (name == NULL || !text_equal(name, "C") || MB_CUR_MAX != 4)
        return 21;
    if (!text_equal(setlocale(LC_ALL, NULL), mixed))
        return 22;
    name = setlocale(LC_ALL, mixed);
    if (name == NULL || !text_equal(name, mixed) || MB_CUR_MAX != 4)
        return 23;
    if (!text_equal(setlocale(LC_TIME, NULL), "C"))
        return 24;
    if (!text_equal(setlocale(LC_CTYPE, "POSIX"), "C") || MB_CUR_MAX != 1)
        return 25;
    if (setlocale(LC_ALL, "C") == NULL || MB_CUR_MAX != 1)
        return 26;
    if (setlocale(LC_ALL + 1, "C") != NULL || MB_CUR_MAX != 1)
        return 27;
#ifdef CRABC_LOCALE_MULTIBYTE_FREESTANDING
    /*
     * The selected candidate admits a mixed LC_ALL value only in the exact
     * spelling it returns itself. Direct POSIX remains selected above, but
     * POSIX components and redundant six-component uniform forms are not
     * silently broadened into a general locale-name parser.
     */
    if (setlocale(LC_ALL, "POSIX;C;C;C;C;C") != NULL ||
        setlocale(LC_ALL, "C;C;C;C;C;C") != NULL ||
        setlocale(LC_ALL, "C;C.UTF-8;C;C;C;C") != NULL ||
        setlocale(LC_ALL,
            "C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8") != NULL)
        return 28;
    if (!text_equal(setlocale(LC_ALL, NULL), "C") || MB_CUR_MAX != 1)
        return 29;
#endif
    return 0;
}

static int check_c_locale_code_units(void)
{
    const char high[] = { (char)0x80, '\0' };
    char encoded[4] = { 0, 0, 0, 0 };
    wchar_t wide = 0;
    mbstate_t state = { 0, 0 };

    if (setlocale(LC_ALL, "C") == NULL || MB_CUR_MAX != 1)
        return 1;
    errno = EINTR;
    if (mbrtowc(&wide, high, 1, &state) != 1 || wide != 0xdf80 ||
        errno != EINTR || !mbsinit(&state))
        return 2;
    if (wcrtomb(encoded, 0xdf80, &state) != 1 ||
        (unsigned char)encoded[0] != 0x80)
        return 3;
    if (btowc(0x80) != 0xdf80 || btowc(256) != 0 ||
        wctob(0xdf80) != 0x80 || wctob(0x80) != EOF)
        return 4;
    errno = 0;
    if (wcrtomb(encoded, 0x80, &state) != (size_t)-1 || errno != EILSEQ)
        return 5;
    if (wcrtomb(NULL, 0x110000, &state) != 1)
        return 6;
    return 0;
}

static int check_utf8_single_character_state(void)
{
    const char smile[] = "\xf0\x9f\x98\x80";
    const char euro_lead[] = "\xe2";
    const char euro_tail[] = "\x82\xac";
    const char invalid_lead[] = "\xc0";
    const char overlong[] = "\xe0\x80\x80";
    const char ctype_utf8_all[] = "C.UTF-8;C;C;C;C;C";
    char encoded[5] = { 0, 0, 0, 0, 0 };
    char *name;
    wchar_t wide = 0;
    mbstate_t state = { 0, 0 };

    name = setlocale(LC_ALL, "C.UTF-8");
    if (name == NULL || !text_equal(name, ctype_utf8_all) || MB_CUR_MAX != 4)
        return 1;
    errno = EINTR;
    if (mbrtowc(&wide, smile, 4, &state) != 4 || wide != 0x1f600 ||
        errno != EINTR || !mbsinit(&state))
        return 2;
    if (wcrtomb(encoded, 0x1f600, &state) != 4 ||
        (unsigned char)encoded[0] != 0xf0 ||
        (unsigned char)encoded[1] != 0x9f ||
        (unsigned char)encoded[2] != 0x98 ||
        (unsigned char)encoded[3] != 0x80)
        return 3;

    if (mbrtowc(&wide, euro_lead, 1, &state) != (size_t)-2 || mbsinit(&state))
        return 4;
    if (mbrtowc(&wide, euro_tail, 2, &state) != 2 || wide != 0x20ac ||
        !mbsinit(&state))
        return 5;
    if (mbrtowc(&wide, euro_lead, 1, &state) != (size_t)-2)
        return 6;
    errno = 0;
    if (mbrtowc(&wide, NULL, 0, &state) != (size_t)-1 || errno != EILSEQ ||
        !mbsinit(&state))
        return 7;
    errno = 0;
    if (mbrtowc(&wide, invalid_lead, 1, &state) != (size_t)-1 || errno != EILSEQ ||
        !mbsinit(&state))
        return 8;
    errno = 0;
    if (mbrtowc(&wide, overlong, 3, &state) != (size_t)-1 || errno != EILSEQ)
        return 9;
    errno = 0;
    if (mbtowc(&wide, euro_lead, 1) != -1 || errno != EILSEQ)
        return 10;
    if (mbtowc(&wide, euro_tail, 2) != -1 || errno != EILSEQ)
        return 11;
    if (mblen(NULL, 0) != 0 || wctomb(NULL, 0x1f600) != 0)
        return 12;
    if (btowc(0x80) != WEOF || wctob(0x80) != EOF)
        return 13;
    errno = 0;
    if (wcrtomb(encoded, 0xd800, &state) != (size_t)-1 || errno != EILSEQ)
        return 14;

    if (mbrlen(euro_lead, 1, NULL) != (size_t)-2)
        return 15;
    errno = 0;
    if (mbrtowc(NULL, euro_tail, 2, NULL) != (size_t)-1 || errno != EILSEQ)
        return 16;
    if (mbrlen(euro_tail, 2, NULL) != 2)
        return 17;
    if (mbrtowc(NULL, euro_lead, 1, NULL) != (size_t)-2)
        return 18;
    errno = 0;
    if (mbrlen(euro_tail, 2, NULL) != (size_t)-1 || errno != EILSEQ)
        return 19;
    if (mbrtowc(&wide, euro_tail, 2, NULL) != 2 || wide != 0x20ac)
        return 20;
    return 0;
}

static int check_string_conversions(void)
{
    static const char utf8[] = "A\xe2\x82\xac";
    static const char invalid[] = "\xe2\x28";
    static const char euro_lead[] = "\xe2";
    static const char euro_tail[] = "\x82\xac";
    static const wchar_t wide[] = { L'A', 0x20ac, L'\0' };
    wchar_t decoded[4] = { 0, 0, 0, 0 };
    char encoded[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    const char *source;
    const wchar_t *wide_source;
    mbstate_t state = { 0, 0 };
    mbstate_t split_state = { 0, 0 };
    size_t result;

    source = utf8;
    result = mbsrtowcs(decoded, &source, 4, &state);
    if (result != 2 || source != NULL || decoded[0] != L'A' ||
        decoded[1] != 0x20ac || decoded[2] != L'\0' || !mbsinit(&state))
        return 1;

    source = utf8;
    result = mbsrtowcs(NULL, &source, 97, &state);
    if (result != 2 || source != utf8)
        return 2;

    source = utf8;
    decoded[0] = 0;
    result = mbsrtowcs(decoded, &source, 1, &state);
    if (result != 1 || source != utf8 + 1 || decoded[0] != L'A')
        return 3;

    source = invalid;
    errno = 0;
    if (mbsrtowcs(decoded, &source, 4, &state) != (size_t)-1 || errno != EILSEQ ||
        source != invalid)
        return 4;

    wide_source = wide;
    result = wcsrtombs(encoded, &wide_source, sizeof(encoded), &state);
    if (result != 4 || wide_source != NULL || encoded[0] != 'A' ||
        (unsigned char)encoded[1] != 0xe2 || (unsigned char)encoded[2] != 0x82 ||
        (unsigned char)encoded[3] != 0xac || encoded[4] != '\0')
        return 5;

    wide_source = wide;
    result = wcsrtombs(NULL, &wide_source, 97, &state);
    if (result != 4 || wide_source != wide)
        return 6;

    wide_source = wide;
    encoded[0] = encoded[1] = encoded[2] = (char)0x5a;
    result = wcsrtombs(encoded, &wide_source, 3, &state);
    if (result != 1 || wide_source != wide + 1 || encoded[0] != 'A' ||
        (unsigned char)encoded[1] != 0x5a || (unsigned char)encoded[2] != 0x5a)
        return 7;

    if (mbstowcs(decoded, utf8, 4) != 2 || decoded[0] != L'A' ||
        decoded[1] != 0x20ac || decoded[2] != L'\0')
        return 8;
    if (wcstombs(encoded, wide, sizeof(encoded)) != 4 || encoded[0] != 'A' ||
        (unsigned char)encoded[1] != 0xe2 || (unsigned char)encoded[2] != 0x82 ||
        (unsigned char)encoded[3] != 0xac || encoded[4] != '\0')
        return 9;

    if (mbrtowc(&decoded[0], euro_lead, 1, &split_state) != (size_t)-2 ||
        mbsinit(&split_state))
        return 10;
    source = euro_tail;
    decoded[0] = 0;
    result = mbsrtowcs(decoded, &source, 1, &split_state);
    if (result != 1 || source != euro_tail + 2 || decoded[0] != 0x20ac ||
        !mbsinit(&split_state))
        return 11;
    return 0;
}

int crabc_x86_64_locale_multibyte_probe(void)
{
    int status = check_named_locale_selection();

    if (status != 0)
        return status;
    status = check_c_locale_code_units();
    if (status != 0)
        return 40 + status;
    status = check_utf8_single_character_state();
    if (status != 0)
        return 80 + status;
    status = check_string_conversions();
    return status == 0 ? 0 : 180 + status;
}

#ifndef CRABC_LOCALE_MULTIBYTE_FREESTANDING
int main(void)
{
    return crabc_x86_64_locale_multibyte_probe();
}
#endif
