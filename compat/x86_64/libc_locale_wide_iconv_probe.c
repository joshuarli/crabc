/* Static x86-64 named-locale, multibyte, and iconv behavior fixture.
 *
 * This fixture deliberately crosses only the selected fixed C/POSIX/C.UTF-8
 * locale state, ordinary multibyte conversion, and an explicit UTF/ASCII
 * iconv descriptor.  It runs unchanged against pinned musl first and then
 * against the dependency-free static candidate.  It is not a general locale
 * database, wide-stream, or legacy-codepage test.
 */

#include <errno.h>
#include <iconv.h>
#include <limits.h>
#include <locale.h>
#include <stddef.h>
#include <stdlib.h>
#include <wchar.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(iconv_t) == sizeof(void *), "x86 iconv_t pointer ABI");
_Static_assert(sizeof(wchar_t) == 4, "x86 wchar_t width");
_Static_assert(sizeof(mbstate_t) == 8, "x86 mbstate_t size");

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

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static int check_named_locale_and_multibyte(void)
{
    static const char mixed[] = "C.UTF-8;C;C;C;C;C";
    static const char euro[] = "\xe2\x82\xac";
    wchar_t wide = 0;
    mbstate_t state = { 0, 0 };
    char *name;

    name = setlocale(LC_ALL, "C.UTF-8");
    if (name == NULL || !text_equal(name, mixed) || MB_CUR_MAX != 4)
        return 1;
    errno = EINTR;
    if (mbrtowc(&wide, euro, sizeof(euro) - 1, &state) != 3 ||
        wide != 0x20ac || errno != EINTR || !mbsinit(&state))
        return 2;
    if (setlocale(LC_ALL, "C") == NULL || MB_CUR_MAX != 1)
        return 3;
    return 0;
}

static int check_utf_round_trips(void)
{
    static const unsigned char utf8[] = {
        'A', 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80,
    };
    static const unsigned char utf16le[] = {
        0x41, 0x00, 0xac, 0x20, 0x3d, 0xd8, 0x00, 0xde,
    };
    static const unsigned char utf16be[] = {
        0x00, 0x41, 0x20, 0xac, 0xd8, 0x3d, 0xde, 0x00,
    };
    unsigned char output[16] = { 0 };
    char *input;
    char *destination;
    size_t input_left;
    size_t output_left;
    iconv_t descriptor;

    descriptor = iconv_open("UTF-16LE", "UTF-8");
    if (descriptor == (iconv_t)-1)
        return 1;
    input = (char *)(void *)utf8;
    destination = (char *)(void *)output;
    input_left = sizeof(utf8);
    output_left = sizeof(output);
    errno = EINTR;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != 0 ||
        input != (char *)(void *)(utf8 + sizeof(utf8)) || input_left != 0 ||
        destination != (char *)(void *)(output + sizeof(utf16le)) ||
        output_left != sizeof(output) - sizeof(utf16le) ||
        !bytes_equal(output, utf16le, sizeof(utf16le)) || errno != EINTR ||
        iconv_close(descriptor) != 0)
        return 2;

    descriptor = iconv_open("UTF-8", "UTF-16BE");
    if (descriptor == (iconv_t)-1)
        return 3;
    input = (char *)(void *)utf16be;
    destination = (char *)(void *)output;
    input_left = sizeof(utf16be);
    output_left = sizeof(output);
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != 0 ||
        input != (char *)(void *)(utf16be + sizeof(utf16be)) || input_left != 0 ||
        destination != (char *)(void *)(output + sizeof(utf8)) ||
        output_left != sizeof(output) - sizeof(utf8) ||
        !bytes_equal(output, utf8, sizeof(utf8)) || iconv_close(descriptor) != 0)
        return 4;
    return 0;
}

static int check_fixed_utf32_and_name_normalization(void)
{
    static const unsigned char utf8[] = {
        0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80,
    };
    static const unsigned char utf32be[] = {
        0x00, 0x00, 0x20, 0xac, 0x00, 0x01, 0xf6, 0x00,
    };
    static const unsigned char utf32le[] = {
        0xac, 0x20, 0x00, 0x00, 0x00, 0xf6, 0x01, 0x00,
    };
    unsigned char output[16] = { 0 };
    char *input;
    char *destination;
    size_t input_left;
    size_t output_left;
    iconv_t descriptor;

    descriptor = iconv_open("Ut_F-32BE", "uTf_8");
    if (descriptor == (iconv_t)-1)
        return 1;
    input = (char *)(void *)utf8;
    destination = (char *)(void *)output;
    input_left = sizeof(utf8);
    output_left = sizeof(output);
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != 0 ||
        input_left != 0 || destination != (char *)(void *)(output + sizeof(utf32be)) ||
        !bytes_equal(output, utf32be, sizeof(utf32be)) ||
        iconv_close(descriptor) != 0)
        return 2;

    descriptor = iconv_open("UTF-8", "UCS-4LE");
    if (descriptor == (iconv_t)-1)
        return 3;
    input = (char *)(void *)utf32le;
    destination = (char *)(void *)output;
    input_left = sizeof(utf32le);
    output_left = sizeof(output);
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != 0 ||
        input_left != 0 || destination != (char *)(void *)(output + sizeof(utf8)) ||
        !bytes_equal(output, utf8, sizeof(utf8)) || iconv_close(descriptor) != 0)
        return 4;

    errno = EINTR;
    descriptor = iconv_open("", "CHAR");
    if (descriptor == (iconv_t)-1 || errno != EINTR || iconv_close(descriptor) != 0)
        return 5;

    errno = 0;
    if (iconv_open("UTF-8-", "UTF-8") != (iconv_t)-1 || errno != EINVAL)
        return 6;
    errno = 0;
    if (iconv_open("UTF:8", "UTF-8") != (iconv_t)-1 || errno != EINVAL)
        return 7;
    return 0;
}

static int check_wchar_and_ascii(void)
{
    static const unsigned char euro_utf8[] = { 0xe2, 0x82, 0xac };
    static const unsigned char euro_ascii[] = { '*' };
    wchar_t wide[] = { 0x20ac };
    unsigned char output[8] = { 0 };
    char *input;
    char *destination;
    size_t input_left;
    size_t output_left;
    iconv_t descriptor;

    descriptor = iconv_open("UTF-8", "WCHAR_T");
    if (descriptor == (iconv_t)-1)
        return 1;
    input = (char *)(void *)wide;
    destination = (char *)(void *)output;
    input_left = sizeof(wide);
    output_left = sizeof(output);
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != 0 ||
        input_left != 0 || !bytes_equal(output, euro_utf8, sizeof(euro_utf8)) ||
        iconv_close(descriptor) != 0)
        return 2;

    descriptor = iconv_open("ASCII", "UTF-8");
    if (descriptor == (iconv_t)-1)
        return 3;
    input = (char *)(void *)euro_utf8;
    destination = (char *)(void *)output;
    input_left = sizeof(euro_utf8);
    output_left = sizeof(output);
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != 1 ||
        input_left != 0 || !bytes_equal(output, euro_ascii, sizeof(euro_ascii)) ||
        iconv_close(descriptor) != 0)
        return 4;
    return 0;
}

static int check_error_progress_and_boundary(void)
{
    static const unsigned char invalid[] = { 0xc0 };
    static const unsigned char incomplete[] = { 0xe2 };
    static const unsigned char progress[] = { 'A', 0xc0 };
    static const unsigned char ascii[] = { 'A' };
    static const unsigned char invalid_utf16le[] = { 0x00, 0xdc };
    static const unsigned char incomplete_utf16le[] = { 0x00, 0xd8 };
    static const unsigned char invalid_utf32le[] = { 0x00, 0x00, 0x11, 0x00 };
    unsigned char output[8] = { 0 };
    char *input;
    char *destination;
    size_t input_left;
    size_t output_left;
    iconv_t descriptor;

    errno = 0;
    if (iconv_open("not-an-encoding", "UTF-8") != (iconv_t)-1 || errno != EINVAL)
        return 1;

    descriptor = iconv_open("UTF-16LE", "UTF-8");
    if (descriptor == (iconv_t)-1)
        return 2;
    input = (char *)(void *)invalid;
    destination = (char *)(void *)output;
    input_left = sizeof(invalid);
    output_left = sizeof(output);
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) !=
            (size_t)-1 ||
        errno != EILSEQ || input != (char *)(void *)invalid ||
        input_left != sizeof(invalid) || destination != (char *)(void *)output ||
        output_left != sizeof(output))
        return 3;

    input = (char *)(void *)incomplete;
    destination = (char *)(void *)output;
    input_left = sizeof(incomplete);
    output_left = sizeof(output);
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) !=
            (size_t)-1 ||
        errno != EINVAL || input != (char *)(void *)incomplete ||
        input_left != sizeof(incomplete) || destination != (char *)(void *)output ||
        output_left != sizeof(output))
        return 4;

    input = (char *)(void *)progress;
    destination = (char *)(void *)output;
    input_left = sizeof(progress);
    output_left = sizeof(output);
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) !=
            (size_t)-1 ||
        errno != EILSEQ || input != (char *)(void *)(progress + 1) ||
        input_left != 1 || destination != (char *)(void *)(output + 2) ||
        output_left != sizeof(output) - 2 || output[0] != 'A' || output[1] != 0)
        return 5;

    input = (char *)(void *)ascii;
    destination = (char *)(void *)output;
    input_left = sizeof(ascii);
    output_left = 1;
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) !=
            (size_t)-1 ||
        errno != E2BIG || input != (char *)(void *)ascii || input_left != 1 ||
        destination != (char *)(void *)output || output_left != 1)
        return 6;

    errno = EINTR;
    if (iconv(descriptor, NULL, NULL, NULL, NULL) != 0 || errno != EINTR ||
        iconv_close(descriptor) != 0)
        return 7;

    descriptor = iconv_open("UTF-8", "UTF-16LE");
    if (descriptor == (iconv_t)-1)
        return 8;
    input = (char *)(void *)invalid_utf16le;
    destination = (char *)(void *)output;
    input_left = sizeof(invalid_utf16le);
    output_left = sizeof(output);
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) !=
            (size_t)-1 ||
        errno != EILSEQ || input != (char *)(void *)invalid_utf16le ||
        input_left != sizeof(invalid_utf16le) ||
        destination != (char *)(void *)output || output_left != sizeof(output))
        return 9;
    input = (char *)(void *)incomplete_utf16le;
    destination = (char *)(void *)output;
    input_left = sizeof(incomplete_utf16le);
    output_left = sizeof(output);
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) !=
            (size_t)-1 ||
        errno != EINVAL || input != (char *)(void *)incomplete_utf16le ||
        input_left != sizeof(incomplete_utf16le) ||
        destination != (char *)(void *)output || output_left != sizeof(output) ||
        iconv_close(descriptor) != 0)
        return 10;

    descriptor = iconv_open("UTF-8", "UTF-32LE");
    if (descriptor == (iconv_t)-1)
        return 11;
    input = (char *)(void *)invalid_utf32le;
    destination = (char *)(void *)output;
    input_left = sizeof(invalid_utf32le);
    output_left = sizeof(output);
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) !=
            (size_t)-1 ||
        errno != EILSEQ || input != (char *)(void *)invalid_utf32le ||
        input_left != sizeof(invalid_utf32le) ||
        destination != (char *)(void *)output || output_left != sizeof(output) ||
        iconv_close(descriptor) != 0)
        return 12;

#ifdef CRABC_LOCALE_WIDE_ICONV_FREESTANDING
    errno = 0;
    if (iconv_open("ISO-8859-1", "UTF-8") != (iconv_t)-1 || errno != EINVAL)
        return 13;
    errno = 0;
    if (iconv_open("UTF-16", "UTF-8") != (iconv_t)-1 || errno != EINVAL)
        return 14;
    errno = 0;
    if (iconv_open("UCS-2LE", "UTF-8") != (iconv_t)-1 || errno != EINVAL)
        return 15;
#endif
    return 0;
}

int crabc_x86_64_locale_wide_iconv_probe(void)
{
    int status = check_named_locale_and_multibyte();

    if (status != 0)
        return status;
    status = check_utf_round_trips();
    if (status != 0)
        return 20 + status;
    status = check_fixed_utf32_and_name_normalization();
    if (status != 0)
        return 30 + status;
    status = check_wchar_and_ascii();
    if (status != 0)
        return 40 + status;
    status = check_error_progress_and_boundary();
    return status == 0 ? 0 : 80 + status;
}

#ifndef CRABC_LOCALE_WIDE_ICONV_FREESTANDING
int main(void)
{
    return crabc_x86_64_locale_wide_iconv_probe();
}
#endif
