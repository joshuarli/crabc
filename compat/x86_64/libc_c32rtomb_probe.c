/* Static Linux/x86-64 c32rtomb C ABI and behavior fixture.
 *
 * The same project-header body runs first through pinned musl 1.2.6 and then
 * through a small selected `-nostdlib -static` crabc archive. It proves only
 * musl src/multibyte/c32rtomb.c's direct forwarding into the already selected
 * fixed C/POSIX/C.UTF-8 wcrtomb profile: caller-owned mbstate_t is forwarded
 * unchanged, C/POSIX private code units stay byte-sized, C.UTF-8 scalars
 * encode as UTF-8, invalid scalars report EILSEQ, and a null output asks the
 * inherited wcrtomb reset query. It does not select UTF-16, decoding, locale
 * objects, environment lookup, databases, general locale, or wide streams.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <locale.h>
#include <uchar.h>

typedef size_t (*c32rtomb_signature)(char *, char32_t, mbstate_t *);

_Static_assert(sizeof(char32_t) == 4, "x86 char32_t is 32-bit");
_Static_assert(sizeof(mbstate_t) == 8, "x86 mbstate_t is eight bytes");
_Static_assert(__builtin_types_compatible_p(__typeof__(&c32rtomb), c32rtomb_signature),
    "c32rtomb declaration");

static void fill_bytes(unsigned char *bytes, size_t count, unsigned char value)
{
    size_t index;

    for (index = 0; index < count; ++index) bytes[index] = value;
}

static int bytes_are(const unsigned char *actual, const unsigned char *expected,
    size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        if (actual[index] != expected[index]) return 0;
    }
    return 1;
}

static int bytes_have_value(const unsigned char *bytes, size_t count,
    unsigned char value)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        if (bytes[index] != value) return 0;
    }
    return 1;
}

static int check_c_and_posix(c32rtomb_signature function)
{
    char output[4];
    mbstate_t state;
    static const unsigned char ascii[] = { 'A' };
    static const unsigned char private_80[] = { 0x80 };
    static const unsigned char private_ff[] = { 0xff };

    if (setlocale(LC_CTYPE, "C") == (char *)0) return 1;
    fill_bytes((unsigned char *)&state, sizeof state, 0xa5);
    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    errno = E2BIG;
    if (function(output, (char32_t)'A', &state) != 1 ||
        !bytes_are((const unsigned char *)output, ascii, sizeof ascii) ||
        !bytes_have_value((const unsigned char *)&state, sizeof state, 0xa5) ||
        errno != E2BIG) return 2;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    if (function(output, (char32_t)0xdf80, &state) != 1 ||
        !bytes_are((const unsigned char *)output, private_80, sizeof private_80) ||
        !bytes_have_value((const unsigned char *)&state, sizeof state, 0xa5)) return 3;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    errno = 0;
    if (function(output, (char32_t)0x80, &state) != (size_t)-1 || errno != EILSEQ ||
        !bytes_have_value((const unsigned char *)output, sizeof output, 0x5a) ||
        !bytes_have_value((const unsigned char *)&state, sizeof state, 0xa5)) return 4;

    if (setlocale(LC_CTYPE, "POSIX") == (char *)0) return 5;
    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    if (function(output, (char32_t)0xdfff, &state) != 1 ||
        !bytes_are((const unsigned char *)output, private_ff, sizeof private_ff) ||
        !bytes_have_value((const unsigned char *)&state, sizeof state, 0xa5)) return 6;

    return 0;
}

static int check_utf8(c32rtomb_signature function)
{
    char output[4];
    mbstate_t state;
    static const unsigned char sharp_s[] = { 0xc3, 0x9f };
    static const unsigned char banana[] = { 0xf0, 0x9f, 0x8d, 0x8c };

    if (setlocale(LC_CTYPE, "C.UTF-8") == (char *)0) return 1;
    fill_bytes((unsigned char *)&state, sizeof state, 0x3c);
    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    errno = E2BIG;
    if (function(output, (char32_t)0x00df, &state) != 2 ||
        !bytes_are((const unsigned char *)output, sharp_s, sizeof sharp_s) ||
        !bytes_have_value((const unsigned char *)&state, sizeof state, 0x3c) ||
        errno != E2BIG) return 2;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    if (function(output, (char32_t)0x1f34c, &state) != 4 ||
        !bytes_are((const unsigned char *)output, banana, sizeof banana) ||
        !bytes_have_value((const unsigned char *)&state, sizeof state, 0x3c)) return 3;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    errno = 0;
    if (function(output, (char32_t)0xd800, &state) != (size_t)-1 || errno != EILSEQ ||
        !bytes_have_value((const unsigned char *)output, sizeof output, 0x5a) ||
        !bytes_have_value((const unsigned char *)&state, sizeof state, 0x3c)) return 4;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    errno = 0;
    if (function(output, (char32_t)0x110000, &state) != (size_t)-1 || errno != EILSEQ ||
        !bytes_have_value((const unsigned char *)output, sizeof output, 0x5a) ||
        !bytes_have_value((const unsigned char *)&state, sizeof state, 0x3c)) return 5;

    errno = E2BIG;
    if (function((char *)0, (char32_t)0x110000, &state) != 1 || errno != E2BIG ||
        !bytes_have_value((const unsigned char *)&state, sizeof state, 0x3c)) return 6;

    return 0;
}

int crabc_x86_64_c32rtomb_probe(void)
{
    const c32rtomb_signature function = c32rtomb;
    int result;

    result = check_c_and_posix(function);
    if (result != 0) return result;
    result = check_utf8(function);
    if (result != 0) return 10 + result;
    return 0;
}

#ifndef CRABC_C32RTOMB_FREESTANDING
int main(void)
{
    return crabc_x86_64_c32rtomb_probe();
}
#endif
