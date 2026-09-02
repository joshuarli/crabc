/* Static Linux/x86-64 C11 stateful <uchar.h> behavior fixture.
 *
 * The same project-header body first runs through pinned musl 1.2.6 and then
 * a one-module-selected, true -nostdlib/-static crabc archive closure. It
 * covers only musl's c16rtomb/mbrtoc16/mbrtoc32 source state machines and
 * their deliberately direct mbrtowc/wcrtomb dependency seam: C/POSIX private
 * code units, C.UTF-8 2/3/4-byte decoding, every-byte partial input, UTF-16
 * pending-low sequencing, null state separation, stale errno, and error
 * reset/output rules. It is not a broader locale, wide stream, or iconv test.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <locale.h>
#include <uchar.h>

typedef size_t (*c16rtomb_signature)(char *, char16_t, mbstate_t *);
typedef size_t (*mbrtoc16_signature)(char16_t *, const char *, size_t, mbstate_t *);
typedef size_t (*mbrtoc32_signature)(char32_t *, const char *, size_t, mbstate_t *);

_Static_assert(sizeof(char16_t) == 2, "x86 char16_t is 16-bit");
_Static_assert(sizeof(char32_t) == 4, "x86 char32_t is 32-bit");
_Static_assert(sizeof(mbstate_t) == 8, "x86 mbstate_t is eight bytes");
_Static_assert(__builtin_types_compatible_p(__typeof__(&c16rtomb), c16rtomb_signature),
    "c16rtomb declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mbrtoc16), mbrtoc16_signature),
    "mbrtoc16 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mbrtoc32), mbrtoc32_signature),
    "mbrtoc32 declaration");

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

static void set_state(mbstate_t *state, unsigned first, unsigned second)
{
    state->__opaque1 = first;
    state->__opaque2 = second;
}

static int state_is(const mbstate_t *state, unsigned first, unsigned second)
{
    return state->__opaque1 == first && state->__opaque2 == second;
}

static int check_c_and_posix_code_units(c16rtomb_signature encode,
    mbrtoc16_signature decode16, mbrtoc32_signature decode32)
{
    const char byte_80[] = { (char)0x80 };
    const char byte_ff[] = { (char)0xff };
    static const unsigned char expected_80[] = { 0x80 };
    static const unsigned char expected_ff[] = { 0xff };
    char output[4];
    char16_t output16;
    char32_t output32;
    mbstate_t state;

    if (setlocale(LC_CTYPE, "C") == (char *)0) return 1;
    set_state(&state, 0, 0xa5a5a5a5u);
    output16 = 0xbeefu;
    errno = E2BIG;
    if (decode16(&output16, byte_80, 1, &state) != 1 || output16 != 0xdf80u ||
        !state_is(&state, 0, 0xa5a5a5a5u) || errno != E2BIG) return 2;

    set_state(&state, 0, 0x5a5a5a5au);
    output32 = 0xdeadbeefu;
    if (decode32(&output32, byte_ff, 1, &state) != 1 || output32 != 0xdfffu ||
        !state_is(&state, 0, 0x5a5a5a5au)) return 3;

    set_state(&state, 0, 0x3c3c3c3cu);
    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    if (encode(output, (char16_t)0xdf80, &state) != 1 ||
        !bytes_are((const unsigned char *)output, expected_80, sizeof expected_80) ||
        !state_is(&state, 0, 0x3c3c3c3cu)) return 4;

    if (setlocale(LC_CTYPE, "POSIX") == (char *)0) return 5;
    set_state(&state, 0, 0x69696969u);
    output16 = 0xbeefu;
    if (decode16(&output16, byte_ff, 1, &state) != 1 || output16 != 0xdfffu ||
        !state_is(&state, 0, 0x69696969u)) return 6;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    if (encode(output, (char16_t)0xdfff, &state) != 1 ||
        !bytes_are((const unsigned char *)output, expected_ff, sizeof expected_ff) ||
        !state_is(&state, 0, 0x69696969u)) return 7;

    return 0;
}

static int check_mbrtoc32_split(mbrtoc32_signature decode32, const char *bytes,
    size_t count, char32_t expected)
{
    mbstate_t state;
    char32_t output = 0xdeadbeefu;
    size_t index;

    set_state(&state, 0, 0x12345678u);
    for (index = 0; index < count; ++index) {
        size_t result = decode32(&output, bytes + index, 1, &state);

        if (index + 1 < count) {
            if (result != (size_t)-2 || output != 0xdeadbeefu ||
                state.__opaque1 == 0 || state.__opaque2 != 0x12345678u) return 1;
        } else if (result != 1 || output != expected ||
            !state_is(&state, 0, 0x12345678u)) {
            return 2;
        }
    }
    return 0;
}

static int check_mbrtoc16_split(mbrtoc16_signature decode16, const char *bytes,
    size_t count, char16_t expected_high, char16_t expected_low)
{
    mbstate_t state;
    char16_t output = 0xbeefu;
    size_t index;

    set_state(&state, 0, 0x87654321u);
    for (index = 0; index < count; ++index) {
        size_t result = decode16(&output, bytes + index, 1, &state);

        if (index + 1 < count) {
            if (result != (size_t)-2 || output != 0xbeefu ||
                state.__opaque1 == 0 || state.__opaque2 != 0x87654321u) return 1;
        } else if (result != 1 || output != expected_high ||
            state.__opaque2 != 0x87654321u) {
            return 2;
        }
    }
    if (expected_low != 0) {
        output = 0xbeefu;
        if (decode16(&output, (const char *)1, (size_t)-1, &state) != (size_t)-3 ||
            output != expected_low || !state_is(&state, 0, 0x87654321u)) return 3;
    } else if (!state_is(&state, 0, 0x87654321u)) {
        return 4;
    }
    return 0;
}

static int check_utf8_decoding(mbrtoc16_signature decode16,
    mbrtoc32_signature decode32)
{
    static const char sharp_s[] = { (char)0xc3, (char)0x9f };
    static const char euro[] = { (char)0xe2, (char)0x82, (char)0xac };
    static const char banana[] = { (char)0xf0, (char)0x9f, (char)0x8d, (char)0x8c };
    mbstate_t state;
    char16_t output16;
    char32_t output32;
    int status;

    if (setlocale(LC_CTYPE, "C.UTF-8") == (char *)0) return 1;
    set_state(&state, 0, 0x11111111u);
    output16 = 0xbeefu;
    errno = E2BIG;
    if (decode16(&output16, "A", 1, &state) != 1 || output16 != (char16_t)'A' ||
        !state_is(&state, 0, 0x11111111u) || errno != E2BIG) return 2;

    set_state(&state, 0, 0x22222222u);
    output16 = 0xbeefu;
    if (decode16(&output16, sharp_s, sizeof sharp_s, &state) != 2 ||
        output16 != 0x00dfu || !state_is(&state, 0, 0x22222222u)) return 3;
    output16 = 0xbeefu;
    if (decode16(&output16, euro, sizeof euro, &state) != 3 ||
        output16 != 0x20acu || !state_is(&state, 0, 0x22222222u)) return 4;

    set_state(&state, 0, 0x33333333u);
    output16 = 0xbeefu;
    if (decode16(&output16, banana, sizeof banana, &state) != 4 ||
        output16 != 0xd83cu || !state_is(&state, 0xdf4cu, 0x33333333u)) return 5;

    output16 = 0xbeefu;
    if (decode16(&output16, (const char *)0, 0, &state) != (size_t)-3 ||
        output16 != 0xbeefu || !state_is(&state, 0, 0x33333333u)) return 6;

    set_state(&state, 0, 0x44444444u);
    output32 = 0xdeadbeefu;
    if (decode32(&output32, sharp_s, sizeof sharp_s, &state) != 2 ||
        output32 != 0x00dfu || !state_is(&state, 0, 0x44444444u)) return 7;
    output32 = 0xdeadbeefu;
    if (decode32(&output32, euro, sizeof euro, &state) != 3 ||
        output32 != 0x20acu || !state_is(&state, 0, 0x44444444u)) return 8;
    output32 = 0xdeadbeefu;
    if (decode32(&output32, banana, sizeof banana, &state) != 4 ||
        output32 != 0x1f34cu || !state_is(&state, 0, 0x44444444u)) return 9;

    status = check_mbrtoc32_split(decode32, sharp_s, sizeof sharp_s, 0x00dfu);
    if (status != 0) return 20 + status;
    status = check_mbrtoc32_split(decode32, euro, sizeof euro, 0x20acu);
    if (status != 0) return 30 + status;
    status = check_mbrtoc32_split(decode32, banana, sizeof banana, 0x1f34cu);
    if (status != 0) return 40 + status;

    status = check_mbrtoc16_split(decode16, sharp_s, sizeof sharp_s, 0x00dfu, 0);
    if (status != 0) return 50 + status;
    status = check_mbrtoc16_split(decode16, euro, sizeof euro, 0x20acu, 0);
    if (status != 0) return 60 + status;
    status = check_mbrtoc16_split(decode16, banana, sizeof banana, 0xd83cu, 0xdf4cu);
    if (status != 0) return 70 + status;

    return 0;
}

static int check_decode_null_and_pending(mbrtoc16_signature decode16,
    mbrtoc32_signature decode32)
{
    static const char banana[] = { (char)0xf0, (char)0x9f, (char)0x8d, (char)0x8c };
    static const char euro_lead[] = { (char)0xe2 };
    mbstate_t state;
    char16_t output16;
    char32_t output32;

    set_state(&state, 0, 0x51515151u);
    output16 = 0xbeefu;
    errno = E2BIG;
    if (decode16(&output16, (const char *)0, 0, &state) != 0 || output16 != 0xbeefu ||
        !state_is(&state, 0, 0x51515151u) || errno != E2BIG) return 1;
    output32 = 0xdeadbeefu;
    if (decode32(&output32, (const char *)0, 0, &state) != 0 || output32 != 0xdeadbeefu ||
        !state_is(&state, 0, 0x51515151u)) return 2;

    output16 = 0xbeefu;
    if (decode16(&output16, "A", 0, &state) != (size_t)-2 || output16 != 0xbeefu ||
        !state_is(&state, 0, 0x51515151u)) return 3;
    output32 = 0xdeadbeefu;
    if (decode32(&output32, "A", 0, &state) != (size_t)-2 || output32 != 0xdeadbeefu ||
        !state_is(&state, 0, 0x51515151u)) return 4;

    if (decode32(&output32, euro_lead, sizeof euro_lead, &state) != (size_t)-2 ||
        state.__opaque1 == 0 || state.__opaque2 != 0x51515151u) return 5;
    output32 = 0xdeadbeefu;
    errno = 0;
    if (decode32(&output32, (const char *)0, 0, &state) != (size_t)-1 ||
        errno != EILSEQ || output32 != 0xdeadbeefu ||
        !state_is(&state, 0, 0x51515151u)) return 6;

    set_state(&state, 0, 0x61616161u);
    output16 = 0xbeefu;
    if (decode16(&output16, banana, sizeof banana, &state) != 4 || output16 != 0xd83cu ||
        !state_is(&state, 0xdf4cu, 0x61616161u)) return 7;
    output16 = 0xbeefu;
    if (decode16(&output16, "ignored", 0, &state) != (size_t)-3 ||
        output16 != 0xdf4cu || !state_is(&state, 0, 0x61616161u)) return 8;

    set_state(&state, 0, 0x71717171u);
    if (decode16((char16_t *)0, banana, sizeof banana, &state) != 4 ||
        !state_is(&state, 0xdf4cu, 0x71717171u)) return 9;
    if (decode16((char16_t *)0, (const char *)1, (size_t)-1, &state) != (size_t)-3 ||
        !state_is(&state, 0, 0x71717171u)) return 10;

    return 0;
}

static int check_decode_errors(mbrtoc16_signature decode16,
    mbrtoc32_signature decode32)
{
    static const char invalid_c0[] = { (char)0xc0 };
    static const char invalid_c1[] = { (char)0xc1 };
    static const char invalid_f5[] = { (char)0xf5 };
    static const char invalid_80[] = { (char)0x80 };
    static const char bad_continuation[] = { (char)0xe2, (char)0x28 };
    static const char overlong[] = { (char)0xe0, (char)0x80, (char)0x80 };
    static const char encoded_surrogate[] = { (char)0xed, (char)0xa0, (char)0x80 };
    static const char beyond_unicode[] = { (char)0xf4, (char)0x90, (char)0x80, (char)0x80 };
    const char *const invalid[] = {
        invalid_c0, invalid_c1, invalid_f5, invalid_80, bad_continuation,
        overlong, encoded_surrogate, beyond_unicode
    };
    static const size_t invalid_size[] = { 1, 1, 1, 1, 2, 3, 3, 4 };
    mbstate_t state;
    char16_t output16;
    char32_t output32;
    size_t index;

    for (index = 0; index < sizeof invalid / sizeof invalid[0]; ++index) {
        set_state(&state, 0, 0xababababu);
        output32 = 0xdeadbeefu;
        errno = 0;
        if (decode32(&output32, invalid[index], invalid_size[index], &state) != (size_t)-1 ||
            errno != EILSEQ || output32 != 0xdeadbeefu ||
            !state_is(&state, 0, 0xababababu)) return (int)(1 + index);
    }

    set_state(&state, 0, 0xcdcdcdcdu);
    output16 = 0xbeefu;
    errno = 0;
    if (decode16(&output16, encoded_surrogate, sizeof encoded_surrogate, &state) !=
            (size_t)-1 || errno != EILSEQ || output16 != 0xbeefu ||
        !state_is(&state, 0, 0xcdcdcdcdu)) return 20;
    return 0;
}

static int check_null_states_are_separate(c16rtomb_signature encode,
    mbrtoc16_signature decode16, mbrtoc32_signature decode32)
{
    static const char banana[] = { (char)0xf0, (char)0x9f, (char)0x8d, (char)0x8c };
    static const char euro_lead[] = { (char)0xe2 };
    char output[4];
    char16_t output16;
    char32_t output32;

    output16 = 0xbeefu;
    if (decode16(&output16, banana, sizeof banana, (mbstate_t *)0) != 4 ||
        output16 != 0xd83cu) return 1;
    output32 = 0xdeadbeefu;
    if (decode32(&output32, "A", 1, (mbstate_t *)0) != 1 || output32 != (char32_t)'A')
        return 2;
    output16 = 0xbeefu;
    if (decode16(&output16, (const char *)1, (size_t)-1, (mbstate_t *)0) !=
            (size_t)-3 || output16 != 0xdf4cu) return 3;

    if (decode32(&output32, euro_lead, sizeof euro_lead, (mbstate_t *)0) != (size_t)-2)
        return 4;
    output16 = 0xbeefu;
    if (decode16(&output16, "A", 1, (mbstate_t *)0) != 1 || output16 != (char16_t)'A')
        return 5;
    errno = 0;
    if (decode32(&output32, (const char *)0, 0, (mbstate_t *)0) != (size_t)-1 ||
        errno != EILSEQ) return 6;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    if (encode(output, (char16_t)0xd800, (mbstate_t *)0) != 0 ||
        !bytes_have_value((const unsigned char *)output, sizeof output, 0x5a)) return 7;
    errno = 0;
    if (encode((char *)0, (char16_t)'A', (mbstate_t *)0) != (size_t)-1 || errno != EILSEQ)
        return 8;
    return 0;
}

static int check_c16rtomb_state_machine(c16rtomb_signature encode)
{
    static const unsigned char sharp_s[] = { 0xc3, 0x9f };
    static const unsigned char banana[] = { 0xf0, 0x9f, 0x8d, 0x8c };
    char output[4];
    mbstate_t state;

    if (setlocale(LC_CTYPE, "C.UTF-8") == (char *)0) return 1;
    set_state(&state, 0, 0x9a9a9a9au);
    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    errno = E2BIG;
    if (encode(output, (char16_t)0xd83c, &state) != 0 ||
        !bytes_have_value((const unsigned char *)output, sizeof output, 0x5a) ||
        !state_is(&state, 0x1f000u, 0x9a9a9a9au) || errno != E2BIG) return 2;
    errno = 0;
    if (encode((char *)0, (char16_t)0xd83c, &state) != (size_t)-1 || errno != EILSEQ ||
        !state_is(&state, 0, 0x9a9a9a9au)) return 3;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    errno = E2BIG;
    if (encode(output, (char16_t)0xd83c, &state) != 0 ||
        encode(output, (char16_t)0xdf4c, &state) != 4 ||
        !bytes_are((const unsigned char *)output, banana, sizeof banana) ||
        !state_is(&state, 0, 0x9a9a9a9au) || errno != E2BIG) return 4;

    set_state(&state, 0, 0x8b8b8b8bu);
    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    errno = E2BIG;
    if (encode(output, (char16_t)0x00df, &state) != 2 ||
        !bytes_are((const unsigned char *)output, sharp_s, sizeof sharp_s) ||
        !state_is(&state, 0, 0x8b8b8b8bu) || errno != E2BIG) return 5;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    if (encode(output, (char16_t)0xd800, &state) != 0 ||
        encode(output, (char16_t)'A', &state) != (size_t)-1 || errno != EILSEQ ||
        !bytes_have_value((const unsigned char *)output, sizeof output, 0x5a) ||
        !state_is(&state, 0, 0x8b8b8b8bu)) return 6;

    fill_bytes((unsigned char *)output, sizeof output, 0x5a);
    errno = 0;
    if (encode(output, (char16_t)0xdc00, &state) != (size_t)-1 || errno != EILSEQ ||
        !bytes_have_value((const unsigned char *)output, sizeof output, 0x5a) ||
        !state_is(&state, 0, 0x8b8b8b8bu)) return 7;

    errno = E2BIG;
    if (encode((char *)0, (char16_t)0xd800, &state) != 1 || errno != E2BIG ||
        !state_is(&state, 0, 0x8b8b8b8bu)) return 8;
    return 0;
}

int crabc_x86_64_uchar_stateful_probe(void)
{
    const c16rtomb_signature encode = c16rtomb;
    const mbrtoc16_signature decode16 = mbrtoc16;
    const mbrtoc32_signature decode32 = mbrtoc32;
    int status;

    status = check_c_and_posix_code_units(encode, decode16, decode32);
    if (status != 0) return status;
    status = check_utf8_decoding(decode16, decode32);
    if (status != 0) return 100 + status;
    status = check_decode_null_and_pending(decode16, decode32);
    if (status != 0) return 250 + status;
    status = check_decode_errors(decode16, decode32);
    if (status != 0) return 300 + status;
    status = check_null_states_are_separate(encode, decode16, decode32);
    if (status != 0) return 350 + status;
    status = check_c16rtomb_state_machine(encode);
    return status == 0 ? 0 : 400 + status;
}

#ifndef CRABC_UCHAR_STATEFUL_FREESTANDING
int main(void)
{
    return crabc_x86_64_uchar_stateful_probe();
}
#endif
