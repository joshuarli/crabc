#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <uchar.h>

static int bytes_equal(const char *actual, const unsigned char *expected, size_t n)
{
    return memcmp(actual, expected, n) == 0;
}

static int state_is_zero(const mbstate_t *state)
{
    mbstate_t zero = { 0 };
    return memcmp(state, &zero, sizeof zero) == 0;
}

int main(void)
{
    char out[8] = {0};
    mbstate_t state = {0};
    const unsigned char banana[] = { 0xf0, 0x9f, 0x8d, 0x8c };

    if (!setlocale(LC_CTYPE, "C.UTF-8")) return 1;

    /* UTF-16 high/low surrogates carry state across separate calls. */
    if (c16rtomb(out, 0xd83c, &state) != 0 || state_is_zero(&state)) return 2;
    if (c16rtomb(out, 0xdf4c, &state) != 4 || !state_is_zero(&state)) return 3;
    if (!bytes_equal(out, banana, sizeof banana)) return 4;
    errno = 0;
    if (c16rtomb(out, 0xdf4c, &state) != (size_t)-1 || errno != EILSEQ || !state_is_zero(&state))
        return 5;
    if (c16rtomb(out, 0x00df, &state) != 2 || out[0] != (char)0xc3 || out[1] != (char)0x9f)
        return 6;

    /* mbrtoc16 emits the high surrogate with the consumed-byte count, then
     * emits the pending low surrogate without consuming source bytes. */
    state = (mbstate_t){0};
    char16_t c16 = 0;
    if (mbrtoc16(&c16, (const char *)banana, sizeof banana, &state) != 4 || c16 != 0xd83c)
        return 7;
    if (mbrtoc16(&c16, "ignored", 7, &state) != (size_t)-3 || c16 != 0xdf4c || !state_is_zero(&state))
        return 8;
    if (mbrtoc16(&c16, "A", 1, &state) != 1 || c16 != 0x41)
        return 9;

    /* UTF-32 conversion is the direct scalar equivalent. */
    state = (mbstate_t){0};
    char32_t c32 = 0;
    if (mbrtoc32(&c32, (const char *)banana, sizeof banana, &state) != 4 || c32 != 0x1f34c)
        return 10;
    if (c32rtomb(out, c32, &state) != 4 || !bytes_equal(out, banana, sizeof banana))
        return 11;
    if (c32rtomb(NULL, 0, &state) != 1) return 12;

    errno = 0;
    if (c32rtomb(out, 0x110000, &state) != (size_t)-1 || errno != EILSEQ)
        return 13;
    errno = 0;
    {
        const char invalid[] = { (char)0xff };
        if (mbrtoc32(&c32, invalid, sizeof invalid, &state) != (size_t)-1 || errno != EILSEQ)
            return 14;
    }

    puts("m4 unicode encoders ok");
    return 0;
}
