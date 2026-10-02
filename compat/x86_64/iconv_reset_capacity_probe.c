/* Ordinary fixed-encoding descriptor reset and output-capacity behavior. */
#include <errno.h>
#include <iconv.h>
#include <stddef.h>

struct encoding {
    const char *name;
    const unsigned char *text;
    size_t size;
};

static const unsigned char ascii[] = {'A', 'z', 0};
static const unsigned char utf16le[] = {'A', 0, 'z', 0, 0, 0};
static const unsigned char utf16be[] = {0, 'A', 0, 'z', 0, 0};
static const unsigned char utf32le[] = {'A', 0, 0, 0, 'z', 0, 0, 0, 0, 0, 0, 0};
static const unsigned char utf32be[] = {0, 0, 0, 'A', 0, 0, 0, 'z', 0, 0, 0, 0};
static const struct encoding encodings[] = {
    {"ASCII", ascii, sizeof ascii},
    {"UTF-8", ascii, sizeof ascii},
    {"UTF-16LE", utf16le, sizeof utf16le},
    {"UTF-16BE", utf16be, sizeof utf16be},
    {"UTF-32LE", utf32le, sizeof utf32le},
    {"UTF-32BE", utf32be, sizeof utf32be},
};

static int equal(const unsigned char *left, const unsigned char *right, size_t size)
{
    for (size_t i = 0; i < size; i++)
        if (left[i] != right[i]) return 0;
    return 1;
}

static int check_reset(iconv_t descriptor)
{
    char *input = NULL;
    char output[4] = {'x', 'x', 'x', 'x'};
    char *cursor = output;
    size_t remaining = sizeof output;
    errno = 123;
    if (iconv(descriptor, NULL, NULL, NULL, NULL) != 0 || errno != 123) return 1;
    if (iconv(descriptor, &input, NULL, NULL, NULL) != 0 || errno != 123) return 2;
    if (iconv(descriptor, &input, NULL, &cursor, &remaining) != 0 ||
        errno != 123 || cursor != output || remaining != sizeof output ||
        !equal((const unsigned char *)output, (const unsigned char *)"xxxx", 4)) return 3;
    return 0;
}

static int check_capacity(iconv_t descriptor, const struct encoding *from,
    const struct encoding *to)
{
    unsigned char output[16];
    char *input = (char *)(void *)from->text;
    char *cursor = NULL;
    size_t input_left = from->size;
    size_t output_left = 0;
    errno = 123;
    if (iconv(descriptor, &input, &input_left, &cursor, &output_left) != (size_t)-1 ||
        errno != E2BIG || input != (char *)(void *)from->text ||
        input_left != from->size || cursor != NULL || output_left != 0) return 4;
    for (size_t i = 0; i < sizeof output; i++) output[i] = 0x55;
    cursor = (char *)(void *)output;
    output_left = to->size - 1;
    errno = 123;
    if (iconv(descriptor, &input, &input_left, &cursor, &output_left) != (size_t)-1 ||
        errno != E2BIG || input_left != from->size / 3 ||
        input != (char *)(void *)(from->text + from->size * 2 / 3) ||
        cursor != (char *)(void *)(output + to->size * 2 / 3) ||
        output_left != to->size / 3 - 1 || !equal(output, to->text, to->size * 2 / 3)) return 5;
    for (size_t i = to->size * 2 / 3; i < sizeof output; i++)
        if (output[i] != 0x55) return 6;
    output_left = sizeof output - (size_t)(cursor - (char *)(void *)output);
    errno = 123;
    if (iconv(descriptor, &input, &input_left, &cursor, &output_left) != 0 ||
        errno != 123 || input_left != 0 || input != (char *)(void *)(from->text + from->size) ||
        cursor != (char *)(void *)(output + to->size) || !equal(output, to->text, to->size)) return 7;
    for (size_t i = to->size; i < sizeof output; i++)
        if (output[i] != 0x55) return 8;
    return 0;
}

struct unicode_encoding {
    struct encoding encoding;
    size_t boundary[5];
};

/* The same ordinary string contains ASCII, a BMP scalar, a supplementary
 * scalar, and its terminating NUL in every selected Unicode encoding. */
static const unsigned char unicode_utf8[] = {'A', 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80, 0};
static const unsigned char unicode_utf16le[] = {'A', 0, 0xac, 0x20, 0x3d, 0xd8, 0, 0xde, 0, 0};
static const unsigned char unicode_utf16be[] = {0, 'A', 0x20, 0xac, 0xd8, 0x3d, 0xde, 0, 0, 0};
static const unsigned char unicode_utf32le[] = {'A', 0, 0, 0, 0xac, 0x20, 0, 0, 0, 0xf6, 1, 0, 0, 0, 0, 0};
static const unsigned char unicode_utf32be[] = {0, 0, 0, 'A', 0, 0, 0x20, 0xac, 0, 1, 0xf6, 0, 0, 0, 0, 0};
static const struct unicode_encoding unicode_encodings[] = {
    {{"UTF-8", unicode_utf8, sizeof unicode_utf8}, {0, 1, 4, 8, 9}},
    {{"UTF-16LE", unicode_utf16le, sizeof unicode_utf16le}, {0, 2, 4, 8, 10}},
    {{"UTF-16BE", unicode_utf16be, sizeof unicode_utf16be}, {0, 2, 4, 8, 10}},
    {{"UTF-32LE", unicode_utf32le, sizeof unicode_utf32le}, {0, 4, 8, 12, 16}},
    {{"UTF-32BE", unicode_utf32be, sizeof unicode_utf32be}, {0, 4, 8, 12, 16}},
};

static int check_unicode_capacity(const struct unicode_encoding *from,
    const struct unicode_encoding *to)
{
    iconv_t descriptor = iconv_open(to->encoding.name, from->encoding.name);
    if (descriptor == (iconv_t)-1) return 11;
    for (size_t capacity = 0; capacity <= to->encoding.size; capacity++) {
        unsigned char output[20];
        for (size_t i = 0; i < sizeof output; i++) output[i] = 0x55;
        char *input = (char *)(void *)from->encoding.text;
        char *cursor = (char *)(void *)output;
        size_t input_left = from->encoding.size;
        size_t output_left = capacity;
        size_t prefix = 0;
        while (prefix < 4 && to->boundary[prefix + 1] <= capacity) prefix++;
        errno = 123;
        size_t result = iconv(descriptor, &input, &input_left, &cursor, &output_left);
        if (result != (prefix == 4 ? 0 : (size_t)-1) || errno != (prefix == 4 ? 123 : E2BIG) ||
            input != (char *)(void *)(from->encoding.text + from->boundary[prefix]) ||
            input_left != from->encoding.size - from->boundary[prefix] ||
            cursor != (char *)(void *)(output + to->boundary[prefix]) ||
            output_left != capacity - to->boundary[prefix] ||
            !equal(output, to->encoding.text, to->boundary[prefix])) return 12;
        for (size_t i = to->boundary[prefix]; i < sizeof output; i++)
            if (output[i] != 0x55) return 13;
        output_left = sizeof output - to->boundary[prefix];
        errno = 123;
        if (iconv(descriptor, &input, &input_left, &cursor, &output_left) != 0 || errno != 123 ||
            input_left != 0 || cursor != (char *)(void *)(output + to->encoding.size) ||
            !equal(output, to->encoding.text, to->encoding.size)) return 14;
        for (size_t i = to->encoding.size; i < sizeof output; i++)
            if (output[i] != 0x55) return 15;
    }
    if (iconv_close(descriptor) != 0) return 16;
    return 0;
}

int crabc_x86_64_locale_wide_iconv_probe(void)
{
    for (size_t from = 0; from < sizeof encodings / sizeof encodings[0]; from++) {
        for (size_t to = 0; to < sizeof encodings / sizeof encodings[0]; to++) {
            iconv_t descriptor = iconv_open(encodings[to].name, encodings[from].name);
            if (descriptor == (iconv_t)-1) return 9;
            /* Preserve both independent failures in the process status. */
            int reset_result = check_reset(descriptor);
            int capacity_result = check_capacity(descriptor, &encodings[from], &encodings[to]);
            if (reset_result != 0 || capacity_result != 0)
                return reset_result + 16 * capacity_result;
            errno = 123;
            if (iconv_close(descriptor) != 0 || errno != 123) return 10;
        }
    }
    for (size_t from = 0; from < sizeof unicode_encodings / sizeof unicode_encodings[0]; from++) {
        for (size_t to = 0; to < sizeof unicode_encodings / sizeof unicode_encodings[0]; to++) {
            int result = check_unicode_capacity(&unicode_encodings[from], &unicode_encodings[to]);
            if (result != 0) return result;
        }
    }
    return 0;
}

#ifndef CRABC_TEXT_CONVERSION_FREESTANDING
int main(void) { return crabc_x86_64_locale_wide_iconv_probe(); }
#endif
