/* Fixed-locale narrow ctype, case, and collation fixture shared by musl/crabc. */

#include <ctype.h>
#include <locale.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

typedef int (*ctype_function)(int);
typedef int (*ctype_l_function)(int, locale_t);

static uint64_t mix_u32(uint64_t hash, uint32_t value)
{
    unsigned shift;
    for (shift = 0; shift != 32; shift += 8) {
        hash ^= (value >> shift) & 0xffu;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t count)
{
    size_t index;
    for (index = 0; index != count; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static void fill(unsigned char *destination, size_t count, unsigned char value)
{
    size_t index;
    for (index = 0; index != count; ++index)
        destination[index] = value;
}

static int check_ctype(locale_t locale, uint64_t *fingerprint)
{
    static ctype_function bases[] = {
        (isalnum), (isalpha), (isblank), (iscntrl), (isdigit), (isgraph),
        (islower), (isprint), (ispunct), (isspace), (isupper), (isxdigit),
        (tolower), (toupper)
    };
    static ctype_l_function localized[] = {
        (isalnum_l), (isalpha_l), (isblank_l), (iscntrl_l), (isdigit_l),
        (isgraph_l), (islower_l), (isprint_l), (ispunct_l), (isspace_l),
        (isupper_l), (isxdigit_l), (tolower_l), (toupper_l)
    };
    uint64_t hash = *fingerprint;
    size_t function_index;
    int character;

    for (character = -1; character != 256; ++character) {
        hash = mix_u32(hash, (uint32_t)character);
        for (function_index = 0;
            function_index != sizeof(bases) / sizeof(bases[0]);
            ++function_index) {
            int base = bases[function_index](character);
            int result = localized[function_index](character, locale);
            if (result != base)
                return 1;
            hash = mix_u32(hash, (uint32_t)result);
        }
    }
    *fingerprint = hash;
    return 0;
}

static int check_case(locale_t locale, uint64_t *fingerprint)
{
    static const char high_upper[] = { (char)0x80, 'A', 0 };
    static const char high_lower[] = { (char)0x80, 'a', 0 };
    static const struct {
        const char *left;
        const char *right;
        size_t count;
    } cases[] = {
        { "", "", 8 }, { "AbC", "aBc", 8 }, { "AbD", "aBc", 8 },
        { "aBc", "AbD", 8 }, { "prefix-X", "PREFIX-y", 6 },
        { "prefix-X", "PREFIX-y", 8 }, { high_upper, high_lower, 8 },
    };
    uint64_t hash = *fingerprint;
    size_t index;

    if (strncasecmp("different", "values", 0) != 0 ||
        strncasecmp_l("different", "values", 0, locale) != 0)
        return 1;
    for (index = 0; index != sizeof(cases) / sizeof(cases[0]); ++index) {
        int whole = strcasecmp(cases[index].left, cases[index].right);
        int whole_l = strcasecmp_l(cases[index].left, cases[index].right,
            locale);
        int bounded = strncasecmp(cases[index].left, cases[index].right,
            cases[index].count);
        int bounded_l = strncasecmp_l(cases[index].left, cases[index].right,
            cases[index].count, locale);
        if (whole_l != whole || bounded_l != bounded)
            return 2;
        hash = mix_u32(hash, (uint32_t)whole);
        hash = mix_u32(hash, (uint32_t)bounded);
    }
    if (strcasecmp("Alpha", "aLPHa") != 0 ||
        strcasecmp("Alpha", "Alphb") >= 0 ||
        strcasecmp("Alphb", "Alpha") <= 0)
        return 3;
    *fingerprint = hash;
    return 0;
}

static int check_xfrm_one(locale_t locale, int localized, uint64_t *fingerprint)
{
    static const unsigned char source[] = { 'A', 'b', 0x80, 'z', 0 };
    static const unsigned char untouched[8] = {
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5
    };
    unsigned char destination[8];
    size_t length;

    fill(destination, sizeof(destination), 0xa5);
    length = localized
        ? strxfrm_l((char *)destination, (const char *)source, 0, locale)
        : strxfrm((char *)destination, (const char *)source, 0);
    if (length != 4 || !bytes_equal(destination, untouched,
        sizeof(destination)))
        return 1;

    fill(destination, sizeof(destination), 0xa5);
    length = localized
        ? strxfrm_l((char *)destination, (const char *)source, 4, locale)
        : strxfrm((char *)destination, (const char *)source, 4);
    if (length != 4 || !bytes_equal(destination, untouched,
        sizeof(destination)))
        return 2;

    fill(destination, sizeof(destination), 0xa5);
    length = localized
        ? strxfrm_l((char *)destination, (const char *)source, 5, locale)
        : strxfrm((char *)destination, (const char *)source, 5);
    if (length != 4 || !bytes_equal(destination, source, 5) ||
        destination[5] != 0xa5)
        return 3;

    fill(destination, sizeof(destination), 0xa5);
    length = localized
        ? strxfrm_l((char *)destination, "", 1, locale)
        : strxfrm((char *)destination, "", 1);
    if (length != 0 || destination[0] != 0 || destination[1] != 0xa5)
        return 4;

    *fingerprint = mix_u32(*fingerprint, (uint32_t)length);
    return 0;
}

static int check_collation(locale_t locale, uint64_t *fingerprint)
{
    static const char high[] = { (char)0x80, 0 };
    static const char ascii[] = { (char)0x7f, 0 };
    static const struct {
        const char *left;
        const char *right;
    } cases[] = {
        { "", "" }, { "a", "b" }, { "b", "a" }, { "same", "same" },
        { "prefix", "prefix-z" }, { high, ascii },
    };
    uint64_t hash = *fingerprint;
    size_t index;

    for (index = 0; index != sizeof(cases) / sizeof(cases[0]); ++index) {
        int result = strcoll(cases[index].left, cases[index].right);
        int localized = strcoll_l(cases[index].left, cases[index].right,
            locale);
        int byte_result = strcmp(cases[index].left, cases[index].right);
        if (result != byte_result || localized != byte_result)
            return 1;
        hash = mix_u32(hash, (uint32_t)result);
    }
    if (check_xfrm_one(locale, 0, &hash) != 0 ||
        check_xfrm_one(locale, 1, &hash) != 0)
        return 2;
    *fingerprint = hash;
    return 0;
}

int crabc_x86_64_locale_narrow_probe(void)
{
    locale_t locales[3];
    uint64_t fingerprint = UINT64_C(1469598103934665603);
    size_t index;
    int result;

    if (setlocale(LC_ALL, "C") == NULL ||
        uselocale(NULL) != LC_GLOBAL_LOCALE)
        return 1;
    locales[0] = newlocale(LC_ALL_MASK, "C", NULL);
    locales[1] = newlocale(LC_ALL_MASK, "POSIX", NULL);
    locales[2] = newlocale(LC_ALL_MASK, "C.UTF-8", NULL);
    if (locales[0] == NULL || locales[1] == NULL || locales[2] == NULL)
        return 2;

    for (index = 0; index != 3; ++index) {
        if (uselocale(locales[index]) == NULL ||
            uselocale(NULL) != locales[index])
            return 3;
        result = check_ctype(locales[index], &fingerprint);
        if (result != 0)
            return 10 + result;
        result = check_case(locales[index], &fingerprint);
        if (result != 0)
            return 20 + result;
        result = check_collation(locales[index], &fingerprint);
        if (result != 0)
            return 30 + result;
        if (uselocale(NULL) != locales[index])
            return 4;
    }

    if (uselocale(LC_GLOBAL_LOCALE) != locales[2] ||
        uselocale(NULL) != LC_GLOBAL_LOCALE)
        return 5;
    for (index = 0; index != 3; ++index)
        freelocale(locales[index]);
    if (write(1, &fingerprint, sizeof(fingerprint)) !=
        (long)sizeof(fingerprint))
        return 6;
    return 0;
}

#if !defined(CRABC_LOCALE_NARROW_FREESTANDING)
int main(void)
{
    return crabc_x86_64_locale_narrow_probe();
}
#endif
