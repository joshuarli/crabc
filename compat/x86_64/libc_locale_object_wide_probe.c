/* Built-in locale-object/localized-wide fixture shared by musl and crabc. */

#include <errno.h>
#include <langinfo.h>
#include <locale.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

struct worker_observation {
    locale_t utf8;
    int result;
};

static int string_equal(const char *left, const char *right)
{
    while (*left == *right) {
        if (*left == 0)
            return 1;
        ++left;
        ++right;
    }
    return 0;
}

static uint64_t mix_u32(uint64_t hash, uint32_t value)
{
    unsigned shift;
    for (shift = 0; shift != 32; shift += 8) {
        hash ^= (value >> shift) & 0xffu;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static int check_langinfo(locale_t c_locale, locale_t utf8_locale)
{
    static const struct {
        nl_item item;
        const char *value;
    } checks[] = {
        { RADIXCHAR, "." }, { THOUSEP, "" }, { ABDAY_1, "Sun" },
        { DAY_7, "Saturday" }, { ABMON_12, "Dec" },
        { MON_9, "September" }, { AM_STR, "AM" }, { PM_STR, "PM" },
        { D_T_FMT, "%a %b %e %T %Y" }, { D_FMT, "%m/%d/%y" },
        { T_FMT, "%H:%M:%S" }, { T_FMT_AMPM, "%I:%M:%S %p" },
        { ERA, "" }, { ERA_D_FMT, "%m/%d/%y" },
        { ALT_DIGITS, "0123456789" },
        { ERA_D_T_FMT, "%a %b %e %T %Y" }, { ERA_T_FMT, "%H:%M:%S" },
        { YESEXPR, "^[yY]" }, { NOEXPR, "^[nN]" }, { CRNCYSTR, "" },
    };
    size_t index;

    if (!string_equal(nl_langinfo_l(CODESET, c_locale), "ASCII") ||
        !string_equal(nl_langinfo_l(CODESET, utf8_locale), "UTF-8") ||
        !string_equal(nl_langinfo_l(_NL_LOCALE_NAME(LC_CTYPE), c_locale), "C") ||
        !string_equal(nl_langinfo_l(_NL_LOCALE_NAME(LC_CTYPE), utf8_locale),
            "C.UTF-8") ||
        !string_equal(nl_langinfo_l(_NL_LOCALE_NAME(LC_TIME), utf8_locale), "C"))
        return 1;
    for (index = 0; index != sizeof(checks) / sizeof(checks[0]); ++index) {
        if (!string_equal(nl_langinfo_l(checks[index].item, c_locale),
            checks[index].value) ||
            !string_equal(nl_langinfo_l(checks[index].item, utf8_locale),
            checks[index].value))
            return 2;
    }
    return 0;
}

static int check_multibyte_selection(locale_t c_locale, locale_t utf8_locale)
{
    static const char utf8[] = { (char)0xc3, (char)0xa4, 0 };
    mbstate_t state = { 0 };
    wchar_t wide = 0;

    if (uselocale(utf8_locale) != LC_GLOBAL_LOCALE ||
        !string_equal(nl_langinfo(CODESET), "UTF-8") || MB_CUR_MAX != 4 ||
        mbrtowc(&wide, utf8, 2, &state) != 2 || wide != 0x00e4)
        return 1;
    if (uselocale(c_locale) != utf8_locale ||
        !string_equal(nl_langinfo(CODESET), "ASCII") || MB_CUR_MAX != 1)
        return 2;
    state = (mbstate_t){ 0 };
    wide = 0;
    if (mbrtowc(&wide, utf8, 2, &state) != 1 || wide != (wchar_t)0xdfc3)
        return 3;
    if (setlocale(LC_ALL, "C.UTF-8") == NULL || MB_CUR_MAX != 1 ||
        uselocale(LC_GLOBAL_LOCALE) != c_locale || MB_CUR_MAX != 4 ||
        !string_equal(nl_langinfo(CODESET), "UTF-8"))
        return 4;
    if (setlocale(LC_ALL, "C") == NULL || MB_CUR_MAX != 1)
        return 5;
    return 0;
}

static void *worker_main(void *argument)
{
    struct worker_observation *observation = argument;
    static const char utf8[] = { (char)0xc3, (char)0xa4, 0 };
    mbstate_t state = { 0 };
    wchar_t wide = 0;

    if (uselocale(NULL) != LC_GLOBAL_LOCALE || MB_CUR_MAX != 1 ||
        !string_equal(nl_langinfo(CODESET), "ASCII")) {
        observation->result = 1;
        return NULL;
    }
    if (uselocale(observation->utf8) != LC_GLOBAL_LOCALE || MB_CUR_MAX != 4 ||
        mbrtowc(&wide, utf8, 2, &state) != 2 || wide != 0x00e4) {
        observation->result = 2;
        return NULL;
    }
    observation->result = 0;
    return NULL;
}

static int check_thread_isolation(locale_t utf8_locale)
{
    struct worker_observation observation = { utf8_locale, -1 };
    pthread_t thread;

    if (uselocale(utf8_locale) != LC_GLOBAL_LOCALE)
        return 1;
    if (pthread_create(&thread, NULL, worker_main, &observation) != 0)
        return 2;
    if (pthread_join(thread, NULL) != 0 || observation.result != 0)
        return 3;
    if (uselocale(NULL) != utf8_locale || MB_CUR_MAX != 4 ||
        uselocale(LC_GLOBAL_LOCALE) != utf8_locale)
        return 4;
    return 0;
}

static int check_localized_wide(locale_t c_locale, locale_t utf8_locale,
    uint64_t *fingerprint)
{
    static const char *names[] = {
        "alnum", "alpha", "blank", "cntrl", "digit", "graph",
        "lower", "print", "punct", "space", "upper", "xdigit"
    };
    static const wchar_t upper[] = { 'A', 0x00c4, 0x4e00, 0 };
    static const wchar_t lower[] = { 'a', 0x00e4, 0x4e00, 0 };
    locale_t locales[] = { c_locale, utf8_locale };
    wctype_t classes[12];
    wctrans_t to_upper;
    wctrans_t to_lower;
    wchar_t transformed[4];
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t locale_index;
    size_t class_index;
    uint32_t scalar;

    for (locale_index = 0; locale_index != 2; ++locale_index) {
        locale_t locale = locales[locale_index];
        for (class_index = 0; class_index != 12; ++class_index) {
            classes[class_index] = wctype_l(names[class_index], locale);
            if (classes[class_index] == 0)
                return 1;
        }
        to_upper = wctrans_l("toupper", locale);
        to_lower = wctrans_l("tolower", locale);
        if (to_upper == 0 || to_lower == 0 || wctype_l("unknown", locale) != 0 ||
            wctrans_l("unknown", locale) != 0)
            return 2;
        if (wcscasecmp_l(upper, lower, locale) != 0 ||
            wcsncasecmp_l(upper, lower, 2, locale) != 0 ||
            wcscoll_l(upper, lower, locale) >= 0 ||
            wcsxfrm_l(transformed, upper, 4, locale) != 3 ||
            wcscmp(transformed, upper) != 0)
            return 3;
        for (scalar = 0; scalar <= 0x110000u; ++scalar) {
            wint_t value = scalar;
            uint32_t flags = 0;
            flags |= !!iswalnum_l(value, locale) << 0;
            flags |= !!iswalpha_l(value, locale) << 1;
            flags |= !!iswblank_l(value, locale) << 2;
            flags |= !!iswcntrl_l(value, locale) << 3;
            flags |= !!(iswdigit_l)(value, locale) << 4;
            flags |= !!iswgraph_l(value, locale) << 5;
            flags |= !!iswlower_l(value, locale) << 6;
            flags |= !!iswprint_l(value, locale) << 7;
            flags |= !!iswpunct_l(value, locale) << 8;
            flags |= !!iswspace_l(value, locale) << 9;
            flags |= !!iswupper_l(value, locale) << 10;
            flags |= !!iswxdigit_l(value, locale) << 11;
            for (class_index = 0; class_index != 12; ++class_index) {
                if (!!iswctype_l(value, classes[class_index], locale) !=
                    !!(flags & (1u << class_index)))
                    return 4;
            }
            hash = mix_u32(hash, scalar);
            hash = mix_u32(hash, flags);
            hash = mix_u32(hash, towlower_l(value, locale));
            hash = mix_u32(hash, towupper_l(value, locale));
            hash = mix_u32(hash, towctrans_l(value, to_lower, locale));
            hash = mix_u32(hash, towctrans_l(value, to_upper, locale));
        }
    }
    *fingerprint = hash;
    return 0;
}

int crabc_x86_64_locale_object_wide_probe(void)
{
    locale_t c_locale;
    locale_t posix_locale;
    locale_t utf8_locale;
    locale_t duplicate;
    locale_t recomposed;
    uint64_t fingerprint;
    int result;

    if (setlocale(LC_ALL, "C") == NULL || uselocale(NULL) != LC_GLOBAL_LOCALE)
        return 1;
    c_locale = newlocale(LC_ALL_MASK, "C", NULL);
    posix_locale = newlocale(LC_ALL_MASK, "POSIX", NULL);
    utf8_locale = newlocale(LC_ALL_MASK, "C.UTF-8", NULL);
    if (c_locale == NULL || posix_locale == NULL || utf8_locale == NULL)
        return 2;
    result = check_langinfo(c_locale, utf8_locale);
    if (result != 0)
        return 10 + result;
    duplicate = duplocale(utf8_locale);
    if (duplicate == NULL ||
        !string_equal(nl_langinfo_l(CODESET, duplicate), "UTF-8"))
        return 20;
    freelocale(duplicate);
    recomposed = newlocale(LC_CTYPE_MASK, "C", utf8_locale);
    if (recomposed == NULL ||
        !string_equal(nl_langinfo_l(CODESET, recomposed), "ASCII"))
        return 21;
    result = check_multibyte_selection(c_locale, utf8_locale);
    if (result != 0)
        return 30 + result;
    result = check_thread_isolation(utf8_locale);
    if (result != 0)
        return 40 + result;
    result = check_localized_wide(c_locale, utf8_locale, &fingerprint);
    if (result != 0)
        return 50 + result;
#if defined(CRABC_LOCALE_OBJECT_WIDE_FREESTANDING)
    errno = EINTR;
    if (newlocale(LC_ALL_MASK, "en_US.UTF-8", NULL) != NULL || errno != ENOENT)
        return 60;
    errno = EINTR;
    if (newlocale(LC_ALL_MASK, "", NULL) != NULL || errno != ENOENT ||
        uselocale(NULL) != LC_GLOBAL_LOCALE || MB_CUR_MAX != 1)
        return 60;
#endif
    freelocale(recomposed);
    freelocale(utf8_locale);
    freelocale(posix_locale);
    freelocale(c_locale);
    if (write(STDOUT_FILENO, &fingerprint, sizeof(fingerprint)) !=
        (ssize_t)sizeof(fingerprint))
        return 61;
    return 0;
}

#if !defined(CRABC_LOCALE_OBJECT_WIDE_FREESTANDING)
int main(void)
{
    return crabc_x86_64_locale_object_wide_probe();
}
#endif
