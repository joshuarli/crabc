/*
 * Ordered installed-product composition for finite text, locale, numeric, and
 * UTF behavior rows.  Each existing probe keeps its own musl-facing semantic
 * assertions.  This driver only fixes their execution order in one normal
 * application object.  The alias-contract probe is deliberately separate:
 * its public replacement definitions would change the other probes' imports.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

typedef int (*probe_function)(void);

int crabc_x86_64_float_parse_probe(void);
int crabc_x86_64_locale_ctype_locators_probe(void);
int crabc_x86_64_locale_narrow_probe(void);
int crabc_x86_64_locale_object_wide_probe(void);
int crabc_x86_64_locale_wide_iconv_probe(void);
int crabc_x86_64_locale_multibyte_probe(void);
int crabc_x86_64_wide_character_probe(void);
int crabc_x86_64_owned_strfmon_probe(void);
int crabc_x86_64_owned_wide_conversion_probe(void);
int crabc_x86_64_uchar_stateful_probe(void);
int crabc_x86_64_c32rtomb_probe(void);
int crabc_x86_64_wcswcs_probe(void);
int crabc_x86_64_locale_error_strings_probe(void);
int crabc_x86_64_text_locale_differential_probe(void);
int crabc_x86_64_wide_stream_differential_probe(void);

struct stage {
    const char *name;
    probe_function probe;
};

static const struct stage stages[] = {
    { "float-parse", crabc_x86_64_float_parse_probe },
    { "ctype-locators", crabc_x86_64_locale_ctype_locators_probe },
    { "locale-narrow", crabc_x86_64_locale_narrow_probe },
    { "locale-object-wide", crabc_x86_64_locale_object_wide_probe },
    { "locale-wide-iconv", crabc_x86_64_locale_wide_iconv_probe },
    { "locale-multibyte", crabc_x86_64_locale_multibyte_probe },
    { "wide-character", crabc_x86_64_wide_character_probe },
    { "strfmon", crabc_x86_64_owned_strfmon_probe },
    { "wide-conversion", crabc_x86_64_owned_wide_conversion_probe },
    { "uchar-stateful", crabc_x86_64_uchar_stateful_probe },
    { "c32rtomb", crabc_x86_64_c32rtomb_probe },
    { "wcswcs", crabc_x86_64_wcswcs_probe },
    { "locale-error-strings", crabc_x86_64_locale_error_strings_probe },
    { "text-locale-differential", crabc_x86_64_text_locale_differential_probe },
    /* Last: it reopens stdout around its stdout-only wide entries. */
    { "wide-stream-differential", crabc_x86_64_wide_stream_differential_probe },
};

static size_t text_length(const char *text)
{
    size_t length = 0;

    while (text[length] != '\0')
        ++length;
    return length;
}

static int write_all(const char *text)
{
    size_t remaining = text_length(text);

    while (remaining != 0) {
        ssize_t written = write(STDOUT_FILENO, text, remaining);

        if (written <= 0)
            return -1;
        text += (size_t)written;
        remaining -= (size_t)written;
    }
    return 0;
}

static int emit(const char *name, const char *suffix)
{
    return write_all("text-locale-numeric/") == 0 &&
        write_all(name) == 0 && write_all(suffix) == 0 ? 0 : -1;
}

int main(void)
{
    size_t index;

    for (index = 0; index != sizeof(stages) / sizeof(stages[0]); ++index) {
        int result;

        /*
         * Existing probes intentionally use buffered printf/puts while the
         * frame markers use write(2).  Flush before the begin frame and after
         * the probe so the retained stream is exactly begin, probe payload,
         * ok.  A flush error is observable instead of being mistaken for a
         * successful stage marker.
         */
        if (fflush(stdout) != 0 || emit(stages[index].name, ":begin\n") != 0)
            return 1;
        result = stages[index].probe();
        if (fflush(stdout) != 0)
            return 2;
        if (result != 0)
            return 64 + (int)index;
        if (emit(stages[index].name, ":ok\n") != 0)
            return 3;
    }
    return 0;
}
