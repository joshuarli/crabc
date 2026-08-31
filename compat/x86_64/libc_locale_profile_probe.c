/* Static crabc-libc x86-64 fixed C/POSIX/C.UTF-8 locale-profile fixture. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <limits.h>
#include <locale.h>
#include <stddef.h>
#include <stdint.h>

static char digest_line[] = "locale-profile-fnv1a64=0000000000000000\n";

static int text_equal(const char *left, const char *right)
{
    while (*left == *right) {
        if (*left == '\0') return 1;
        left++;
        right++;
    }
    return 0;
}

static long raw_write(int descriptor, const void *buffer, size_t length)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(1L), "D"((long)descriptor), "S"(buffer), "d"(length)
        : "rcx", "r11", "memory");
    return result;
}

static int write_all(const char *buffer, size_t length)
{
    while (length) {
        long written = raw_write(1, buffer, length);
        if (written <= 0) return 0;
        buffer += (size_t)written;
        length -= (size_t)written;
    }
    return 1;
}

static uint64_t hash_byte(uint64_t hash, unsigned char byte)
{
    return (hash ^ byte) * UINT64_C(1099511628211);
}

static uint64_t hash_text(uint64_t hash, const char *text)
{
    do {
        hash = hash_byte(hash, (unsigned char)*text);
    } while (*text++);
    return hash;
}

static int expect_name(uint64_t *hash, int category, const char *request,
                       const char *expected)
{
    char *actual = setlocale(category, request);

    if (actual == NULL || !text_equal(actual, expected)) return 1;
    *hash = hash_byte(*hash, (unsigned char)category);
    *hash = hash_text(*hash, request == NULL ? "<query>" : request);
    *hash = hash_text(*hash, actual);
    return 0;
}

static int check_lconv(uint64_t *hash, const struct lconv **record)
{
    static const char *const expected_text[] = {
        ".", "", "", "", "", "", "", "", "", "",
    };
    struct lconv *value = localeconv();
    const char *const fields[] = {
        value ? value->decimal_point : NULL,
        value ? value->thousands_sep : NULL,
        value ? value->grouping : NULL,
        value ? value->int_curr_symbol : NULL,
        value ? value->currency_symbol : NULL,
        value ? value->mon_decimal_point : NULL,
        value ? value->mon_thousands_sep : NULL,
        value ? value->mon_grouping : NULL,
        value ? value->positive_sign : NULL,
        value ? value->negative_sign : NULL,
    };
    const signed char digits[] = {
        value ? value->int_frac_digits : 0,
        value ? value->frac_digits : 0,
        value ? value->p_cs_precedes : 0,
        value ? value->p_sep_by_space : 0,
        value ? value->n_cs_precedes : 0,
        value ? value->n_sep_by_space : 0,
        value ? value->p_sign_posn : 0,
        value ? value->n_sign_posn : 0,
        value ? value->int_p_cs_precedes : 0,
        value ? value->int_p_sep_by_space : 0,
        value ? value->int_n_cs_precedes : 0,
        value ? value->int_n_sep_by_space : 0,
        value ? value->int_p_sign_posn : 0,
        value ? value->int_n_sign_posn : 0,
    };
    size_t index;

    if (value == NULL || (*record != NULL && value != *record)) return 1;
    *record = value;
    for (index = 0; index < sizeof fields / sizeof fields[0]; index++) {
        if (fields[index] == NULL || !text_equal(fields[index], expected_text[index]))
            return 2;
        *hash = hash_text(*hash, fields[index]);
    }
    for (index = 0; index < sizeof digits / sizeof digits[0]; index++) {
        if (digits[index] != CHAR_MAX) return 3;
        *hash = hash_byte(*hash, (unsigned char)digits[index]);
    }
    return 0;
}

static int check_fixed_profile(uint64_t *hash)
{
    static const int categories[] = {
        LC_CTYPE, LC_NUMERIC, LC_TIME, LC_COLLATE, LC_MONETARY, LC_MESSAGES,
    };
    static const char mixed[] = "C.UTF-8;C;C;C;C;C";
    const struct lconv *record = NULL;
    size_t index;
    int status;

    if (expect_name(hash, LC_ALL, "C", "C")) return 1;
    for (index = 0; index < sizeof categories / sizeof categories[0]; index++) {
        if (expect_name(hash, categories[index], NULL, "C")) return 2;
    }
    if ((status = check_lconv(hash, &record)) != 0) return 10 + status;

    if (expect_name(hash, LC_CTYPE, "C.UTF-8", "C.UTF-8")) return 20;
    if (expect_name(hash, LC_ALL, NULL, mixed)) return 21;
    for (index = 1; index < sizeof categories / sizeof categories[0]; index++) {
        if (expect_name(hash, categories[index], "C.UTF-8", "C"))
            return 22 + (int)index;
    }
    if (expect_name(hash, LC_ALL, NULL, mixed)) return 30;
    if (expect_name(hash, LC_ALL, mixed, mixed)) return 31;
    if (expect_name(hash, LC_ALL, "C.UTF-8", mixed)) return 32;
    if (expect_name(hash, LC_CTYPE, NULL, "C.UTF-8")) return 33;
    for (index = 1; index < sizeof categories / sizeof categories[0]; index++) {
        if (expect_name(hash, categories[index], NULL, "C"))
            return 34 + (int)index;
    }
    if ((status = check_lconv(hash, &record)) != 0) return 50 + status;

    if (expect_name(hash, LC_ALL, "POSIX", "C")) return 60;
    for (index = 0; index < sizeof categories / sizeof categories[0]; index++) {
        if (expect_name(hash, categories[index], NULL, "C")) return 61;
    }
    if (setlocale(LC_ALL + 1, "C") != NULL ||
        setlocale(LC_ALL + 1, NULL) != NULL)
        return 70;
    *hash = hash_byte(*hash, 0xa7);
    if ((status = check_lconv(hash, &record)) != 0) return 80 + status;

#ifdef CRABC_LOCALE_PROFILE_FREESTANDING
    /*
     * Pinned musl intentionally accepts its general map/environment paths.
     * The selected candidate must instead reject each one without changing its
     * fixed global state, so these negative checks are candidate-only.
     */
    /* Keep candidate-only rejection checks out of the common musl digest. */
    {
        uint64_t ignored_hash = 0;

        if (expect_name(&ignored_hash, LC_CTYPE, "C.UTF-8", "C.UTF-8"))
            return 90;
        if (setlocale(LC_ALL, "") != NULL ||
            setlocale(LC_CTYPE, "en_US.UTF-8") != NULL ||
            setlocale(LC_ALL, "C;C;C;C;C;C") != NULL ||
            setlocale(LC_ALL, "C;C.UTF-8;C;C;C;C") != NULL)
            return 91;
        if (expect_name(&ignored_hash, LC_ALL, NULL, mixed) ||
            expect_name(&ignored_hash, LC_CTYPE, NULL, "C.UTF-8"))
            return 92;
        if (expect_name(&ignored_hash, LC_ALL, "C", "C")) return 93;
    }
#endif

    return 0;
}

static void write_digest_hex(uint64_t digest)
{
    static const char hex[] = "0123456789abcdef";
    const size_t offset = sizeof "locale-profile-fnv1a64=" - 1;
    size_t index;

    for (index = 0; index < 16; index++) {
        unsigned int shift = (unsigned int)((15 - index) * 4);
        digest_line[offset + index] = hex[(digest >> shift) & 15];
    }
}

int crabc_x86_64_locale_profile_probe(void)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    int status = check_fixed_profile(&hash);

    if (status != 0) return status;
    write_digest_hex(hash);
    return write_all(digest_line, sizeof digest_line - 1) ? 0 : 127;
}

#if !defined(CRABC_LOCALE_PROFILE_FREESTANDING)
int main(void)
{
    return crabc_x86_64_locale_profile_probe();
}
#endif
