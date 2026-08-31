/* Static crabc-libc x86-64 fixed-profile locale error-string fixture. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <locale.h>
#include <stdint.h>
#include <string.h>

/* Musl exposes this internal spelling as the strong target of strerror_l. */
extern char *__strerror_l(int, locale_t);

static char digest_line[] = "locale-error-strings-fnv1a64=0000000000000000\n";
static const char alias_line[] = "strerror-l-alias=weak-same-address\n";
static const char profile_line[] = "strerror-l-profile=c-posix-cutf8-thread-global\n";

static size_t local_strlen(const char *text)
{
    size_t length = 0;
    while (text[length]) length++;
    return length;
}

static int local_streq(const char *left, const char *right)
{
    size_t index = 0;
    do {
        if (left[index] != right[index]) return 0;
    } while (left[index++]);
    return 1;
}

static long raw_write(int descriptor, const void *buffer, size_t length)
{
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(1L), "D"((long)descriptor), "S"((long)buffer), "d"((long)length)
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

static uint64_t hash_message(uint64_t hash, unsigned int selector,
                             int error, const char *message)
{
    unsigned int word = (unsigned int)error;
    int byte;

    hash = hash_byte(hash, (unsigned char)selector);
    for (byte = 0; byte < 4; byte++) {
        hash = hash_byte(hash, (unsigned char)word);
        word >>= 8;
    }
    do {
        hash = hash_byte(hash, (unsigned char)*message);
    } while (*message++);
    return hash;
}

static int check_one_locale(locale_t locale, unsigned int selector,
                            uint64_t *hash)
{
    int error;

    errno = EINTR;
    for (error = 0; error <= 134; error++) {
        char *plain = strerror(error);
        char *public_local = strerror_l(error, locale);
        char *internal_local = __strerror_l(error, locale);

        if (plain != public_local || public_local != internal_local) return 1;
        *hash = hash_message(*hash, selector, error, public_local);
    }
    if (errno != EINTR) return 2;
    return 0;
}

static int check_locale_calls(locale_t c_locale, locale_t posix_locale,
                              locale_t utf8_locale, uint64_t *hash)
{
    const locale_t locales[] = { c_locale, posix_locale, utf8_locale };
    size_t index;
    int result;

    if (strerror_l != __strerror_l) return 1;
    if (!local_streq(strerror_l(ENOENT, c_locale), "No such file or directory") ||
        !local_streq(strerror_l(0, utf8_locale), "No error information") ||
        !local_streq(__strerror_l(134, posix_locale), "No error information"))
        return 2;

    if (uselocale(c_locale) != LC_GLOBAL_LOCALE) return 3;
    for (index = 0; index < sizeof locales / sizeof locales[0]; index++) {
        result = check_one_locale(locales[index], (unsigned int)index, hash);
        if (result) return 10 + result;
    }
    if (uselocale(NULL) != c_locale) return 20;

    if (uselocale(utf8_locale) != c_locale) return 21;
    for (index = 0; index < sizeof locales / sizeof locales[0]; index++) {
        result = check_one_locale(locales[index], 4U + (unsigned int)index, hash);
        if (result) return 30 + result;
    }
    if (uselocale(NULL) != utf8_locale) return 40;

    if (uselocale(LC_GLOBAL_LOCALE) != utf8_locale) return 41;
    for (index = 0; index < sizeof locales / sizeof locales[0]; index++) {
        result = check_one_locale(locales[index], 8U + (unsigned int)index, hash);
        if (result) return 50 + result;
    }
    if (uselocale(NULL) != LC_GLOBAL_LOCALE) return 60;
    return 0;
}

static void write_digest_hex(uint64_t digest)
{
    static const char hex[] = "0123456789abcdef";
    const size_t offset = sizeof "locale-error-strings-fnv1a64=" - 1;
    size_t index;

    for (index = 0; index < 16; index++) {
        unsigned int shift = (unsigned int)((15 - index) * 4);
        digest_line[offset + index] = hex[(digest >> shift) & 15];
    }
}

int crabc_x86_64_locale_error_strings_probe(void)
{
    locale_t c_locale;
    locale_t posix_locale;
    locale_t utf8_locale;
    uint64_t hash = UINT64_C(14695981039346656037);
    int result;

    c_locale = newlocale(LC_ALL_MASK, "C", NULL);
    posix_locale = newlocale(LC_ALL_MASK, "POSIX", NULL);
    utf8_locale = newlocale(LC_ALL_MASK, "C.UTF-8", NULL);
    if (c_locale == NULL || posix_locale == NULL || utf8_locale == NULL) return 1;

    result = check_locale_calls(c_locale, posix_locale, utf8_locale, &hash);
    freelocale(utf8_locale);
    freelocale(posix_locale);
    freelocale(c_locale);
    if (result) return 10 + result;

    write_digest_hex(hash);
    if (!write_all(digest_line, local_strlen(digest_line))) return 80;
    if (!write_all(alias_line, sizeof alias_line - 1)) return 81;
    if (!write_all(profile_line, sizeof profile_line - 1)) return 82;
    return 0;
}

#if !defined(CRABC_LOCALE_ERROR_STRINGS_FREESTANDING)
int main(void)
{
    return crabc_x86_64_locale_error_strings_probe();
}
#endif
