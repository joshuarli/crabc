/* Installed x86-64 fixed-locale, multibyte, and UTF iconv composition.
 *
 * This is one application object compiled through selected installed headers.
 * It uses only C, POSIX, and C.UTF-8; fixed UTF-8/16/32 and ASCII iconv
 * descriptors; and two selected pthread workers.  It intentionally excludes
 * arbitrary locale maps, wide streams, collation,
 * general Unicode tables, and historical code pages.
 */

#define _XOPEN_SOURCE 700

#include <errno.h>
#include <iconv.h>
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <wchar.h>

/* Keep the isolated regression and this same-object installed composition on
 * the same assertions. The receipt seals this exact additional source. */
#define CRABC_LOCALE_ENVIRONMENT_NO_MAIN
#include "libc_locale_environment_probe.c"

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(wchar_t) == 4, "x86 wchar_t width");
_Static_assert(sizeof(mbstate_t) == 8, "x86 mbstate_t size");
_Static_assert(_Alignof(mbstate_t) == 4, "x86 mbstate_t alignment");
_Static_assert(sizeof(locale_t) == sizeof(void *), "x86 locale_t ABI");
_Static_assert(sizeof(iconv_t) == sizeof(void *), "x86 iconv_t ABI");

struct thread_case {
    locale_t locale;
    int utf8;
    int initial_errno;
    pthread_barrier_t *ready;
    pthread_barrier_t *finished;
    int result;
};

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

    for (index = 0; index != count; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static int barrier_wait(pthread_barrier_t *barrier)
{
    int result = pthread_barrier_wait(barrier);

    return result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD;
}

static int check_lconv(void)
{
    struct lconv *value = localeconv();

    return value != NULL && text_equal(value->decimal_point, ".") &&
        text_equal(value->thousands_sep, "") && text_equal(value->grouping, "") &&
        value->int_frac_digits == CHAR_MAX && value->frac_digits == CHAR_MAX;
}

static int check_locale_core(locale_t *c_locale, locale_t *utf8_locale)
{
    static const char mixed[] = "C.UTF-8;C;C;C;C;C";
    locale_t duplicate;

    if (setlocale(LC_ALL, "C") == NULL || !text_equal(setlocale(LC_ALL, NULL), "C") ||
        MB_CUR_MAX != 1 || !check_lconv())
        return 1;
    *c_locale = newlocale(LC_ALL_MASK, "POSIX", NULL);
    *utf8_locale = newlocale(LC_ALL_MASK, "C.UTF-8", NULL);
    if (*c_locale == NULL || *utf8_locale == NULL ||
        !text_equal(nl_langinfo_l(CODESET, *c_locale), "ASCII") ||
        !text_equal(nl_langinfo_l(CODESET, *utf8_locale), "UTF-8"))
        return 2;
    duplicate = duplocale(*utf8_locale);
    if (duplicate == NULL || !text_equal(nl_langinfo_l(CODESET, duplicate), "UTF-8"))
        return 3;
    freelocale(duplicate);
    if (setlocale(LC_CTYPE, "C.UTF-8") == NULL ||
        !text_equal(setlocale(LC_ALL, NULL), mixed) || MB_CUR_MAX != 4)
        return 4;
    if (setlocale(LC_ALL, "C") == NULL || MB_CUR_MAX != 1)
        return 5;
    return 0;
}

static int check_utf8_thread_state(void)
{
    static const char euro[] = { (char)0xe2, (char)0x82, (char)0xac };
    static const char invalid[] = { (char)0xc0 };
    static const char truncated[] = { (char)0xe2 };
    mbstate_t state = { 0 };
    wchar_t wide = 0;

    errno = EINTR;
    if (MB_CUR_MAX != 4 || !text_equal(nl_langinfo(CODESET), "UTF-8") ||
        mbrtowc(&wide, euro, 2, &state) != (size_t)-2 || mbsinit(&state) ||
        errno != EINTR || mbrtowc(&wide, euro + 2, 1, &state) != 1 ||
        wide != 0x20ac || !mbsinit(&state) || errno != EINTR)
        return 1;
    errno = 0;
    if (mbrtowc(&wide, invalid, sizeof(invalid), &state) != (size_t)-1 ||
        errno != EILSEQ || !mbsinit(&state))
        return 2;
    errno = EINTR;
    if (mbrtowc(&wide, truncated, sizeof(truncated), &state) != (size_t)-2 ||
        mbsinit(&state) || errno != EINTR)
        return 3;
    errno = 0;
    if (mbrtowc(&wide, NULL, 0, &state) != (size_t)-1 || errno != EILSEQ ||
        !mbsinit(&state))
        return 4;
    return 0;
}

static int check_c_thread_state(void)
{
    static const char byte[] = { (char)0xc3 };
    mbstate_t state = { 0 };
    wchar_t wide = 0;

    errno = EBUSY;
    if (MB_CUR_MAX != 1 || !text_equal(nl_langinfo(CODESET), "ASCII") ||
        mbrtowc(&wide, byte, sizeof(byte), &state) != 1 ||
        wide != (wchar_t)0xdfc3 || !mbsinit(&state) || errno != EBUSY)
        return 1;
    return 0;
}

static void *thread_main(void *argument)
{
    struct thread_case *test = argument;
    int status;

    test->result = 1;
    if (uselocale(test->locale) != LC_GLOBAL_LOCALE)
        return NULL;
    errno = test->initial_errno;
    if (!barrier_wait(test->ready) || errno != test->initial_errno)
        return NULL;
    status = test->utf8 ? check_utf8_thread_state() : check_c_thread_state();
    if (status != 0 || !barrier_wait(test->finished)) {
        test->result = 10 + status;
        return NULL;
    }
    if (errno != (test->utf8 ? EILSEQ : EBUSY)) {
        test->result = 20;
        return NULL;
    }
    if (uselocale(LC_GLOBAL_LOCALE) != test->locale) {
        test->result = 21;
        return NULL;
    }
    test->result = 0;
    return NULL;
}

static int check_thread_locale_and_errno(locale_t c_locale, locale_t utf8_locale)
{
    pthread_barrier_t ready;
    pthread_barrier_t finished;
    struct thread_case utf8 = { utf8_locale, 1, EINTR, &ready, &finished, -1 };
    struct thread_case c = { c_locale, 0, EBUSY, &ready, &finished, -1 };
    pthread_t utf8_thread;
    pthread_t c_thread;
    int result;

    if (pthread_barrier_init(&ready, NULL, 3) != 0 ||
        pthread_barrier_init(&finished, NULL, 3) != 0)
        return 1;
    if (pthread_create(&utf8_thread, NULL, thread_main, &utf8) != 0 ||
        pthread_create(&c_thread, NULL, thread_main, &c) != 0)
        return 2;
    errno = ERANGE;
    if (!barrier_wait(&ready) || errno != ERANGE || !barrier_wait(&finished) ||
        errno != ERANGE)
        return 3;
    result = pthread_join(utf8_thread, NULL) | pthread_join(c_thread, NULL);
    if (pthread_barrier_destroy(&ready) != 0 || pthread_barrier_destroy(&finished) != 0)
        return 4;
    if (result != 0 || utf8.result != 0 || c.result != 0)
        return 5;
    return 0;
}

static int check_iconv_pointer_and_errors(void)
{
    static const unsigned char utf8[] = {
        'A', 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80,
    };
    static const unsigned char utf16le[] = {
        0x41, 0x00, 0xac, 0x20, 0x3d, 0xd8, 0x00, 0xde,
    };
    static const unsigned char utf32be[] = {
        0x00, 0x00, 0x20, 0xac, 0x00, 0x01, 0xf6, 0x00,
    };
    static const unsigned char utf8_pair[] = {
        0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80,
    };
    static const unsigned char invalid[] = { 0xc0 };
    static const unsigned char truncated[] = { 0xe2 };
    static const unsigned char progress[] = { 'A', 0xc0 };
    static const unsigned char ascii[] = { 'A' };
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

    descriptor = iconv_open("UTF-8", "UTF-32BE");
    if (descriptor == (iconv_t)-1)
        return 3;
    input = (char *)(void *)utf32be;
    destination = (char *)(void *)output;
    input_left = sizeof(utf32be);
    output_left = sizeof(output);
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != 0 ||
        input != (char *)(void *)(utf32be + sizeof(utf32be)) || input_left != 0 ||
        destination != (char *)(void *)(output + sizeof(utf8_pair)) ||
        output_left != sizeof(output) - sizeof(utf8_pair) ||
        !bytes_equal(output, utf8_pair, sizeof(utf8_pair)) || iconv_close(descriptor) != 0)
        return 4;

    descriptor = iconv_open("UTF-16LE", "UTF-8");
    if (descriptor == (iconv_t)-1)
        return 5;
    input = (char *)(void *)invalid;
    destination = (char *)(void *)output;
    input_left = sizeof(invalid);
    output_left = sizeof(output);
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != (size_t)-1 ||
        errno != EILSEQ || input != (char *)(void *)invalid || input_left != sizeof(invalid) ||
        destination != (char *)(void *)output || output_left != sizeof(output))
        return 6;
    input = (char *)(void *)truncated;
    destination = (char *)(void *)output;
    input_left = sizeof(truncated);
    output_left = sizeof(output);
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != (size_t)-1 ||
        errno != EINVAL || input != (char *)(void *)truncated || input_left != sizeof(truncated) ||
        destination != (char *)(void *)output || output_left != sizeof(output))
        return 7;
    input = (char *)(void *)progress;
    destination = (char *)(void *)output;
    input_left = sizeof(progress);
    output_left = sizeof(output);
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != (size_t)-1 ||
        errno != EILSEQ || input != (char *)(void *)(progress + 1) || input_left != 1 ||
        destination != (char *)(void *)(output + 2) || output_left != sizeof(output) - 2 ||
        output[0] != 'A' || output[1] != 0)
        return 8;
    input = (char *)(void *)ascii;
    destination = (char *)(void *)output;
    input_left = sizeof(ascii);
    output_left = 1;
    errno = 0;
    if (iconv(descriptor, &input, &input_left, &destination, &output_left) != (size_t)-1 ||
        errno != E2BIG || input != (char *)(void *)ascii || input_left != 1 ||
        destination != (char *)(void *)output || output_left != 1 || iconv_close(descriptor) != 0)
        return 9;
    return 0;
}

int main(int argc, char **argv)
{
    locale_t c_locale;
    locale_t utf8_locale;
    int status;

    status = check_locale_core(&c_locale, &utf8_locale);
    if (status != 0)
        return status;
    status = check_thread_locale_and_errno(c_locale, utf8_locale);
    if (status != 0)
        return 20 + status;
    status = check_iconv_pointer_and_errors();
    if (status != 0)
        return 40 + status;
    if (!text_equal(setlocale(LC_ALL, NULL), "C") || MB_CUR_MAX != 1)
        return 80;
    freelocale(utf8_locale);
    freelocale(c_locale);
    status = crabc_x86_64_locale_environment_probe(argc, argv);
    if (status != 0)
        return status;
    if (argc == 2 && !strcmp(argv[1], "profile")) {
        static const char result[] = "owned-locale-environment-profile-ok\n";
        return write(STDOUT_FILENO, result, sizeof result - 1) == sizeof result - 1 ? 0 : 127;
    }
    return write(STDOUT_FILENO, "owned-locale-products-ok\n", 25) == 25 ? 0 : 127;
}
