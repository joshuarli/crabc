/* Caller-owned restart state and output capacity, using live ordinary arrays. */
#define _GNU_SOURCE
#include <errno.h>
#include <locale.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>

static int failures;
static void require(int condition) { if (!condition) ++failures; }

static void resumed_conversion(const char *text, size_t prefix, wchar_t scalar,
    size_t capacity, int count_only)
{
    mbstate_t state = {0}, saved;
    wchar_t output[4] = {0x5555, 0x5555, 0x5555, 0x5555};
    const char *source = text + prefix;
    require(mbrtowc(NULL, text, prefix, &state) == (size_t)-2);
    require(!mbsinit(&state));
    memcpy(&saved, &state, sizeof state);
    errno = EINTR;
    size_t result = mbsrtowcs(count_only ? NULL : output, &source, capacity, &state);
    require(errno == EINTR);
    if (count_only) {
        require(result == 2 && source == text + prefix);
        require(memcmp(&state, &saved, sizeof state) == 0);
        require(output[0] == 0x5555);
    } else if (capacity == 0) {
        require(result == 0 && source == text + prefix);
        require(memcmp(&state, &saved, sizeof state) == 0);
        require(output[0] == 0x5555 && output[1] == 0x5555);
        /* A later call must still complete the pending scalar exactly once. */
        result = mbsrtowcs(output, &source, 3, &state);
        require(result == 2 && source == NULL && mbsinit(&state));
        require(output[0] == scalar && output[1] == L'Z' && output[2] == 0);
    } else {
        require(result == (capacity == 1 ? 1 : 2) && mbsinit(&state));
        require(output[0] == scalar);
        if (capacity == 1) {
            require(source == text + strlen(text) - 1 && output[1] == 0x5555);
        } else {
            require(output[1] == L'Z');
            require(capacity == 2 ? source == text + strlen(text) : source == NULL);
            require(output[2] == (capacity == 2 ? 0x5555 : 0));
        }
    }
    require(output[3] == 0x5555);
}

static void resumed_error(const char *text, size_t prefix, size_t capacity,
    int count_only)
{
    mbstate_t state = {0}, saved;
    wchar_t output[4] = {0x5555, 0x5555, 0x5555, 0x5555};
    const char *source = text + prefix;
    require(mbrtowc(NULL, text, prefix, &state) == (size_t)-2);
    memcpy(&saved, &state, sizeof state);
    errno = EINTR;
    size_t result = mbsrtowcs(count_only ? NULL : output, &source, capacity, &state);
    if (!count_only && capacity == 0) {
        require(result == 0 && errno == EINTR && source == text + prefix);
        require(memcmp(&state, &saved, sizeof state) == 0);
    } else {
        require(result == (size_t)-1 && errno == EILSEQ);
        require(source == text + prefix - (count_only ? 0 : 1));
        require(count_only ? memcmp(&state, &saved, sizeof state) == 0 : mbsinit(&state));
    }
    require(output[0] == 0x5555 && output[1] == 0x5555 && output[3] == 0x5555);
}

#ifdef CRABC_BOUNDED_MBSTATE
static void bounded_resumed_error(const char *text, size_t prefix, int bulk)
{
    char input[160] = {0};
    wchar_t output[64];
    mbstate_t state = {0}, saved;
    for (size_t byte = 0; byte < sizeof input; ++byte) input[byte] = 'A';
    for (size_t byte = 0; byte < prefix; ++byte) input[byte] = text[byte];
    input[sizeof input - 1] = 0;
    for (size_t slot = 0; slot < 64; ++slot) output[slot] = 0x5555;
    require(mbrtowc(NULL, input, prefix, &state) == (size_t)-2);
    const char *source = input + prefix;
    memcpy(&saved, &state, sizeof state);
    errno = EINTR;
    size_t bytes = bulk ? 132 : 1;
    require(mbsnrtowcs(output, &source, bytes, 0, &state) == 0);
    require(source == input + prefix && errno == EINTR && output[0] == 0x5555);
    require(memcmp(&state, &saved, sizeof state) == 0);
    require(mbsnrtowcs(output, &source, bytes, 64, &state) == (size_t)-1);
    require(source == input + prefix - (bulk ? 1 : 0) && errno == EILSEQ);
    require(mbsinit(&state) && output[0] == 0x5555 && output[63] == 0x5555);
}
#endif

static int probe(void)
{
    const char *valid[] = {"\xc2\xa2Z", "\xe2\x82\xacZ", "\xf0\x9f\x98\x80Z"};
    const wchar_t scalars[] = {0xa2, 0x20ac, 0x1f600};
    const size_t sizes[] = {2, 3, 4};
    require(setlocale(LC_CTYPE, "C.UTF-8") != NULL);
    for (size_t sequence = 0; sequence < 3; ++sequence) {
        for (size_t prefix = 1; prefix < sizes[sequence]; ++prefix) {
#ifdef CRABC_BOUNDED_MBSTATE
            bounded_resumed_error(valid[sequence], prefix, 0);
            bounded_resumed_error(valid[sequence], prefix, 1);
#endif
#ifdef CRABC_MULTIBYTE_ZERO_CAPACITY
            resumed_conversion(valid[sequence], prefix, scalars[sequence], 0, 0);
#endif
            for (size_t capacity = 1; capacity <= 3; ++capacity)
                resumed_conversion(valid[sequence], prefix, scalars[sequence], capacity, 0);
            resumed_conversion(valid[sequence], prefix, scalars[sequence], 0, 1);
            /* Keep the prefix and all error cursor addresses in one backing array. */
            char invalid[8] = {0};
            for (size_t byte = 0; byte < prefix; ++byte) invalid[byte] = valid[sequence][byte];
            for (int terminator = 0; terminator < 2; ++terminator) {
                invalid[prefix] = terminator ? 0 : 'X';
#ifdef CRABC_MULTIBYTE_ZERO_CAPACITY
                resumed_error(invalid, prefix, 0, 0);
#endif
                resumed_error(invalid, prefix, 1, 0);
                resumed_error(invalid, prefix, 0, 1);
            }
        }
    }
    for (int utf8 = 0; utf8 < 2; ++utf8) {
        require(setlocale(LC_CTYPE, utf8 ? "C.UTF-8" : "C") != NULL);
        mbstate_t state = {0}, saved;
        wchar_t output = 0x5555;
        const char invalid[] = "\xff";
        const char *source = invalid;
        memcpy(&saved, &state, sizeof state);
        errno = EINTR;
        require(mbsrtowcs(&output, &source, 0, &state) == 0);
        require(source == invalid && output == 0x5555 && errno == EINTR);
        require(memcmp(&state, &saved, sizeof state) == 0);
    }
    return failures != 0;
}

#ifdef CRABC_MULTIBYTE_FREESTANDING
int crabc_x86_64_locale_multibyte_probe(void) { return probe(); }
#else
int main(void) { return probe(); }
#endif
