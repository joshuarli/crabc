/* Static Linux/x86-64 basename C ABI and behavior fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6
 * and then through a true one-member `-nostdlib -static` crabc candidate. It
 * selects only musl's caller-owned mutable basename scan: null/empty dot
 * fallback, trailing-slash removal, the returned input offset, and musl's
 * weak same-address __xpg_basename alias. It does not select dirname,
 * filesystem lookup, pathname normalization, errno/TLS, allocation, locale,
 * or any string helper ABI.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <libgen.h>

typedef char *(*basename_signature)(char *);
extern char *__xpg_basename(char *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&basename),
    basename_signature), "basename declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&__xpg_basename),
    basename_signature), "__xpg_basename declaration");

static int copy_text(char *destination, unsigned long capacity,
    const char *source)
{
    unsigned long index;

    for (index = 0; index < capacity; ++index) {
        destination[index] = source[index];
        if (source[index] == '\0')
            return 0;
    }
    return 1;
}

static int same_text(const char *left, const char *right)
{
    unsigned long index = 0;

    for (;;) {
        if (left[index] != right[index])
            return 0;
        if (left[index] == '\0')
            return 1;
        ++index;
    }
}

static int same_bytes(const unsigned char *left, const unsigned char *right,
    unsigned long count)
{
    unsigned long index;

    for (index = 0; index < count; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static int check_case(const char *initial, const char *expected_result,
    const char *expected_input, long expected_offset)
{
    char input[64];
    char *result;

    if (copy_text(input, sizeof(input), initial) != 0)
        return 1;
    result = basename(input);
    if (!same_text(result, expected_result))
        return 2;
    if (expected_offset < 0 ? result == input : result != input + expected_offset)
        return 3;
    if (!same_text(input, expected_input))
        return 4;
    return 0;
}

static int check_null(void)
{
    char *result = basename((char *)0);

    return result != (char *)0 && same_text(result, ".") ? 0 : 1;
}

static int check_trailing_slash_bytes(void)
{
    char input[] = "dir/file///";
    static const unsigned char expected[] = {
        'd', 'i', 'r', '/', 'f', 'i', 'l', 'e', 0, 0, 0, 0,
    };
    char *result = basename(input);

    if (result != input + 4 || !same_text(result, "file"))
        return 1;
    return same_bytes((const unsigned char *)input, expected, sizeof(expected)) ? 0 : 2;
}

static int check_all_slash_bytes(void)
{
    char input[] = "///";
    static const unsigned char expected[] = { '/', 0, 0, 0 };
    char *result = basename(input);

    if (result != input || !same_text(result, "/"))
        return 1;
    return same_bytes((const unsigned char *)input, expected, sizeof(expected)) ? 0 : 2;
}

static int check_weak_alias(void)
{
    char direct[] = "dir/item///";
    char alias[] = "dir/item///";
    char *direct_result;
    char *alias_result;

    if (&basename != &__xpg_basename)
        return 1;
    direct_result = basename(direct);
    alias_result = __xpg_basename(alias);
    if (direct_result - direct != alias_result - alias)
        return 2;
    if (!same_text(direct_result, alias_result) || !same_text(direct, alias))
        return 3;
    return 0;
}

int crabc_x86_64_basename_probe(void)
{
    static const struct {
        const char *initial;
        const char *result;
        const char *input;
        long offset;
    } cases[] = {
        {"", ".", "", -1},
        {"name", "name", "name", 0},
        {"name/", "name", "name", 0},
        {"name//", "name", "name", 0},
        {"dir/file", "file", "dir/file", 4},
        {"dir//file", "file", "dir//file", 5},
        {"/file", "file", "/file", 1},
        {"//file", "file", "//file", 2},
        {"/", "/", "/", 0},
        {"./", ".", ".", 0},
        {".", ".", ".", 0},
        {"..", "..", "..", 0},
        {"a/.", ".", "a/.", 2},
        {"a/..", "..", "a/..", 2},
    };
    unsigned long index;
    int status;

    if (check_null() != 0)
        return 1;
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        status = check_case(cases[index].initial, cases[index].result,
            cases[index].input, cases[index].offset);
        if (status != 0)
            return 10 + (int)(index * 10) + status;
    }
    if (check_trailing_slash_bytes() != 0)
        return 160;
    if (check_all_slash_bytes() != 0)
        return 161;
    return check_weak_alias() == 0 ? 0 : 170;
}

#ifndef CRABC_BASENAME_FREESTANDING
int main(void)
{
    return crabc_x86_64_basename_probe();
}
#endif
