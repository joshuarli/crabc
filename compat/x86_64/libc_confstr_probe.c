/* Static Linux/x86-64 confstr C ABI and behavior fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * through a `--gc-sections` true-static crabc archive candidate. It observes
 * only musl's fixed `_CS_PATH` and empty selected configuration strings,
 * caller-buffer query/copy/truncation rules, and invalid-selector errno. It
 * does not select sysconf, pathconf, filesystem configuration, or a general
 * runtime configuration facility.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <unistd.h>

typedef size_t (*confstr_signature)(int, char *, size_t);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&confstr),
    confstr_signature), "confstr declaration");
_Static_assert(_CS_PATH == 0 && _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS == 1 &&
    _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS == 5, "selected confstr selectors");

static int text_equal(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static int check_path(confstr_signature function)
{
    static const char expected[] = "/bin:/usr/bin";
    char full[sizeof expected];
    char short_buffer[5] = { 'X', 'X', 'X', 'X', 'X' };
    char one_byte[1] = { 'X' };
    char untouched = 'X';
    const size_t required = sizeof expected;

    errno = E2BIG;
    if (function(_CS_PATH, 0, 0) != required || errno != E2BIG)
        return 1;
    if (function(_CS_PATH, full, sizeof full) != required ||
        !text_equal(full, expected) || errno != E2BIG)
        return 2;
    if (function(_CS_PATH, short_buffer, sizeof short_buffer) != required ||
        !text_equal(short_buffer, "/bin") || errno != E2BIG)
        return 3;
    if (function(_CS_PATH, one_byte, sizeof one_byte) != required ||
        one_byte[0] != '\0' || errno != E2BIG)
        return 4;
    if (function(_CS_PATH, &untouched, 0) != required || untouched != 'X' ||
        errno != E2BIG)
        return 5;
    return 0;
}

static int check_empty_values(confstr_signature function)
{
    char buffer[2] = { 'X', 'Y' };
    int name;

    for (name = _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS;
         name <= _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS; name += 4) {
        errno = E2BIG;
        if (function(name, buffer, sizeof buffer) != 1 || buffer[0] != '\0' ||
            errno != E2BIG)
            return 1;
    }
    for (name = _CS_POSIX_V6_ILP32_OFF32_CFLAGS;
         name <= _CS_POSIX_V7_THREADS_LDFLAGS; name++) {
        errno = E2BIG;
        buffer[0] = 'X';
        if (function(name, buffer, sizeof buffer) != 1 || buffer[0] != '\0' ||
            errno != E2BIG)
            return 2;
    }
    return 0;
}

static int check_invalid_selector(confstr_signature function)
{
    char untouched = 'X';

    errno = E2BIG;
    if (function(-1, &untouched, 1) != 0 || untouched != 'X' || errno != EINVAL)
        return 1;
    return 0;
}

int crabc_x86_64_confstr_probe(void)
{
    const confstr_signature function = confstr;
    int result = check_path(function);

    if (result != 0)
        return result;
    result = check_empty_values(function);
    if (result != 0)
        return 10 + result;
    result = check_invalid_selector(function);
    if (result != 0)
        return 20 + result;
    return 0;
}

#ifndef CRABC_CONFSTR_FREESTANDING
int main(void)
{
    return crabc_x86_64_confstr_probe();
}
#endif
