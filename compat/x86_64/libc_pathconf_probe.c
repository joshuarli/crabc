/* Static Linux/x86-64 pathconf C ABI and behavior fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * through a `--gc-sections` true-static crabc archive candidate. It observes
 * only musl's `pathconf` delegation to the fixed fpathconf table for selectors
 * 0 through 20, the ignored pathname on those valid selectors, stale errno
 * preservation, and the defined nonnegative out-of-range EINVAL result.
 * Pinned musl's delegated fpathconf source indexes a negative selector without
 * a source-defined result, so that input is deliberately outside this
 * differential contract.
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
#include <limits.h>
#include <unistd.h>

typedef long (*pathconf_signature)(const char *, int);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pathconf),
    pathconf_signature), "pathconf declaration");
_Static_assert(_PC_LINK_MAX == 0 && _PC_2_SYMLINKS == 20 &&
    _PC_FILESIZEBITS == 13 && _PC_REC_INCR_XFER_SIZE == 14,
    "selected pathconf selectors");

static const char ignored_path[] = "/pathconf-does-not-inspect-this";
static const long expected_values[] = {
    8, 255, 255, 255, 4096, 4096, 1, 1, 0, 1, -1,
    -1, -1, 64, 4096, 4096, 4096, 4096, 4096, -1, 1,
};

static int check_direct_values(void)
{
    int name;

    for (name = 0; name < (int)(sizeof expected_values / sizeof expected_values[0]);
         name++) {
        errno = E2BIG;
        if (pathconf((const char *)0, name) != expected_values[name] ||
            errno != E2BIG)
            return 1 + name;
    }
    return 0;
}

static int check_indirect_values(pathconf_signature function)
{
    int name;

    for (name = 0; name < (int)(sizeof expected_values / sizeof expected_values[0]);
         name++) {
        errno = E2BIG;
        if (function(ignored_path, name) != expected_values[name] ||
            errno != E2BIG)
            return 1 + name;
    }
    return 0;
}

static int check_nonnegative_invalid(pathconf_signature function)
{
    errno = E2BIG;
    if (function((const char *)0, 21) != -1 || errno != EINVAL)
        return 1;
    errno = E2BIG;
    if (function(ignored_path, INT_MAX) != -1 || errno != EINVAL)
        return 2;
    return 0;
}

int crabc_x86_64_pathconf_probe(void)
{
    const pathconf_signature indirect = pathconf;
    int result = check_direct_values();

    if (result != 0)
        return result;
    result = check_indirect_values(indirect);
    if (result != 0)
        return 30 + result;
    result = check_nonnegative_invalid(indirect);
    return result == 0 ? 0 : 60 + result;
}

#ifndef CRABC_PATHCONF_FREESTANDING
int main(void)
{
    return crabc_x86_64_pathconf_probe();
}
#endif
