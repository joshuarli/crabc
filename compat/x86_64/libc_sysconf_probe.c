/* Static Linux/x86-64 selected sysconf C ABI and behavior fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * through a `--gc-sections` true-static crabc archive candidate. It observes
 * only musl's direct static-table entries for _SC_CLK_TCK and _SC_PAGE_SIZE,
 * stale errno preservation, and the defined far nonnegative-invalid EINVAL
 * result. The pinned source has a much wider table whose other names can reach
 * rlimit, scheduler, system-information, or auxv state; those selectors are
 * deliberately outside this differential contract. It also indexes negative
 * selectors without a source-defined result, so negative inputs are excluded.
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

typedef long (*sysconf_signature)(int);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sysconf),
    sysconf_signature), "sysconf declaration");
_Static_assert(_SC_CLK_TCK == 2 && _SC_PAGE_SIZE == 30 &&
    _SC_PAGESIZE == _SC_PAGE_SIZE, "selected sysconf selectors");

static int check_direct_selected_values(void)
{
    errno = E2BIG;
    if (sysconf(_SC_CLK_TCK) != 100 || errno != E2BIG)
        return 1;
    errno = E2BIG;
    if (sysconf(_SC_PAGE_SIZE) != 4096 || errno != E2BIG)
        return 2;
    return 0;
}

static int check_indirect_selected_values(sysconf_signature function)
{
    errno = E2BIG;
    if (function(_SC_CLK_TCK) != 100 || errno != E2BIG)
        return 1;
    errno = E2BIG;
    if (function(_SC_PAGESIZE) != 4096 || errno != E2BIG)
        return 2;
    return 0;
}

static int check_far_nonnegative_invalid(sysconf_signature function)
{
    errno = E2BIG;
    if (function(INT_MAX) != -1 || errno != EINVAL)
        return 1;
    return 0;
}

int crabc_x86_64_sysconf_probe(void)
{
    const sysconf_signature indirect = sysconf;
    int result = check_direct_selected_values();

    if (result != 0)
        return result;
    result = check_indirect_selected_values(indirect);
    if (result != 0)
        return 20 + result;
    result = check_far_nonnegative_invalid(indirect);
    return result == 0 ? 0 : 40 + result;
}

#ifndef CRABC_SYSCONF_FREESTANDING
int main(void)
{
    return crabc_x86_64_sysconf_probe();
}
#endif
