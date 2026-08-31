/* Static crabc-libc x86-64 hstrerror fixture.
 *
 * This one project-header C body first runs against pinned musl 1.2.6 and
 * then as a freestanding -nostdlib/static candidate linked only through the
 * selected archive. It deliberately selects only hstrerror's immutable
 * fixed-profile h_errno message lookup; it does not read or modify h_errno,
 * parse hosts/resolver configuration, inspect a network database, or issue a
 * DNS or socket request.
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
#include <netdb.h>
#include <stddef.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef const char *(*hstrerror_signature)(int);

_Static_assert(HOST_NOT_FOUND == 1 && TRY_AGAIN == 2 && NO_RECOVERY == 3 &&
    NO_DATA == 4 && NO_ADDRESS == NO_DATA,
    "GNU/BSD h_errno values");
_Static_assert(CRABC_TYPE_IS(__typeof__(&hstrerror), hstrerror_signature),
    "hstrerror declaration");

static int text_equal(const char *left, const char *right)
{
    size_t index = 0;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int check_message(int code, const char *expected)
{
    const char *actual = hstrerror(code);
    return actual != NULL && text_equal(actual, expected);
}

int crabc_x86_64_hstrerror_probe(void)
{
    const char *host_not_found;

#ifndef CRABC_HSTRERROR_FREESTANDING
    errno = E2BIG;
#endif

    if (!check_message(-1, "Unknown error")) return 1;
    if (!check_message(0, "Unknown error")) return 2;
    if (!check_message(HOST_NOT_FOUND, "Host not found")) return 3;
    if (!check_message(TRY_AGAIN, "Try again")) return 4;
    if (!check_message(NO_RECOVERY, "Non-recoverable error")) return 5;
    if (!check_message(NO_DATA, "Address not available")) return 6;
    if (!check_message(5, "Unknown error")) return 7;
    if (!check_message(99, "Unknown error")) return 8;

    host_not_found = hstrerror(HOST_NOT_FOUND);
    if (host_not_found != hstrerror(HOST_NOT_FOUND)) return 9;
    if (host_not_found == hstrerror(TRY_AGAIN)) return 10;

#ifndef CRABC_HSTRERROR_FREESTANDING
    if (errno != E2BIG) return 11;
#endif
    return 0;
}

#ifndef CRABC_HSTRERROR_FREESTANDING
int main(void)
{
    return crabc_x86_64_hstrerror_probe();
}
#endif
