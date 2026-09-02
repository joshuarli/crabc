/* Linux/x86-64 <netdb.h> h_errno declaration and visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef CRABC_EXPECT_H_ERRNO
#error "the runner must declare whether this feature profile exposes h_errno"
#endif

#include <netdb.h>

#if CRABC_EXPECT_H_ERRNO

/* The public x86 spelling must be the accessor macro, never a direct object
 * declaration. Its address expression makes the macro's result type visible
 * without requiring a candidate archive link in this header-only matrix. */
#ifndef h_errno
#error "this profile must expose h_errno as an accessor macro"
#endif

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef __typeof__(&__h_errno_location) h_errno_location_signature;

_Static_assert(CRABC_TYPE_IS(__typeof__(*__h_errno_location()), int),
    "__h_errno_location result declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&h_errno), int *),
    "h_errno macro expression type");

static h_errno_location_signature h_errno_location_function __attribute__((used)) =
    __h_errno_location;

int crabc_x86_64_h_errno_header_abi_probe(void)
{
    return h_errno_location_function != (h_errno_location_signature)0 &&
        &h_errno != (int *)0 ? 0 : 1;
}

#else

#ifdef h_errno
#error "this profile must not expose the h_errno macro"
#endif

int crabc_x86_64_h_errno_header_abi_probe(void)
{
    return 0;
}

#endif
