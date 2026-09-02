/* Linux/x86-64 C++17 <netdb.h> h_errno declaration and linkage probe. */

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

#ifndef h_errno
#error "this profile must expose h_errno as an accessor macro"
#endif

using h_errno_location_signature = decltype(&__h_errno_location);

static_assert(__is_same(decltype(*__h_errno_location()), int &),
    "__h_errno_location result declaration");
static_assert(__is_same(decltype(&h_errno), int *),
    "h_errno macro expression type");

static h_errno_location_signature h_errno_location_function __attribute__((used)) =
    &__h_errno_location;

extern "C" int crabc_x86_64_h_errno_header_abi_probe_cpp()
{
    return h_errno_location_function != nullptr && &h_errno != nullptr ? 0 : 1;
}

#else

#ifdef h_errno
#error "this profile must not expose the h_errno macro"
#endif

extern "C" int crabc_x86_64_h_errno_header_abi_probe_cpp()
{
    return 0;
}

#endif
