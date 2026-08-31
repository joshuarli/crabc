/* C++17 companion for the Linux/x86-64 sleep declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_SLEEP)
using sleep_signature = unsigned int (*)(unsigned int);

static_assert(__is_same(decltype(&sleep), sleep_signature),
    "C++ sleep declaration");

static sleep_signature sleep_function = sleep;
#endif

int crabc_x86_64_sleep_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_SLEEP)
    return sleep_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
