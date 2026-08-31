/* Pinned-musl/project Linux/x86-64 usleep declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_USLEEP)
typedef int (*usleep_signature)(unsigned int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&usleep),
    usleep_signature), "usleep declaration");

static usleep_signature usleep_function = usleep;
#endif

/* An opt-in reference that must fail when the extension is hidden. */
#if defined(CRABC_REQUIRE_USLEEP_HIDDEN)
typedef int (*hidden_usleep_signature)(unsigned int);
static hidden_usleep_signature usleep_must_be_hidden = usleep;
#endif

int crabc_x86_64_usleep_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_USLEEP)
    return usleep_function != (usleep_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
