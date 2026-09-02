/* Pinned-musl/project Linux/x86-64 ualarm declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_UALARM)
typedef unsigned int (*ualarm_signature)(unsigned int, unsigned int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&ualarm),
    ualarm_signature), "ualarm declaration");

static ualarm_signature ualarm_function = ualarm;
#endif

/* An opt-in reference that must fail when the extension is hidden. */
#if defined(CRABC_REQUIRE_UALARM_HIDDEN)
typedef unsigned int (*hidden_ualarm_signature)(unsigned int, unsigned int);
static hidden_ualarm_signature ualarm_must_be_hidden = ualarm;
#endif

int crabc_x86_64_ualarm_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_UALARM)
    return ualarm_function != (ualarm_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
