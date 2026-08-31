/* Selected Linux/x86-64 sync C header ABI facts. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef void (*sync_signature)(void);

#if defined(CRABC_EXPECT_SYNC)
_Static_assert(__builtin_types_compatible_p(__typeof__(&sync), sync_signature),
               "sync declaration");
__attribute__((used)) static sync_signature crabc_sync = sync;
#endif

/* This branch is compiled only as an expected-failure visibility check. */
#if defined(CRABC_REQUIRE_SYNC_HIDDEN)
static sync_signature sync_must_be_hidden = sync;
#endif

int crabc_x86_64_sync_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_SYNC)
    crabc_sync();
#endif
    return 0;
}
