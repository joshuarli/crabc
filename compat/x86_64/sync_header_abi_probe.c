/* Pinned-musl/project Linux/x86-64 sync declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_SYNC)
typedef void (*sync_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sync),
    sync_signature), "sync declaration");

static sync_signature sync_function = sync;
#endif

/* An opt-in reference that must fail under strict/POSIX-only selectors. */
#if defined(CRABC_REQUIRE_SYNC_HIDDEN)
typedef void (*hidden_sync_signature)(void);
static hidden_sync_signature sync_must_be_hidden = sync;
#endif

int crabc_x86_64_sync_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_SYNC)
    return sync_function != (sync_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
