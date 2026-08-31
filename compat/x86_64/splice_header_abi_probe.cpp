/* C++17 companion for the Linux/x86-64 GNU splice declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <fcntl.h>

extern "C" ssize_t splice(int, off_t *, int, off_t *, size_t, unsigned);

using splice_signature = ssize_t (*)(int, off_t *, int, off_t *, size_t,
    unsigned);

#if defined(CRABC_EXPECT_SPLICE)
static_assert(__is_same(decltype(&splice), splice_signature),
    "splice declaration");
static splice_signature splice_function __attribute__((used)) = splice;
#endif

#if defined(CRABC_REQUIRE_SPLICE_HIDDEN)
static splice_signature splice_must_be_hidden __attribute__((used)) = splice;
#endif

int crabc_x86_64_splice_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_SPLICE)
    return splice_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
