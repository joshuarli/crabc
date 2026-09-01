/* Linux/x86-64 C++ resolver-runtime public-header ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#error "this probe fixes the GNU h_errno visibility profile"
#endif

#include <netdb.h>
#include <resolv.h>
#include <stddef.h>

/* Keep the C++ profile on the same accessor boundary as C. */
#ifndef h_errno
#error "musl h_errno must be an __h_errno_location accessor macro"
#endif

using res_state_signature = struct __res_state *(*)(void);
using res_query_signature = int (*)(const char *, int, int, unsigned char *, int);
using res_send_signature = int (*)(const unsigned char *, int, unsigned char *, int);

static_assert(sizeof(struct __res_state) == 568 && alignof(struct __res_state) == 8,
    "musl __res_state x86-64 size/alignment");
static_assert(offsetof(struct __res_state, dnsrch) == 72 &&
    offsetof(struct __res_state, defdname) == 128 &&
    offsetof(struct __res_state, sort_list) == 396 &&
    offsetof(struct __res_state, _u) == 512,
    "musl __res_state x86-64 fields");
static_assert(__is_same(decltype(&__res_state), res_state_signature),
    "__res_state C linkage");
static_assert(__is_same(decltype(*__h_errno_location()), int &),
    "__h_errno_location result declaration");
static_assert(__is_same(decltype(&res_query), res_query_signature),
    "res_query C linkage");
static_assert(__is_same(decltype(&res_send), res_send_signature),
    "res_send C linkage");
static_assert(__is_same(decltype(&h_errno), int *), "h_errno object declaration");

static res_state_signature state_function __attribute__((used)) = __res_state;
static auto h_errno_function __attribute__((used)) = &__h_errno_location;
static res_query_signature query_function __attribute__((used)) = res_query;

int crabc_x86_64_resolver_runtime_header_abi_probe_cpp()
{
    return state_function != nullptr && h_errno_function != nullptr &&
        query_function != nullptr ? 0 : 1;
}
