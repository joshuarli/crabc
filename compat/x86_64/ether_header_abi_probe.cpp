/* C++17 companion for the pinned-musl/project Linux/x86-64 ether.c gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <netinet/ether.h>

using ether_aton_signature = struct ether_addr *(*)(const char *);
using ether_aton_r_signature = struct ether_addr *(*)(const char *,
                                                        struct ether_addr *);
using ether_ntoa_signature = char *(*)(const struct ether_addr *);
using ether_ntoa_r_signature = char *(*)(const struct ether_addr *, char *);
using ether_line_signature = int (*)(const char *, struct ether_addr *, char *);
using ether_ntohost_signature = int (*)(char *, const struct ether_addr *);
using ether_hostton_signature = int (*)(const char *, struct ether_addr *);

static_assert(ETH_ALEN == 6, "Ethernet address width");
static_assert(sizeof(struct ether_addr) == 6, "ether_addr size");
static_assert(alignof(struct ether_addr) == 1, "ether_addr alignment");
static_assert(offsetof(struct ether_addr, ether_addr_octet) == 0,
              "ether_addr octets offset");
static_assert(__is_same(decltype(&ether_aton), ether_aton_signature),
              "C++ ether_aton declaration");
static_assert(__is_same(decltype(&ether_aton_r), ether_aton_r_signature),
              "C++ ether_aton_r declaration");
static_assert(__is_same(decltype(&ether_ntoa), ether_ntoa_signature),
              "C++ ether_ntoa declaration");
static_assert(__is_same(decltype(&ether_ntoa_r), ether_ntoa_r_signature),
              "C++ ether_ntoa_r declaration");
static_assert(__is_same(decltype(&ether_line), ether_line_signature),
              "C++ ether_line declaration");
static_assert(__is_same(decltype(&ether_ntohost), ether_ntohost_signature),
              "C++ ether_ntohost declaration");
static_assert(__is_same(decltype(&ether_hostton), ether_hostton_signature),
              "C++ ether_hostton declaration");

static ether_aton_signature ether_aton_function __attribute__((used)) = ether_aton;
static ether_aton_r_signature ether_aton_r_function __attribute__((used)) =
    ether_aton_r;
static ether_ntoa_signature ether_ntoa_function __attribute__((used)) = ether_ntoa;
static ether_ntoa_r_signature ether_ntoa_r_function __attribute__((used)) =
    ether_ntoa_r;
static ether_line_signature ether_line_function __attribute__((used)) = ether_line;
static ether_ntohost_signature ether_ntohost_function __attribute__((used)) =
    ether_ntohost;
static ether_hostton_signature ether_hostton_function __attribute__((used)) =
    ether_hostton;

int crabc_x86_64_ether_header_abi_probe_cpp()
{
    return ether_aton_function != nullptr && ether_aton_r_function != nullptr &&
            ether_ntoa_function != nullptr && ether_ntoa_r_function != nullptr &&
            ether_line_function != nullptr && ether_ntohost_function != nullptr &&
            ether_hostton_function != nullptr
        ? 0
        : 1;
}
