/* C++17 companion for the Linux/x86-64 legacy Ethernet-line declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <netinet/ether.h>

using ether_line_signature = int (*)(const char *, struct ether_addr *, char *);

static_assert(ETH_ALEN == 6, "Ethernet address width");
static_assert(sizeof(struct ether_addr) == 6, "ether_addr size");
static_assert(alignof(struct ether_addr) == 1, "ether_addr alignment");
static_assert(offsetof(struct ether_addr, ether_addr_octet) == 0,
              "ether_addr octets offset");
static_assert(__is_same(decltype(&ether_line), ether_line_signature),
              "C++ ether_line declaration");

static ether_line_signature ether_line_function __attribute__((used)) = ether_line;

int crabc_x86_64_ether_line_header_abi_probe_cpp()
{
    return ether_line_function != nullptr ? 0 : 1;
}
