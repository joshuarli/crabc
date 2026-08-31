/* Pinned-musl/project Linux/x86-64 legacy Ethernet-line declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <netinet/ether.h>

typedef int (*ether_line_signature)(const char *, struct ether_addr *, char *);

_Static_assert(ETH_ALEN == 6, "Ethernet address width");
_Static_assert(sizeof(struct ether_addr) == 6, "ether_addr size");
_Static_assert(_Alignof(struct ether_addr) == 1, "ether_addr alignment");
_Static_assert(offsetof(struct ether_addr, ether_addr_octet) == 0,
               "ether_addr octets offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_line),
                                             ether_line_signature),
               "ether_line declaration");

static ether_line_signature ether_line_function __attribute__((used)) = ether_line;

int crabc_x86_64_ether_line_header_abi_probe(void)
{
    return ether_line_function != (ether_line_signature)0 ? 0 : 1;
}
