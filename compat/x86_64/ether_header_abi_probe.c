/* Pinned-musl/project Linux/x86-64 ether.c declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <netinet/ether.h>

typedef struct ether_addr *(*ether_aton_signature)(const char *);
typedef struct ether_addr *(*ether_aton_r_signature)(const char *,
                                                       struct ether_addr *);
typedef char *(*ether_ntoa_signature)(const struct ether_addr *);
typedef char *(*ether_ntoa_r_signature)(const struct ether_addr *, char *);
typedef int (*ether_line_signature)(const char *, struct ether_addr *, char *);
typedef int (*ether_ntohost_signature)(char *, const struct ether_addr *);
typedef int (*ether_hostton_signature)(const char *, struct ether_addr *);

_Static_assert(ETH_ALEN == 6, "Ethernet address width");
_Static_assert(sizeof(struct ether_addr) == 6, "ether_addr size");
_Static_assert(_Alignof(struct ether_addr) == 1, "ether_addr alignment");
_Static_assert(offsetof(struct ether_addr, ether_addr_octet) == 0,
               "ether_addr octets offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_aton),
                                             ether_aton_signature),
               "ether_aton declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_aton_r),
                                             ether_aton_r_signature),
               "ether_aton_r declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_ntoa),
                                             ether_ntoa_signature),
               "ether_ntoa declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_ntoa_r),
                                             ether_ntoa_r_signature),
               "ether_ntoa_r declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_line),
                                             ether_line_signature),
               "ether_line declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_ntohost),
                                             ether_ntohost_signature),
               "ether_ntohost declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_hostton),
                                             ether_hostton_signature),
               "ether_hostton declaration");

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

int crabc_x86_64_ether_header_abi_probe(void)
{
    return ether_aton_function != (ether_aton_signature)0 &&
            ether_aton_r_function != (ether_aton_r_signature)0 &&
            ether_ntoa_function != (ether_ntoa_signature)0 &&
            ether_ntoa_r_function != (ether_ntoa_r_signature)0 &&
            ether_line_function != (ether_line_signature)0 &&
            ether_ntohost_function != (ether_ntohost_signature)0 &&
            ether_hostton_function != (ether_hostton_signature)0
        ? 0
        : 1;
}
