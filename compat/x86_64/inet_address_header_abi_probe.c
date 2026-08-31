/* Native Linux/x86-64 <arpa/inet.h> numeric-address declaration ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <arpa/inet.h>
#include <stddef.h>

typedef int (*inet_pton_signature)(int, const char *, void *);
typedef const char *(*inet_ntop_signature)(int, const void *, char *, socklen_t);
typedef int (*inet_aton_signature)(const char *, struct in_addr *);
typedef in_addr_t (*inet_addr_signature)(const char *);
typedef in_addr_t (*inet_network_signature)(const char *);
typedef char *(*inet_ntoa_signature)(struct in_addr);
typedef struct in_addr (*inet_makeaddr_signature)(in_addr_t, in_addr_t);
typedef in_addr_t (*inet_lnaof_signature)(struct in_addr);
typedef in_addr_t (*inet_netof_signature)(struct in_addr);

_Static_assert(sizeof(in_addr_t) == 4 && _Alignof(in_addr_t) == 4,
    "x86 in_addr_t width/alignment");
_Static_assert(sizeof(in_port_t) == 2 && _Alignof(in_port_t) == 2,
    "x86 in_port_t width/alignment");
_Static_assert(sizeof(struct in_addr) == 4 && _Alignof(struct in_addr) == 4 &&
    offsetof(struct in_addr, s_addr) == 0,
    "x86 in_addr layout");
_Static_assert(INET_ADDRSTRLEN == 16 && INET6_ADDRSTRLEN == 46,
    "numeric address text-buffer constants");

_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_pton),
    inet_pton_signature), "inet_pton declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_ntop),
    inet_ntop_signature), "inet_ntop declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_aton),
    inet_aton_signature), "inet_aton declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_addr),
    inet_addr_signature), "inet_addr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_network),
    inet_network_signature), "inet_network declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_ntoa),
    inet_ntoa_signature), "inet_ntoa declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_makeaddr),
    inet_makeaddr_signature), "inet_makeaddr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_lnaof),
    inet_lnaof_signature), "inet_lnaof declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_netof),
    inet_netof_signature), "inet_netof declaration");

static inet_pton_signature inet_pton_function = inet_pton;
static inet_ntop_signature inet_ntop_function = inet_ntop;
static inet_aton_signature inet_aton_function = inet_aton;
static inet_addr_signature inet_addr_function = inet_addr;
static inet_network_signature inet_network_function = inet_network;
static inet_ntoa_signature inet_ntoa_function = inet_ntoa;
static inet_makeaddr_signature inet_makeaddr_function = inet_makeaddr;
static inet_lnaof_signature inet_lnaof_function = inet_lnaof;
static inet_netof_signature inet_netof_function = inet_netof;

int crabc_x86_64_inet_address_header_abi_probe(void)
{
    (void)inet_pton_function;
    (void)inet_ntop_function;
    (void)inet_aton_function;
    (void)inet_addr_function;
    (void)inet_network_function;
    (void)inet_ntoa_function;
    (void)inet_makeaddr_function;
    (void)inet_lnaof_function;
    (void)inet_netof_function;
    return 0;
}
