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

static inet_pton_signature inet_pton_function = inet_pton;
static inet_ntop_signature inet_ntop_function = inet_ntop;
static inet_aton_signature inet_aton_function = inet_aton;
static inet_addr_signature inet_addr_function = inet_addr;

int crabc_x86_64_inet_address_header_abi_probe(void)
{
    (void)inet_pton_function;
    (void)inet_ntop_function;
    (void)inet_aton_function;
    (void)inet_addr_function;
    return 0;
}
