/* C++ companion for the x86-64 <arpa/inet.h> numeric-address ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <arpa/inet.h>
#include <stddef.h>

using inet_pton_signature = int (*)(int, const char *, void *);
using inet_ntop_signature = const char *(*)(int, const void *, char *, socklen_t);
using inet_aton_signature = int (*)(const char *, in_addr *);
using inet_addr_signature = in_addr_t (*)(const char *);
using inet_ntoa_signature = char *(*)(in_addr);

static_assert(sizeof(in_addr_t) == 4 && alignof(in_addr_t) == 4,
    "x86 in_addr_t C++ width/alignment");
static_assert(sizeof(in_port_t) == 2 && alignof(in_port_t) == 2,
    "x86 in_port_t C++ width/alignment");
static_assert(sizeof(in_addr) == 4 && alignof(in_addr) == 4 &&
    offsetof(in_addr, s_addr) == 0,
    "x86 in_addr C++ layout");
static_assert(INET_ADDRSTRLEN == 16 && INET6_ADDRSTRLEN == 46,
    "numeric address text-buffer C++ constants");

static_assert(__is_same(decltype(&inet_pton), inet_pton_signature),
    "inet_pton C++ declaration");
static_assert(__is_same(decltype(&inet_ntop), inet_ntop_signature),
    "inet_ntop C++ declaration");
static_assert(__is_same(decltype(&inet_aton), inet_aton_signature),
    "inet_aton C++ declaration");
static_assert(__is_same(decltype(&inet_addr), inet_addr_signature),
    "inet_addr C++ declaration");
static_assert(__is_same(decltype(&inet_ntoa), inet_ntoa_signature),
    "inet_ntoa C++ declaration");

static inet_pton_signature inet_pton_function = inet_pton;
static inet_ntop_signature inet_ntop_function = inet_ntop;
static inet_aton_signature inet_aton_function = inet_aton;
static inet_addr_signature inet_addr_function = inet_addr;
static inet_ntoa_signature inet_ntoa_function = inet_ntoa;

extern "C" int inet_pton(int, const char *, void *);
extern "C" const char *inet_ntop(int, const void *, char *, socklen_t);
extern "C" int inet_aton(const char *, in_addr *);
extern "C" in_addr_t inet_addr(const char *);
extern "C" char *inet_ntoa(in_addr);

int crabc_x86_64_inet_address_header_abi_probe_cpp()
{
    (void)inet_pton_function;
    (void)inet_ntop_function;
    (void)inet_aton_function;
    (void)inet_addr_function;
    (void)inet_ntoa_function;
    return 0;
}
