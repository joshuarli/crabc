/* C++17 companion for the pinned-musl/project proto.c declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <netdb.h>

using endprotoent_signature = void (*)(void);
using getprotobyname_signature = protoent *(*)(const char *);
using getprotobynumber_signature = protoent *(*)(int);
using getprotoent_signature = protoent *(*)(void);
using setprotoent_signature = void (*)(int);

static_assert(sizeof(protoent) == 24, "C++ protoent size");
static_assert(alignof(protoent) == 8, "C++ protoent alignment");
static_assert(offsetof(protoent, p_name) == 0, "C++ protoent name offset");
static_assert(offsetof(protoent, p_aliases) == 8,
              "C++ protoent aliases offset");
static_assert(offsetof(protoent, p_proto) == 16,
              "C++ protoent number offset");
static_assert(__is_same(decltype(&endprotoent), endprotoent_signature),
              "C++ endprotoent declaration");
static_assert(__is_same(decltype(&getprotobyname), getprotobyname_signature),
              "C++ getprotobyname declaration");
static_assert(__is_same(decltype(&getprotobynumber), getprotobynumber_signature),
              "C++ getprotobynumber declaration");
static_assert(__is_same(decltype(&getprotoent), getprotoent_signature),
              "C++ getprotoent declaration");
static_assert(__is_same(decltype(&setprotoent), setprotoent_signature),
              "C++ setprotoent declaration");

static endprotoent_signature endprotoent_function __attribute__((used)) =
    endprotoent;
static getprotobyname_signature getprotobyname_function __attribute__((used)) =
    getprotobyname;
static getprotobynumber_signature getprotobynumber_function __attribute__((used)) =
    getprotobynumber;
static getprotoent_signature getprotoent_function __attribute__((used)) =
    getprotoent;
static setprotoent_signature setprotoent_function __attribute__((used)) =
    setprotoent;

int crabc_x86_64_protocol_database_header_abi_probe_cpp()
{
    return endprotoent_function != nullptr && getprotobyname_function != nullptr &&
            getprotobynumber_function != nullptr && getprotoent_function != nullptr &&
            setprotoent_function != nullptr
        ? 0
        : 1;
}
