/* Source-only Linux/x86-64 base socket transport header ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

_Static_assert(sizeof(sa_family_t) == 2 && _Alignof(sa_family_t) == 2,
    "x86 sa_family_t width/alignment");
_Static_assert(sizeof(socklen_t) == 4 && _Alignof(socklen_t) == 4,
    "x86 socklen_t width/alignment");
_Static_assert(sizeof(struct sockaddr) == 16 && _Alignof(struct sockaddr) == 2,
    "x86 sockaddr size/alignment");
_Static_assert(offsetof(struct sockaddr, sa_family) == 0 &&
    offsetof(struct sockaddr, sa_data) == 2,
    "x86 sockaddr offsets");
_Static_assert(sizeof(struct sockaddr_storage) == 128 &&
    _Alignof(struct sockaddr_storage) == 8 &&
    offsetof(struct sockaddr_storage, ss_family) == 0 &&
    offsetof(struct sockaddr_storage, __ss_align) == 120,
    "x86 sockaddr_storage layout");
_Static_assert(sizeof(struct sockaddr_in) == 16 &&
    _Alignof(struct sockaddr_in) == 4 &&
    offsetof(struct sockaddr_in, sin_family) == 0 &&
    offsetof(struct sockaddr_in, sin_port) == 2 &&
    offsetof(struct sockaddr_in, sin_addr) == 4,
    "x86 sockaddr_in layout");
_Static_assert(sizeof(struct sockaddr_in6) == 28 &&
    _Alignof(struct sockaddr_in6) == 4 &&
    offsetof(struct sockaddr_in6, sin6_family) == 0 &&
    offsetof(struct sockaddr_in6, sin6_port) == 2 &&
    offsetof(struct sockaddr_in6, sin6_flowinfo) == 4 &&
    offsetof(struct sockaddr_in6, sin6_addr) == 8 &&
    offsetof(struct sockaddr_in6, sin6_scope_id) == 24,
    "x86 sockaddr_in6 layout");
_Static_assert(sizeof(struct in6_addr) == 16 && _Alignof(struct in6_addr) == 4 &&
    offsetof(struct in6_addr, s6_addr) == 0,
    "x86 in6_addr layout");
_Static_assert(__builtin_types_compatible_p(__typeof__(&in6addr_any),
    const struct in6_addr *), "in6addr_any declaration");

_Static_assert(AF_UNSPEC == 0 && AF_UNIX == 1 && AF_INET == 2 && AF_INET6 == 10,
    "Linux address-family values");
_Static_assert(SOCK_STREAM == 1 && SOCK_DGRAM == 2 && SOCK_SEQPACKET == 5,
    "Linux base socket-type values");
_Static_assert(SOCK_CLOEXEC == 02000000 && SOCK_NONBLOCK == 04000,
    "Linux socket creation flags");
_Static_assert(SHUT_RD == 0 && SHUT_WR == 1 && SHUT_RDWR == 2 && SOMAXCONN == 128,
    "Linux shutdown and listen constants");
_Static_assert(MSG_OOB == 1 && MSG_PEEK == 2 && MSG_DONTROUTE == 4 &&
    MSG_TRUNC == 0x20 && MSG_EOR == 0x80 && MSG_WAITALL == 0x100 &&
    MSG_NOSIGNAL == 0x4000,
    "Linux basic send/receive flags");

_Static_assert(__builtin_types_compatible_p(__typeof__(&socket),
    int (*)(int, int, int)), "socket declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&socketpair),
    int (*)(int, int, int, int *)), "socketpair declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&bind),
    int (*)(int, const struct sockaddr *, socklen_t)), "bind declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&listen),
    int (*)(int, int)), "listen declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&accept),
    int (*)(int, struct sockaddr *, socklen_t *)), "accept declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&accept4),
    int (*)(int, struct sockaddr *, socklen_t *, int)), "accept4 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&connect),
    int (*)(int, const struct sockaddr *, socklen_t)), "connect declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&send),
    ssize_t (*)(int, const void *, size_t, int)), "send declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&recv),
    ssize_t (*)(int, void *, size_t, int)), "recv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sendto),
    ssize_t (*)(int, const void *, size_t, int, const struct sockaddr *, socklen_t)),
    "sendto declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&recvfrom),
    ssize_t (*)(int, void *, size_t, int, struct sockaddr *, socklen_t *)),
    "recvfrom declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&shutdown),
    int (*)(int, int)), "shutdown declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getsockname),
    int (*)(int, struct sockaddr *, socklen_t *)), "getsockname declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpeername),
    int (*)(int, struct sockaddr *, socklen_t *)), "getpeername declaration");

int crabc_x86_64_socket_header_abi_probe(void)
{
    struct sockaddr_storage address = {0};
    return (int)sizeof(address);
}
