/* C++ source-only companion for the x86-64 base socket transport ABI probe. */

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

static_assert(sizeof(sa_family_t) == 2 && alignof(sa_family_t) == 2,
    "x86 sa_family_t C++ width/alignment");
static_assert(sizeof(socklen_t) == 4 && alignof(socklen_t) == 4,
    "x86 socklen_t C++ width/alignment");
static_assert(sizeof(sockaddr) == 16 && alignof(sockaddr) == 2 &&
    offsetof(sockaddr, sa_family) == 0 && offsetof(sockaddr, sa_data) == 2,
    "x86 sockaddr C++ layout");
static_assert(sizeof(sockaddr_storage) == 128 && alignof(sockaddr_storage) == 8 &&
    offsetof(sockaddr_storage, ss_family) == 0 &&
    offsetof(sockaddr_storage, __ss_align) == 120,
    "x86 sockaddr_storage C++ layout");
static_assert(sizeof(sockaddr_in) == 16 && alignof(sockaddr_in) == 4 &&
    offsetof(sockaddr_in, sin_family) == 0 && offsetof(sockaddr_in, sin_port) == 2 &&
    offsetof(sockaddr_in, sin_addr) == 4,
    "x86 sockaddr_in C++ layout");
static_assert(sizeof(sockaddr_in6) == 28 && alignof(sockaddr_in6) == 4 &&
    offsetof(sockaddr_in6, sin6_family) == 0 &&
    offsetof(sockaddr_in6, sin6_port) == 2 &&
    offsetof(sockaddr_in6, sin6_flowinfo) == 4 &&
    offsetof(sockaddr_in6, sin6_addr) == 8 &&
    offsetof(sockaddr_in6, sin6_scope_id) == 24,
    "x86 sockaddr_in6 C++ layout");
static_assert(AF_UNSPEC == 0 && AF_UNIX == 1 && AF_INET == 2 && AF_INET6 == 10 &&
    SOCK_STREAM == 1 && SOCK_DGRAM == 2 && SOCK_SEQPACKET == 5 &&
    SOCK_CLOEXEC == 02000000 && SOCK_NONBLOCK == 04000,
    "Linux base socket constants");
static_assert(SHUT_RD == 0 && SHUT_WR == 1 && SHUT_RDWR == 2 && SOMAXCONN == 128 &&
    MSG_OOB == 1 && MSG_PEEK == 2 && MSG_DONTROUTE == 4 && MSG_TRUNC == 0x20 &&
    MSG_EOR == 0x80 && MSG_WAITALL == 0x100 && MSG_NOSIGNAL == 0x4000,
    "Linux basic transport constants");

using socket_function = int (*)(int, int, int);
using socketpair_function = int (*)(int, int, int, int *);
using bind_function = int (*)(int, const sockaddr *, socklen_t);
using listen_function = int (*)(int, int);
using accept_function = int (*)(int, sockaddr *, socklen_t *);
using accept4_function = int (*)(int, sockaddr *, socklen_t *, int);
using connect_function = int (*)(int, const sockaddr *, socklen_t);
using send_function = ssize_t (*)(int, const void *, size_t, int);
using recv_function = ssize_t (*)(int, void *, size_t, int);
using sendto_function = ssize_t (*)(int, const void *, size_t, int,
    const sockaddr *, socklen_t);
using recvfrom_function = ssize_t (*)(int, void *, size_t, int, sockaddr *, socklen_t *);
using shutdown_function = int (*)(int, int);
using socket_name_function = int (*)(int, sockaddr *, socklen_t *);

static_assert(__is_same(decltype(&socket), socket_function), "socket C++ declaration");
static_assert(__is_same(decltype(&socketpair), socketpair_function),
    "socketpair C++ declaration");
static_assert(__is_same(decltype(&bind), bind_function), "bind C++ declaration");
static_assert(__is_same(decltype(&listen), listen_function), "listen C++ declaration");
static_assert(__is_same(decltype(&accept), accept_function), "accept C++ declaration");
static_assert(__is_same(decltype(&accept4), accept4_function),
    "accept4 C++ declaration");
static_assert(__is_same(decltype(&connect), connect_function), "connect C++ declaration");
static_assert(__is_same(decltype(&send), send_function), "send C++ declaration");
static_assert(__is_same(decltype(&recv), recv_function), "recv C++ declaration");
static_assert(__is_same(decltype(&sendto), sendto_function), "sendto C++ declaration");
static_assert(__is_same(decltype(&recvfrom), recvfrom_function),
    "recvfrom C++ declaration");
static_assert(__is_same(decltype(&shutdown), shutdown_function),
    "shutdown C++ declaration");
static_assert(__is_same(decltype(&getsockname), socket_name_function),
    "getsockname C++ declaration");
static_assert(__is_same(decltype(&getpeername), socket_name_function),
    "getpeername C++ declaration");

extern "C" int socket(int, int, int);
extern "C" int socketpair(int, int, int, int[2]);
extern "C" int bind(int, const sockaddr *, socklen_t);
extern "C" int listen(int, int);
extern "C" int accept(int, sockaddr *, socklen_t *);
extern "C" int accept4(int, sockaddr *, socklen_t *, int);
extern "C" int connect(int, const sockaddr *, socklen_t);
extern "C" ssize_t send(int, const void *, size_t, int);
extern "C" ssize_t recv(int, void *, size_t, int);
extern "C" ssize_t sendto(int, const void *, size_t, int, const sockaddr *, socklen_t);
extern "C" ssize_t recvfrom(int, void *, size_t, int, sockaddr *, socklen_t *);
extern "C" int shutdown(int, int);
extern "C" int getsockname(int, sockaddr *, socklen_t *);
extern "C" int getpeername(int, sockaddr *, socklen_t *);

int crabc_x86_64_socket_header_abi_probe_cpp()
{
    sockaddr_storage address{};
    return static_cast<int>(sizeof(address));
}
