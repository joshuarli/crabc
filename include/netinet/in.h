#ifndef _NETINET_IN_H
#define _NETINET_IN_H

#include <arpa/inet.h>

struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};
struct in6_addr { uint8_t s6_addr[16]; };
struct sockaddr_in6 {
    sa_family_t sin6_family;
    in_port_t sin6_port;
    uint32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};
struct ipv6_mreq { struct in6_addr ipv6mr_multiaddr; unsigned ipv6mr_interface; };

extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
#define IN6ADDR_ANY_INIT {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
#define IN6ADDR_LOOPBACK_INIT {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}

#define IPPROTO_IP 0
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41
#define IPPROTO_RAW 255
#define INADDR_ANY 0
#define INADDR_BROADCAST 0xffffffffU
#define IPV6_JOIN_GROUP 20
#define IPV6_LEAVE_GROUP 21
#define IPV6_MULTICAST_HOPS 18
#define IPV6_MULTICAST_IF 17
#define IPV6_MULTICAST_LOOP 19
#define IPV6_UNICAST_HOPS 16
#define IPV6_V6ONLY 26

/*
 * Keep musl's public IPv6 address-classification contract in byte order,
 * rather than relying on a word-sized alias or host-endian conversion. The
 * macros accept a pointer to `struct in6_addr`, as POSIX callers expect. They
 * intentionally evaluate that pointer more than once, matching the ordinary
 * musl macro contract; callers must not pass a side-effecting expression.
 */
#define __IN6_ADDR_BYTE(a, index) \
    (((const struct in6_addr *)(a))->s6_addr[(index)])

#define IN6_IS_ADDR_UNSPECIFIED(a) \
    (__IN6_ADDR_BYTE(a, 0) == 0 && __IN6_ADDR_BYTE(a, 1) == 0 && \
     __IN6_ADDR_BYTE(a, 2) == 0 && __IN6_ADDR_BYTE(a, 3) == 0 && \
     __IN6_ADDR_BYTE(a, 4) == 0 && __IN6_ADDR_BYTE(a, 5) == 0 && \
     __IN6_ADDR_BYTE(a, 6) == 0 && __IN6_ADDR_BYTE(a, 7) == 0 && \
     __IN6_ADDR_BYTE(a, 8) == 0 && __IN6_ADDR_BYTE(a, 9) == 0 && \
     __IN6_ADDR_BYTE(a, 10) == 0 && __IN6_ADDR_BYTE(a, 11) == 0 && \
     __IN6_ADDR_BYTE(a, 12) == 0 && __IN6_ADDR_BYTE(a, 13) == 0 && \
     __IN6_ADDR_BYTE(a, 14) == 0 && __IN6_ADDR_BYTE(a, 15) == 0)

#define IN6_IS_ADDR_LOOPBACK(a) \
    (__IN6_ADDR_BYTE(a, 0) == 0 && __IN6_ADDR_BYTE(a, 1) == 0 && \
     __IN6_ADDR_BYTE(a, 2) == 0 && __IN6_ADDR_BYTE(a, 3) == 0 && \
     __IN6_ADDR_BYTE(a, 4) == 0 && __IN6_ADDR_BYTE(a, 5) == 0 && \
     __IN6_ADDR_BYTE(a, 6) == 0 && __IN6_ADDR_BYTE(a, 7) == 0 && \
     __IN6_ADDR_BYTE(a, 8) == 0 && __IN6_ADDR_BYTE(a, 9) == 0 && \
     __IN6_ADDR_BYTE(a, 10) == 0 && __IN6_ADDR_BYTE(a, 11) == 0 && \
     __IN6_ADDR_BYTE(a, 12) == 0 && __IN6_ADDR_BYTE(a, 13) == 0 && \
     __IN6_ADDR_BYTE(a, 14) == 0 && __IN6_ADDR_BYTE(a, 15) == 1)

#define IN6_IS_ADDR_MULTICAST(a) (__IN6_ADDR_BYTE(a, 0) == 0xff)
#define IN6_IS_ADDR_LINKLOCAL(a) \
    (__IN6_ADDR_BYTE(a, 0) == 0xfe && \
     (__IN6_ADDR_BYTE(a, 1) & 0xc0) == 0x80)
#define IN6_IS_ADDR_SITELOCAL(a) \
    (__IN6_ADDR_BYTE(a, 0) == 0xfe && \
     (__IN6_ADDR_BYTE(a, 1) & 0xc0) == 0xc0)

#define IN6_IS_ADDR_V4MAPPED(a) \
    (__IN6_ADDR_BYTE(a, 0) == 0 && __IN6_ADDR_BYTE(a, 1) == 0 && \
     __IN6_ADDR_BYTE(a, 2) == 0 && __IN6_ADDR_BYTE(a, 3) == 0 && \
     __IN6_ADDR_BYTE(a, 4) == 0 && __IN6_ADDR_BYTE(a, 5) == 0 && \
     __IN6_ADDR_BYTE(a, 6) == 0 && __IN6_ADDR_BYTE(a, 7) == 0 && \
     __IN6_ADDR_BYTE(a, 8) == 0 && __IN6_ADDR_BYTE(a, 9) == 0 && \
     __IN6_ADDR_BYTE(a, 10) == 0xff && __IN6_ADDR_BYTE(a, 11) == 0xff)

#define IN6_IS_ADDR_V4COMPAT(a) \
    (__IN6_ADDR_BYTE(a, 0) == 0 && __IN6_ADDR_BYTE(a, 1) == 0 && \
     __IN6_ADDR_BYTE(a, 2) == 0 && __IN6_ADDR_BYTE(a, 3) == 0 && \
     __IN6_ADDR_BYTE(a, 4) == 0 && __IN6_ADDR_BYTE(a, 5) == 0 && \
     __IN6_ADDR_BYTE(a, 6) == 0 && __IN6_ADDR_BYTE(a, 7) == 0 && \
     __IN6_ADDR_BYTE(a, 8) == 0 && __IN6_ADDR_BYTE(a, 9) == 0 && \
     __IN6_ADDR_BYTE(a, 10) == 0 && __IN6_ADDR_BYTE(a, 11) == 0 && \
     (__IN6_ADDR_BYTE(a, 12) != 0 || __IN6_ADDR_BYTE(a, 13) != 0 || \
      __IN6_ADDR_BYTE(a, 14) != 0 || __IN6_ADDR_BYTE(a, 15) > 1))

#define IN6_IS_ADDR_MC_NODELOCAL(a) \
    (IN6_IS_ADDR_MULTICAST(a) && (__IN6_ADDR_BYTE(a, 1) & 0x0f) == 0x01)
#define IN6_IS_ADDR_MC_LINKLOCAL(a) \
    (IN6_IS_ADDR_MULTICAST(a) && (__IN6_ADDR_BYTE(a, 1) & 0x0f) == 0x02)
#define IN6_IS_ADDR_MC_SITELOCAL(a) \
    (IN6_IS_ADDR_MULTICAST(a) && (__IN6_ADDR_BYTE(a, 1) & 0x0f) == 0x05)
#define IN6_IS_ADDR_MC_ORGLOCAL(a) \
    (IN6_IS_ADDR_MULTICAST(a) && (__IN6_ADDR_BYTE(a, 1) & 0x0f) == 0x08)
#define IN6_IS_ADDR_MC_GLOBAL(a) \
    (IN6_IS_ADDR_MULTICAST(a) && (__IN6_ADDR_BYTE(a, 1) & 0x0f) == 0x0e)

#endif
