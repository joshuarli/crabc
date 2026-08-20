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
#define IN6_IS_ADDR_UNSPECIFIED(a) 0
#define IN6_IS_ADDR_LOOPBACK(a) 0
#define IN6_IS_ADDR_MULTICAST(a) 0
#define IN6_IS_ADDR_LINKLOCAL(a) 0
#define IN6_IS_ADDR_SITELOCAL(a) 0
#define IN6_IS_ADDR_V4MAPPED(a) 0
#define IN6_IS_ADDR_V4COMPAT(a) 0
#define IN6_IS_ADDR_MC_NODELOCAL(a) 0
#define IN6_IS_ADDR_MC_LINKLOCAL(a) 0
#define IN6_IS_ADDR_MC_SITELOCAL(a) 0
#define IN6_IS_ADDR_MC_ORGLOCAL(a) 0
#define IN6_IS_ADDR_MC_GLOBAL(a) 0

#endif
