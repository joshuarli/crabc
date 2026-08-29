/* Pinned-musl/project-header IPv6 address-classification macro regression. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <netinet/in.h>

static const struct in6_addr unspecified = IN6ADDR_ANY_INIT;
static const struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
static const struct in6_addr link_local = {{
    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
}};
static const struct in6_addr site_local = {{
    0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
}};
static const struct in6_addr v4_mapped = {{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1
}};
static const struct in6_addr v4_compatible = {{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1
}};
static const struct in6_addr multicast_node = {{
    0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
}};
static const struct in6_addr multicast_link = {{
    0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
}};
static const struct in6_addr multicast_site = {{
    0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
}};
static const struct in6_addr multicast_org = {{
    0xff, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
}};
static const struct in6_addr multicast_global = {{
    0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
}};

int main(void)
{
    if (!IN6_IS_ADDR_UNSPECIFIED(&unspecified) ||
        IN6_IS_ADDR_UNSPECIFIED(&loopback))
        return 1;
    if (!IN6_IS_ADDR_LOOPBACK(&loopback) ||
        IN6_IS_ADDR_LOOPBACK(&unspecified))
        return 2;
    if (!IN6_IS_ADDR_LINKLOCAL(&link_local) ||
        IN6_IS_ADDR_LINKLOCAL(&site_local))
        return 3;
    if (!IN6_IS_ADDR_SITELOCAL(&site_local) ||
        IN6_IS_ADDR_SITELOCAL(&link_local))
        return 4;
    if (!IN6_IS_ADDR_V4MAPPED(&v4_mapped) ||
        IN6_IS_ADDR_V4MAPPED(&v4_compatible))
        return 5;
    if (!IN6_IS_ADDR_V4COMPAT(&v4_compatible) ||
        IN6_IS_ADDR_V4COMPAT(&unspecified) || IN6_IS_ADDR_V4COMPAT(&loopback))
        return 6;
    if (!IN6_IS_ADDR_MULTICAST(&multicast_node) ||
        !IN6_IS_ADDR_MC_NODELOCAL(&multicast_node) ||
        !IN6_IS_ADDR_MC_LINKLOCAL(&multicast_link) ||
        !IN6_IS_ADDR_MC_SITELOCAL(&multicast_site) ||
        !IN6_IS_ADDR_MC_ORGLOCAL(&multicast_org) ||
        !IN6_IS_ADDR_MC_GLOBAL(&multicast_global))
        return 7;
    if (IN6_IS_ADDR_MC_GLOBAL(&multicast_link) ||
        IN6_IS_ADDR_MULTICAST(&v4_mapped))
        return 8;
    return 0;
}
