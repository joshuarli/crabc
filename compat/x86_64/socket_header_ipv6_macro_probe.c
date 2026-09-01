/* Pinned-musl/project-header Internet address-classification macro regression. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <netinet/in.h>

static const uint32_t equality_words[] = { 1, 2, 3, 4 };
static const uint32_t equality_words_copy[] = { 1, 2, 3, 4 };
static const uint32_t equality_words_different[] = { 1, 2, 3, 5 };

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
static const struct in6_addr v4_mapped_copy = {{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1
}};
static const struct in6_addr v4_mapped_different = {{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 2
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
    if (!__ARE_4_EQUAL(equality_words, equality_words_copy) ||
        __ARE_4_EQUAL(equality_words, equality_words_different))
        return 9;
    if (!IN6_ARE_ADDR_EQUAL(&v4_mapped, &v4_mapped_copy) ||
        IN6_ARE_ADDR_EQUAL(&v4_mapped, &v4_mapped_different))
        return 10;
    if (!IN_CLASSA(0x7fffffffU) || IN_CLASSA(0x80000000U) ||
        !IN_CLASSB(0x80000000U) || IN_CLASSB(0xc0000000U) ||
        !IN_CLASSC(0xc0000000U) || IN_CLASSC(0xe0000000U) ||
        !IN_CLASSD(0xe0000000U) || IN_CLASSD(0xf0000000U) ||
        IN_MULTICAST(0xe0000000U) != IN_CLASSD(0xe0000000U))
        return 11;
    if (!IN_EXPERIMENTAL(0xe0000000U) || !IN_EXPERIMENTAL(0xf0000000U) ||
        !IN_BADCLASS(0xf0000000U) || IN_BADCLASS(0xe0000000U))
        return 12;
    if (IP_MSFILTER_SIZE(0) != 16 || IP_MSFILTER_SIZE(1) != 20 ||
        IP_MSFILTER_SIZE(2) != 24 || GROUP_FILTER_SIZE(0) != 144 ||
        GROUP_FILTER_SIZE(1) != 272 || GROUP_FILTER_SIZE(2) != 400)
        return 13;
    return 0;
}
