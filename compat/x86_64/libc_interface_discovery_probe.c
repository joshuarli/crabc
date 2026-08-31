/* Static C interface-discovery ownership and ABI differential. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stddef.h>
#include <stdint.h>

_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer width");
_Static_assert(sizeof(struct if_nameindex) == 16, "x86 if_nameindex layout");
_Static_assert(_Alignof(struct if_nameindex) == 8, "x86 if_nameindex alignment");
_Static_assert(offsetof(struct if_nameindex, if_index) == 0,
    "x86 if_nameindex index offset");
_Static_assert(offsetof(struct if_nameindex, if_name) == 8,
    "x86 if_nameindex name offset");
_Static_assert(sizeof(struct ifaddrs) == 56, "x86 ifaddrs layout");
_Static_assert(_Alignof(struct ifaddrs) == 8, "x86 ifaddrs alignment");
_Static_assert(offsetof(struct ifaddrs, ifa_name) == 8,
    "x86 ifaddrs name offset");
_Static_assert(offsetof(struct ifaddrs, ifa_flags) == 16,
    "x86 ifaddrs flags offset");
_Static_assert(offsetof(struct ifaddrs, ifa_addr) == 24,
    "x86 ifaddrs address offset");
_Static_assert(offsetof(struct ifaddrs, ifa_netmask) == 32,
    "x86 ifaddrs netmask offset");
_Static_assert(offsetof(struct ifaddrs, ifa_data) == 48,
    "x86 ifaddrs data offset");
_Static_assert(sizeof(struct sockaddr_ll) == 20, "x86 sockaddr_ll layout");
_Static_assert(IF_NAMESIZE == 16, "Linux interface-name capacity");

static int text_equal(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t length)
{
    while (length--) {
        if (*left++ != *right++)
            return 0;
    }
    return 1;
}

static int name_index_cases(unsigned int *loopback_index)
{
    struct if_nameindex *entries;
    char name[IF_NAMESIZE];
    unsigned int count = 0;
    unsigned int index;
    int found_loopback = 0;

    index = if_nametoindex("lo");
    if (index == 0)
        return 10;
    if (if_indextoname(index, name) != name || !text_equal(name, "lo"))
        return 11;

    name[0] = 'x';
    name[1] = '\0';
    errno = 0;
    if (if_indextoname(0, name) != NULL || errno != ENXIO || name[0] != 'x' ||
        name[1] != '\0')
        return 12;
    errno = 0;
    if (if_nametoindex("crabc0") != 0 ||
        errno != ENODEV)
        return 13;

    entries = if_nameindex();
    if (!entries)
        return 14;
    for (;;) {
        struct if_nameindex *entry = &entries[count];
        if (entry->if_index == 0) {
            if (entry->if_name != NULL)
                goto failure;
            break;
        }
        if (!entry->if_name || if_nametoindex(entry->if_name) != entry->if_index ||
            if_indextoname(entry->if_index, name) != name ||
            !text_equal(name, entry->if_name))
            goto failure;
        if (text_equal(entry->if_name, "lo") && entry->if_index == index)
            found_loopback = 1;
        if (++count == 64)
            goto failure;
    }
    if (!found_loopback)
        goto failure;
    if_freenameindex(entries);
    *loopback_index = index;
    return 0;

failure:
    if_freenameindex(entries);
    return 15;
}

static int list_is_valid(struct ifaddrs *list, unsigned int loopback_index)
{
    static const unsigned char loopback_v4[4] = { 127, 0, 0, 1 };
    static const unsigned char loopback_v4_mask[4] = { 255, 0, 0, 0 };
    static const unsigned char loopback_v6[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    static const unsigned char loopback_v6_mask[16] = {
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255
    };
    struct ifaddrs *entry;
    unsigned int count = 0;
    int have_packet = 0;
    int have_v4 = 0;
    int have_v6 = 0;

    for (entry = list; entry; entry = entry->ifa_next) {
        int family;

        if (++count > 128 || !entry->ifa_name ||
            if_nametoindex(entry->ifa_name) == 0)
            return 20;
        if (!entry->ifa_addr)
            continue;
        family = entry->ifa_addr->sa_family;
        if (family == AF_PACKET) {
            const struct sockaddr_ll *packet =
                (const struct sockaddr_ll *)entry->ifa_addr;
            if (packet->sll_halen > sizeof packet->sll_addr)
                return 21;
            if (text_equal(entry->ifa_name, "lo") &&
                packet->sll_ifindex == (int)loopback_index)
                have_packet = 1;
            continue;
        }
        if (family == AF_INET) {
            const struct sockaddr_in *address =
                (const struct sockaddr_in *)entry->ifa_addr;
            const struct sockaddr_in *netmask;

            if (!entry->ifa_netmask || entry->ifa_netmask->sa_family != AF_INET)
                return 22;
            netmask = (const struct sockaddr_in *)entry->ifa_netmask;
            if (text_equal(entry->ifa_name, "lo") &&
                bytes_equal((const unsigned char *)&address->sin_addr, loopback_v4,
                    sizeof loopback_v4)) {
                if (!bytes_equal((const unsigned char *)&netmask->sin_addr,
                        loopback_v4_mask, sizeof loopback_v4_mask))
                    return 23;
                have_v4 = 1;
            }
            continue;
        }
        if (family == AF_INET6) {
            const struct sockaddr_in6 *address =
                (const struct sockaddr_in6 *)entry->ifa_addr;
            const struct sockaddr_in6 *netmask;

            if (!entry->ifa_netmask || entry->ifa_netmask->sa_family != AF_INET6)
                return 24;
            netmask = (const struct sockaddr_in6 *)entry->ifa_netmask;
            if (text_equal(entry->ifa_name, "lo") &&
                bytes_equal(address->sin6_addr.s6_addr, loopback_v6,
                    sizeof loopback_v6)) {
                if (!bytes_equal(netmask->sin6_addr.s6_addr, loopback_v6_mask,
                        sizeof loopback_v6_mask))
                    return 25;
                have_v6 = 1;
            }
            continue;
        }
        return 26;
    }
    return count != 0 && have_packet && have_v4 && have_v6 ? 0 : 27;
}

static int ifaddrs_cases(unsigned int loopback_index)
{
    struct ifaddrs *first = NULL;
    struct ifaddrs *second = NULL;
    int result;

    if (getifaddrs(&first) != 0 || !first)
        return 30;
    result = list_is_valid(first, loopback_index);
    if (result != 0) {
        freeifaddrs(first);
        return result;
    }
    if (getifaddrs(&second) != 0 || !second) {
        freeifaddrs(first);
        return 31;
    }
    result = list_is_valid(second, loopback_index);
    if (result == 0) {
        freeifaddrs(second);
        result = list_is_valid(first, loopback_index);
    } else {
        freeifaddrs(second);
    }
    freeifaddrs(first);
    freeifaddrs(NULL);
    return result;
}

int crabc_x86_64_interface_discovery_probe(void)
{
    unsigned int loopback_index = 0;
    int result = name_index_cases(&loopback_index);

    if (result != 0)
        return result;
    return ifaddrs_cases(loopback_index);
}

#ifndef CRABC_INTERFACE_DISCOVERY_FREESTANDING
int main(void)
{
    return crabc_x86_64_interface_discovery_probe();
}
#endif
