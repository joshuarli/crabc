#define _GNU_SOURCE 1

#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct ifaddrs *list = NULL;
    struct ifaddrs *ifa;
    unsigned int count = 0;
    int have_packet = 0;
    int have_ip = 0;
    int result = 1;

    errno = 0;
    if (getifaddrs(NULL) != -1 || errno != EFAULT)
        return result;
    if (getifaddrs(&list) < 0 || !list)
        return result;

    for (ifa = list; ifa; ifa = ifa->ifa_next) {
        unsigned int index;
        int family;

        if (++count > 512 || !ifa->ifa_name)
            goto cleanup;
        index = if_nametoindex(ifa->ifa_name);
        if (index == 0)
            goto cleanup;
        if (!ifa->ifa_addr)
            continue;

        family = ifa->ifa_addr->sa_family;
        if (family == AF_PACKET) {
            const struct sockaddr_ll *ll = (const struct sockaddr_ll *)ifa->ifa_addr;
            if (ll->sll_ifindex != (int)index || ll->sll_halen > sizeof(ll->sll_addr))
                goto cleanup;
            have_packet = 1;
        } else if (family == AF_INET || family == AF_INET6) {
            if (!ifa->ifa_netmask || ifa->ifa_netmask->sa_family != family)
                goto cleanup;
            if (ifa->ifa_dstaddr && ifa->ifa_dstaddr->sa_family != family)
                goto cleanup;
            have_ip = 1;
        } else {
            goto cleanup;
        }
    }

    if (count == 0 || !have_packet || !have_ip)
        goto cleanup;
    result = 0;

cleanup:
    freeifaddrs(list);
    freeifaddrs(NULL);
    if (result == 0)
        puts("c-abi ifaddrs ok");
    return result;
}
