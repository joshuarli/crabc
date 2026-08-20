#ifndef _NETINET_IF_ETHER_H
#define _NETINET_IF_ETHER_H

#include <stdint.h>

#define ETH_ALEN 6

struct ether_addr {
    uint8_t ether_addr_octet[ETH_ALEN];
};

#endif
