#include <errno.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct ether_addr addr;
    struct ether_addr parsed;
    struct ether_addr absent_addr = {{0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde}};
    unsigned char untouched[6];
    char text[18];
    char hostname[128];
    const struct ether_addr *static_addr;
    const char *static_text;

    if (!ether_aton_r("00:1a:2B:03:04:ff", &addr))
        return 1;
    if (addr.ether_addr_octet[0] != 0x00 || addr.ether_addr_octet[1] != 0x1a ||
        addr.ether_addr_octet[2] != 0x2b || addr.ether_addr_octet[3] != 0x03 ||
        addr.ether_addr_octet[4] != 0x04 || addr.ether_addr_octet[5] != 0xff)
        return 2;
    if (ether_ntoa_r(&addr, text) != text || strcmp(text, "00:1A:2B:03:04:FF"))
        return 3;

    static_addr = ether_aton("10:20:30:40:50:60");
    if (!static_addr || static_addr->ether_addr_octet[5] != 0x60)
        return 4;
    static_text = ether_ntoa(static_addr);
    if (!static_text || strcmp(static_text, "10:20:30:40:50:60"))
        return 5;

    memset(&parsed, 0xa5, sizeof parsed);
    if (ether_aton_r("00:11:22:33:44:gg", &parsed) != NULL ||
        memcmp(&parsed, "\xa5\xa5\xa5\xa5\xa5\xa5", 6) != 0)
        return 6;
    if (ether_aton_r("00:11:22:33:44:100", &parsed) != NULL)
        return 7;
    if (ether_aton_r(":11:22:33:44:55", &parsed) != NULL)
        return 12;

    if (ether_line("00:11:22:33:44:55 fixture-host # comment", &addr, hostname) != 0 ||
        strcmp(hostname, "fixture-host") || addr.ether_addr_octet[5] != 0x55)
        return 8;
    if (ether_line("00:11:22:33:44:55 # no host", &addr, hostname) == 0 ||
        ether_line("00:11:22:33:44:zz fixture-host", &addr, hostname) == 0)
        return 9;

    memset(untouched, 0xa5, sizeof untouched);
    if (ether_hostton("crabc-c-abi-ether-host-that-does-not-exist", &parsed) == 0 ||
        memcmp(&parsed, untouched, sizeof untouched) != 0)
        return 10;
    memset(hostname, 0xa5, sizeof hostname);
    if (ether_ntohost(hostname, &absent_addr) == 0 || hostname[0] != (char)0xa5)
        return 11;

    puts("c-abi ether interfaces ok");
    return 0;
}
