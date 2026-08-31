/* Native Linux/x86-64 static ether_line C ABI evidence.
 *
 * Pinned musl's ether.c body returns -1 without inspecting any pointer. This
 * fixture therefore proves the exact private failure leaf with valid
 * caller-owned inputs and null pointer values; it does not select Ethernet
 * address conversion, /etc/ethers, resolver, socket, or interface behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <netinet/ether.h>

#ifndef CRABC_ETHER_LINE_FREESTANDING
#include <errno.h>
#endif

typedef int (*ether_line_signature)(const char *, struct ether_addr *, char *);

_Static_assert(ETH_ALEN == 6, "Ethernet address width");
_Static_assert(sizeof(struct ether_addr) == 6, "ether_addr size");
_Static_assert(_Alignof(struct ether_addr) == 1, "ether_addr alignment");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_line),
                                             ether_line_signature),
               "ether_line declaration");

static int bytes_match(const unsigned char *left, const unsigned char *right,
                       unsigned long count)
{
    unsigned long index;

    for (index = 0; index != count; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

int crabc_x86_64_ether_line_probe(void)
{
    const ether_line_signature function = ether_line;
    char line[] = "08:00:27:12:34:56 host.example";
    struct ether_addr address = {{0x10, 0x20, 0x30, 0x40, 0x50, 0x60}};
    char hostname[] = "unchanged";
    const unsigned char expected_address[ETH_ALEN] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    };
    const char expected_hostname[] = "unchanged";

    if (ether_line(line, &address, hostname) != -1)
        return 1;
    if (function(line, &address, hostname) != -1)
        return 2;
    if (!bytes_match(address.ether_addr_octet, expected_address, ETH_ALEN))
        return 3;
    if (!bytes_match((const unsigned char *)hostname,
                     (const unsigned char *)expected_hostname,
                     sizeof(expected_hostname)))
        return 4;

#ifndef CRABC_ETHER_LINE_FREESTANDING
    errno = E2BIG;
    if (ether_line(line, &address, hostname) != -1)
        return 5;
    if (errno != E2BIG)
        return 6;
#endif

    if (ether_line((const char *)0, (struct ether_addr *)0, (char *)0) != -1)
        return 7;
    if (function((const char *)0, (struct ether_addr *)0, (char *)0) != -1)
        return 8;
    return 0;
}

#ifndef CRABC_ETHER_LINE_FREESTANDING
int main(void)
{
    return crabc_x86_64_ether_line_probe();
}
#endif
