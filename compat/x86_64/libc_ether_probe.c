/* Native Linux/x86-64 static musl ether.c provider evidence.
 *
 * This one project-header C body first runs through pinned musl 1.2.6 and
 * then through a true static crabc-libc candidate. It covers all seven public
 * entries from musl src/network/ether.c: its strtoul-shaped address grammar,
 * caller and process-static storage, uppercase text rendering, and the three
 * source-shaped -1 stubs. It does not select /etc/ethers, name resolution,
 * sockets, interfaces, allocation, stdio, libc.so, a CRT, or a runtime.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <netinet/ether.h>

typedef struct ether_addr *(*ether_aton_signature)(const char *);
typedef struct ether_addr *(*ether_aton_r_signature)(const char *,
                                                       struct ether_addr *);
typedef char *(*ether_ntoa_signature)(const struct ether_addr *);
typedef char *(*ether_ntoa_r_signature)(const struct ether_addr *, char *);
typedef int (*ether_line_signature)(const char *, struct ether_addr *, char *);
typedef int (*ether_ntohost_signature)(char *, const struct ether_addr *);
typedef int (*ether_hostton_signature)(const char *, struct ether_addr *);

_Static_assert(ETH_ALEN == 6, "Ethernet address width");
_Static_assert(sizeof(struct ether_addr) == 6, "ether_addr size");
_Static_assert(_Alignof(struct ether_addr) == 1, "ether_addr alignment");
_Static_assert(offsetof(struct ether_addr, ether_addr_octet) == 0,
               "ether_addr octets offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_aton),
                                             ether_aton_signature),
               "ether_aton declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_aton_r),
                                             ether_aton_r_signature),
               "ether_aton_r declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_ntoa),
                                             ether_ntoa_signature),
               "ether_ntoa declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_ntoa_r),
                                             ether_ntoa_r_signature),
               "ether_ntoa_r declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_line),
                                             ether_line_signature),
               "ether_line declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_ntohost),
                                             ether_ntohost_signature),
               "ether_ntohost declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ether_hostton),
                                             ether_hostton_signature),
               "ether_hostton declaration");

static ether_aton_signature ether_aton_function = ether_aton;
static ether_aton_r_signature ether_aton_r_function = ether_aton_r;
static ether_ntoa_signature ether_ntoa_function = ether_ntoa;
static ether_ntoa_r_signature ether_ntoa_r_function = ether_ntoa_r;
static ether_line_signature ether_line_function = ether_line;
static ether_ntohost_signature ether_ntohost_function = ether_ntohost;
static ether_hostton_signature ether_hostton_function = ether_hostton;

static int bytes_equal(const unsigned char *left, const unsigned char *right,
                       size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static int bytes_are(const unsigned char *bytes, size_t count, unsigned char value)
{
    size_t index;

    for (index = 0; index < count; ++index)
        if (bytes[index] != value) return 0;
    return 1;
}

static void fill_bytes(unsigned char *bytes, size_t count, unsigned char value)
{
    size_t index;

    for (index = 0; index < count; ++index) bytes[index] = value;
}

static int text_equal(const char *left, const char *right)
{
    size_t index = 0;

    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int check_ether_aton_r(void)
{
    static const unsigned char normal[ETH_ALEN] = {0, 0x1a, 0x2b, 3, 4, 0xff};
    static const unsigned char variable[ETH_ALEN] = {0, 1, 2, 3, 4, 5};
    static const unsigned char empty_field[ETH_ALEN] = {0, 0, 0x22, 0x33, 0x44, 0x55};
    struct ether_addr address;
    struct ether_addr *result;

    fill_bytes(address.ether_addr_octet, ETH_ALEN, 0xa5);
    errno = E2BIG;
    result = ether_aton_r("00:1a:2B:03:04:ff", &address);
    if (result != &address ||
        !bytes_equal(address.ether_addr_octet, normal, ETH_ALEN) || errno != E2BIG)
        return 1;

    fill_bytes(address.ether_addr_octet, ETH_ALEN, 0xa5);
    errno = E2BIG;
    result = ether_aton_r_function("0x0:0X1:2:3:4:5", &address);
    if (result != &address ||
        !bytes_equal(address.ether_addr_octet, variable, ETH_ALEN) || errno != E2BIG)
        return 2;

    fill_bytes(address.ether_addr_octet, ETH_ALEN, 0xa5);
    errno = E2BIG;
    result = ether_aton_r("00::22:33:44:55", &address);
    if (result != &address ||
        !bytes_equal(address.ether_addr_octet, empty_field, ETH_ALEN) || errno != EINVAL)
        return 3;

    fill_bytes(address.ether_addr_octet, ETH_ALEN, 0xa5);
    errno = E2BIG;
    result = ether_aton_r("00:1a:2B:03:04:gg", &address);
    if (result != 0 || !bytes_are(address.ether_addr_octet, ETH_ALEN, 0xa5) ||
        errno != EINVAL)
        return 4;

    fill_bytes(address.ether_addr_octet, ETH_ALEN, 0xa5);
    errno = E2BIG;
    result = ether_aton_r("00:1a:2B:03:04:100", &address);
    if (result != 0 || !bytes_are(address.ether_addr_octet, ETH_ALEN, 0xa5) ||
        errno != E2BIG)
        return 5;

    fill_bytes(address.ether_addr_octet, ETH_ALEN, 0xa5);
    errno = E2BIG;
    result = ether_aton_r("00-1a:2B:03:04:ff", &address);
    if (result != 0 || !bytes_are(address.ether_addr_octet, ETH_ALEN, 0xa5) ||
        errno != E2BIG)
        return 6;

    fill_bytes(address.ether_addr_octet, ETH_ALEN, 0xa5);
    errno = E2BIG;
    result = ether_aton_r("00:1a:2B:03:04:ffx", &address);
    if (result != 0 || !bytes_are(address.ether_addr_octet, ETH_ALEN, 0xa5) ||
        errno != E2BIG)
        return 7;
    return 0;
}

static int check_ether_aton_storage(void)
{
    static const unsigned char first_bytes[ETH_ALEN] = {0, 1, 2, 3, 4, 5};
    static const unsigned char second_bytes[ETH_ALEN] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};
    struct ether_addr *first;
    struct ether_addr *second;

    errno = E2BIG;
    first = ether_aton_function("0:1:2:3:4:5");
    if (first == 0 || !bytes_equal(first->ether_addr_octet, first_bytes, ETH_ALEN) ||
        errno != E2BIG)
        return 1;

    errno = E2BIG;
    second = ether_aton("ff:ee:dd:cc:bb:aa");
    if (second != first ||
        !bytes_equal(second->ether_addr_octet, second_bytes, ETH_ALEN) || errno != E2BIG)
        return 2;

    errno = E2BIG;
    if (ether_aton_function("not-an-address") != 0 || errno != EINVAL ||
        !bytes_equal(first->ether_addr_octet, second_bytes, ETH_ALEN))
        return 3;
    return 0;
}

static int check_ether_ntoa(void)
{
    static const char expected_first[] = "00:1A:2B:03:04:FF";
    static const char expected_second[] = "FF:EE:DD:CC:BB:AA";
    const struct ether_addr first = {{0, 0x1a, 0x2b, 3, 4, 0xff}};
    const struct ether_addr second = {{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}};
    char output[19];
    char *first_static;
    char *second_static;

    fill_bytes((unsigned char *)output, sizeof(output), 0xa5);
    errno = E2BIG;
    if (ether_ntoa_r_function(&first, output) != output ||
        !text_equal(output, expected_first) || (unsigned char)output[18] != 0xa5 ||
        errno != E2BIG)
        return 1;

    errno = E2BIG;
    first_static = ether_ntoa_function(&first);
    if (first_static == 0 || !text_equal(first_static, expected_first) || errno != E2BIG)
        return 2;

    errno = E2BIG;
    second_static = ether_ntoa(&second);
    if (second_static != first_static || !text_equal(second_static, expected_second) ||
        errno != E2BIG)
        return 3;
    return 0;
}

static int check_legacy_stubs(void)
{
    const char line[] = "00:1a:2B:03:04:ff host.example";
    const char hostname[] = "host.example";
    struct ether_addr address = {{0x10, 0x20, 0x30, 0x40, 0x50, 0x60}};
    static const unsigned char expected_address[ETH_ALEN] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    };
    char output[] = "unchanged";
    static const char expected_output[] = "unchanged";

    errno = E2BIG;
    if (ether_line(line, &address, output) != -1 || errno != E2BIG ||
        !bytes_equal(address.ether_addr_octet, expected_address, ETH_ALEN) ||
        !text_equal(output, expected_output))
        return 1;
    if (ether_line_function((const char *)0, (struct ether_addr *)0, (char *)0) != -1 ||
        errno != E2BIG)
        return 2;

    errno = E2BIG;
    if (ether_ntohost(output, &address) != -1 || errno != E2BIG ||
        !text_equal(output, expected_output))
        return 3;
    if (ether_ntohost_function((char *)0, (const struct ether_addr *)0) != -1 ||
        errno != E2BIG)
        return 4;

    errno = E2BIG;
    if (ether_hostton(hostname, &address) != -1 || errno != E2BIG ||
        !bytes_equal(address.ether_addr_octet, expected_address, ETH_ALEN))
        return 5;
    if (ether_hostton_function((const char *)0, (struct ether_addr *)0) != -1 ||
        errno != E2BIG)
        return 6;
    return 0;
}

int crabc_x86_64_ether_probe(void)
{
    int status;

    status = check_ether_aton_r();
    if (status != 0) return status;
    status = check_ether_aton_storage();
    if (status != 0) return 10 + status;
    status = check_ether_ntoa();
    if (status != 0) return 20 + status;
    status = check_legacy_stubs();
    if (status != 0) return 30 + status;
    return 0;
}

#ifndef CRABC_ETHER_FREESTANDING
int main(void)
{
    return crabc_x86_64_ether_probe();
}
#endif
