/* Static crabc-libc x86-64 legacy IPv4 textual-network fixture.
 *
 * The same project-header C body runs against pinned musl 1.2.6 and a
 * freestanding static crabc executable. Each run writes the parsed word and
 * errno for the same input table. The runner retains and compares both
 * observations. This leaf selects numeric parsing only.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef in_addr_t (*inet_network_signature)(const char *);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(in_addr_t) == 4 && _Alignof(in_addr_t) == 4 &&
    sizeof(struct in_addr) == 4 && _Alignof(struct in_addr) == 4 &&
    offsetof(struct in_addr, s_addr) == 0,
    "x86 IPv4 address ABI");
_Static_assert(CRABC_TYPE_IS(__typeof__(&inet_network), inet_network_signature),
    "inet_network declaration");

static const char *const inputs[] = {
    "0", "1", "127", "255", "256", "65535", "65536", "16777215",
    "16777216", "4294967295", "4294967296", "0.0.0.0",
    "127.18.52.86", "128.18.52.86", "191.171.205.239",
    "192.18.52.86", "255.255.255.255", "256.0.0.1",
    "1.2", "1.65535", "1.65536", "1.16777215", "1.16777216",
    "127.1", "1.2.3", "1.2.65535", "1.2.65536", "1.2.3.4",
    "1.2.3.255", "1.2.3.256", "1.2.3.4.5", "1..2", ".1",
    "1.", "1.2.", "1.2.3.", "", " ", " 1", "1 ", "+1", "-1",
    "0x7f.1", "0177.1", "08.1", "0Xff.0377.0.1",
    "0x", "0x1g", "01.002.003.004", "0000000000000001",
    "18446744073709551615", "18446744073709551616",
    "0.18446744073709551616", "0.0.0.18446744073709551616",
    "not-an-address", "1x", "1\t", "1\n", "1/2", "1:2",
    "\200", "1.\200", "1.0x10", "1.010", "1.0",
};

_Static_assert(sizeof(inputs) / sizeof(inputs[0]) <= 256,
    "observation index fits two hexadecimal digits");

static char hex_digit(unsigned int value)
{
    return "0123456789abcdef"[value & 15U];
}

static void hex_word(char *out, uint32_t value)
{
    unsigned int position;
    for (position = 0; position < 8; ++position)
        out[position] = hex_digit(value >> (28 - position * 4));
}

static int write_record(unsigned int index, in_addr_t value, int error)
{
    char record[21];
    long written;

    record[0] = hex_digit(index >> 4);
    record[1] = hex_digit(index);
    record[2] = ' ';
    hex_word(record + 3, value);
    record[11] = ' ';
    hex_word(record + 12, (uint32_t)error);
    record[20] = '\n';
    __asm__ volatile("syscall" : "=a"(written)
        : "a"(1L), "D"(1L), "S"(record), "d"(sizeof(record))
        : "rcx", "r11", "memory");
    return written == (long)sizeof(record) ? 0 : 1;
}

int crabc_x86_64_inet_network_probe(void)
{
    unsigned int index;

    for (index = 0; index < sizeof(inputs) / sizeof(inputs[0]); ++index) {
        in_addr_t value;
        int error;

        errno = E2BIG;
        value = inet_network(inputs[index]);
        error = errno;
        if (write_record(index, value, error)) return 1;
    }
    return 0;
}

#ifndef CRABC_INET_NETWORK_FREESTANDING
int main(void)
{
    return crabc_x86_64_inet_network_probe();
}
#endif
