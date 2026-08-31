/* Static C inet_ntoa scratch-buffer differential. */
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

typedef char *(*inet_ntoa_signature)(struct in_addr);

_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer width");
_Static_assert(sizeof(struct in_addr) == 4, "x86 in_addr layout");
_Static_assert(_Alignof(struct in_addr) == 4, "x86 in_addr alignment");
_Static_assert(offsetof(struct in_addr, s_addr) == 0, "x86 in_addr offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inet_ntoa),
    inet_ntoa_signature), "inet_ntoa declaration");

union address_bytes {
    struct in_addr address;
    unsigned char bytes[4];
};

static struct in_addr address_from_bytes(
    unsigned char first,
    unsigned char second,
    unsigned char third,
    unsigned char fourth)
{
    union address_bytes value;

    value.bytes[0] = first;
    value.bytes[1] = second;
    value.bytes[2] = third;
    value.bytes[3] = fourth;
    return value.address;
}

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

static int check_shared_buffer(void)
{
    char *first;
    char *second;
    char *third;

    first = inet_ntoa(address_from_bytes(0, 9, 10, 99));
    if (!first || !text_equal(first, "0.9.10.99"))
        return 10;

    second = inet_ntoa(address_from_bytes(100, 255, 0, 1));
    if (!second || second != first || !text_equal(second, "100.255.0.1"))
        return 11;
    if (!text_equal(first, "100.255.0.1"))
        return 12;

    third = inet_ntoa(address_from_bytes(255, 255, 255, 255));
    if (!third || third != first || !text_equal(third, "255.255.255.255"))
        return 13;

    if (inet_ntoa(address_from_bytes(0, 0, 0, 0)) != first ||
        !text_equal(first, "0.0.0.0"))
        return 14;

    return 0;
}

int crabc_x86_64_inet_ntoa_probe(void)
{
    return check_shared_buffer();
}

#ifndef CRABC_INET_NTOA_FREESTANDING
int main(void)
{
    return crabc_x86_64_inet_ntoa_probe();
}
#endif
