/* Static crabc-libc x86-64 dn_expand differential.
 *
 * The same project-header C body executes through pinned musl 1.2.6 and an
 * archive-free static candidate carrying exactly one extracted dn_expand
 * object. It expands only caller-owned DNS wire-name spans; it does not select
 * resolver state, resolver files, DNS I/O, sockets, netdb, or a parser.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>
#include <stddef.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef int (*dn_expand_signature)(const unsigned char *,
    const unsigned char *, const unsigned char *, char *, int);

_Static_assert(NS_CMPRSFLGS == 0xc0 && NS_MAXLABEL == 63 &&
    NS_MAXCDNAME == 255 && NS_MAXDNAME == 1025,
    "DNS wire-name constants");
_Static_assert(CRABC_TYPE_IS(__typeof__(&dn_expand),
    dn_expand_signature), "dn_expand declaration");

static int text_equals(const char *actual, const char *expected)
{
    while (*actual == *expected) {
        if (*actual == '\0') return 1;
        actual++;
        expected++;
    }
    return 0;
}

static int bytes_are(const unsigned char *bytes, size_t count, unsigned char value)
{
    while (count--) {
        if (*bytes++ != value) return 0;
    }
    return 1;
}

static const unsigned char root[] = { 0 };
static const unsigned char one_label[] = { 3, 'w', 'w', 'w', 0 };
static const unsigned char labels[] = { 3, 'w', 'w', 'w', 7, 'e', 'x', 'a',
    'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
static const unsigned char compressed[] = { 3, 'w', 'w', 'w', 0xc0, 0x06,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
/* `dn_expand` treats any octet with either top bit set as a pointer. */
static const unsigned char noncanonical_pointer[] = { 0x40, 0x02, 0 };
/* The 14-bit compression offset must not truncate to one byte. */
static const unsigned char high_offset_pointer[259] = {
    [0] = 0xc1, [1] = 0x02,
};
static const unsigned char truncated_pointer[] = { 0xc0 };
static const unsigned char invalid_pointer[] = { 0xc0, 0x02 };
static const unsigned char pointer_loop[] = { 0xc0, 0x00 };
static const unsigned char two_labels[] = { 3, 'w', 'w', 'w', 3, 'f', 'o',
    'o', 0 };

int crabc_x86_64_dn_expand_probe(void)
{
    char output[64];
    unsigned char capped_name[256];
    char capped_output[256];

    if (dn_expand(root, root + sizeof(root), root, output, sizeof(output)) != 1 ||
        !text_equals(output, "")) return 1;
    if (dn_expand(labels, labels + sizeof(labels), labels, output, sizeof(output)) != 17 ||
        !text_equals(output, "www.example.com")) return 2;
    if (dn_expand(compressed, compressed + sizeof(compressed), compressed,
            output, sizeof(output)) != 6 ||
        !text_equals(output, "www.example.com")) return 3;
    if (dn_expand(compressed, compressed + sizeof(compressed), compressed + 4,
            output, sizeof(output)) != 2 ||
        !text_equals(output, "example.com")) return 4;
    if (dn_expand(noncanonical_pointer,
            noncanonical_pointer + sizeof(noncanonical_pointer),
            noncanonical_pointer, output, sizeof(output)) != 2 ||
        !text_equals(output, "")) return 5;
    if (dn_expand(high_offset_pointer,
            high_offset_pointer + sizeof(high_offset_pointer),
            high_offset_pointer, output, sizeof(output)) != 2 ||
        !text_equals(output, "")) return 6;
    if (dn_expand(truncated_pointer,
            truncated_pointer + sizeof(truncated_pointer), truncated_pointer,
            output, sizeof(output)) != -1) return 7;
    if (dn_expand(invalid_pointer, invalid_pointer + sizeof(invalid_pointer),
            invalid_pointer, output, sizeof(output)) != -1) return 8;
    if (dn_expand(pointer_loop, pointer_loop + sizeof(pointer_loop),
            pointer_loop, output, sizeof(output)) != -1) return 9;
    /* source==end and nonpositive space return before destination access. */
    if (dn_expand(root, root + sizeof(root), root + sizeof(root), NULL, 1) != -1)
        return 10;
    if (dn_expand(root, root + sizeof(root), root, NULL, 0) != -1) return 11;
    if (dn_expand(one_label, one_label + sizeof(one_label), one_label,
            output, 4) != 5 || !text_equals(output, "www")) return 12;
    for (size_t i = 0; i < sizeof(output); i++) output[i] = (char)0xa5;
    if (dn_expand(one_label, one_label + sizeof(one_label), one_label,
            output, 3) != -1 || !bytes_are((const unsigned char *)output,
            sizeof(output), 0xa5)) return 13;
    for (size_t i = 0; i < sizeof(output); i++) output[i] = (char)0xa5;
    if (dn_expand(two_labels, two_labels + sizeof(two_labels), two_labels,
            output, 7) != -1 || output[0] != 'w' || output[1] != 'w' ||
        output[2] != 'w' || output[3] != '.' ||
        (unsigned char)output[4] != 0xa5) return 14;
    {
        static const unsigned char capped_lengths[] = { 63, 63, 63, 62 };
        size_t encoded = 0;
        for (size_t label = 0; label < sizeof(capped_lengths); label++) {
            capped_name[encoded++] = capped_lengths[label];
            for (size_t byte = 0; byte < capped_lengths[label]; byte++)
                capped_name[encoded++] = (unsigned char)('a' + label);
        }
        capped_name[encoded++] = 0;
        /* A 255-byte destination is deliberately capped to musl's 254 bytes. */
        if (dn_expand(capped_name, capped_name + encoded, capped_name,
                capped_output, 255) != -1) return 15;
    }
    return 0;
}

#ifndef CRABC_DN_EXPAND_FREESTANDING
int main(void)
{
    return crabc_x86_64_dn_expand_probe();
}
#endif
