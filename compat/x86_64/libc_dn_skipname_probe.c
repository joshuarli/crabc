/* Static crabc-libc x86-64 dn_skipname differential.
 *
 * The same project-header C body executes through pinned musl 1.2.6 and an
 * archive-free static candidate carrying exactly one extracted dn_skipname
 * object. It walks only caller-owned DNS wire-name byte spans; it does not
 * select resolver state, resolver files, DNS I/O, sockets, netdb, or a
 * complete DNS parser.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <resolv.h>
#include <stddef.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef int (*dn_skipname_signature)(const unsigned char *,
    const unsigned char *);

_Static_assert(NS_CMPRSFLGS == 0xc0 && NS_MAXLABEL == 63 &&
    NS_MAXCDNAME == 255 && NS_MAXDNAME == 1025,
    "DNS wire-name constants");
_Static_assert(CRABC_TYPE_IS(__typeof__(&dn_skipname),
    dn_skipname_signature), "dn_skipname declaration");

static int skips(const unsigned char *wire, size_t length, int expected)
{
    return dn_skipname(wire, wire + length) == expected;
}

static const unsigned char root[] = { 0 };
static const unsigned char labels[] = { 3, 'w', 'w', 'w', 7, 'e', 'x', 'a',
    'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
static const unsigned char compressed[] = { 3, 'w', 'w', 'w', 0xc0, 0x0c };
static const unsigned char truncated_pointer[] = { 0xc0 };
static const unsigned char truncated_label[] = { 3, 'w', 'w' };
/* Musl treats all octets below 192 as ordinary label lengths, even 64..191. */
static const unsigned char label_64[66] = { 0x40 };
static const unsigned char label_191[193] = { 0xbf };

int crabc_x86_64_dn_skipname_probe(void)
{
    if (!skips(root, sizeof(root), 1)) return 1;
    if (!skips(root, 0, -1)) return 2;
    if (!skips(labels, sizeof(labels), 17)) return 3;
    if (!skips(compressed, sizeof(compressed), 6)) return 4;
    if (!skips(compressed + 4, 2, 2)) return 5;
    if (!skips(truncated_pointer, sizeof(truncated_pointer), -1)) return 6;
    if (!skips(truncated_label, sizeof(truncated_label), -1)) return 7;
    if (!skips(label_64, sizeof(label_64), 66)) return 8;
    if (!skips(label_191, sizeof(label_191), 193)) return 9;
    return 0;
}

#ifndef CRABC_DN_SKIPNAME_FREESTANDING
int main(void)
{
    return crabc_x86_64_dn_skipname_probe();
}
#endif
