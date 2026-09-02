/* Native Linux/x86-64 static musl proto.c provider evidence.
 *
 * This one project-header C body runs through pinned musl 1.2.6 before the
 * static crabc candidate. It exercises the complete fixed protocol table,
 * one shared enumeration index/result object, reset semantics, NULL alias
 * slot, and exact case-sensitive lookup composition. It deliberately does
 * not read /etc/protocols or select resolver, DNS, file, allocation, or
 * errno/TLS behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <netdb.h>

typedef void (*endprotoent_signature)(void);
typedef struct protoent *(*getprotobyname_signature)(const char *);
typedef struct protoent *(*getprotobynumber_signature)(int);
typedef struct protoent *(*getprotoent_signature)(void);
typedef void (*setprotoent_signature)(int);

_Static_assert(sizeof(struct protoent) == 24, "protoent size");
_Static_assert(_Alignof(struct protoent) == 8, "protoent alignment");
_Static_assert(offsetof(struct protoent, p_name) == 0, "protoent name offset");
_Static_assert(offsetof(struct protoent, p_aliases) == 8,
               "protoent aliases offset");
_Static_assert(offsetof(struct protoent, p_proto) == 16,
               "protoent number offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&endprotoent),
                                             endprotoent_signature),
               "endprotoent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getprotobyname),
                                             getprotobyname_signature),
               "getprotobyname declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getprotobynumber),
                                             getprotobynumber_signature),
               "getprotobynumber declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getprotoent),
                                             getprotoent_signature),
               "getprotoent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setprotoent),
                                             setprotoent_signature),
               "setprotoent declaration");

static endprotoent_signature endprotoent_function = endprotoent;
static getprotobyname_signature getprotobyname_function = getprotobyname;
static getprotobynumber_signature getprotobynumber_function = getprotobynumber;
static getprotoent_signature getprotoent_function = getprotoent;
static setprotoent_signature setprotoent_function = setprotoent;

struct expected_protocol {
    int number;
    const char *name;
};

static const struct expected_protocol expected_protocols[] = {
    {0, "ip"}, {1, "icmp"}, {2, "igmp"}, {3, "ggp"}, {4, "ipencap"},
    {5, "st"}, {6, "tcp"}, {8, "egp"}, {12, "pup"}, {17, "udp"},
    {20, "hmp"}, {22, "xns-idp"}, {27, "rdp"}, {29, "iso-tp4"},
    {36, "xtp"}, {37, "ddp"}, {38, "idpr-cmtp"}, {41, "ipv6"},
    {43, "ipv6-route"}, {44, "ipv6-frag"}, {45, "idrp"}, {46, "rsvp"},
    {47, "gre"}, {50, "esp"}, {51, "ah"}, {57, "skip"},
    {58, "ipv6-icmp"}, {59, "ipv6-nonxt"}, {60, "ipv6-opts"},
    {73, "rspf"}, {81, "vmtp"}, {89, "ospf"}, {94, "ipip"},
    {98, "encap"}, {103, "pim"}, {255, "raw"},
};

static int text_equal(const char *left, const char *right)
{
    size_t index = 0;

    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int matches(const struct protoent *entry, int number, const char *name)
{
    return entry != NULL && entry->p_name != NULL && entry->p_aliases != NULL &&
            entry->p_aliases[0] == NULL && entry->p_proto == number &&
            text_equal(entry->p_name, name);
}

static int check_enumeration(void)
{
    struct protoent *first = NULL;
    struct protoent *entry;
    char **aliases = NULL;
    size_t index;

    endprotoent_function();
    for (index = 0; index < sizeof(expected_protocols) / sizeof(expected_protocols[0]);
         ++index) {
        entry = getprotoent_function();
        if (!matches(entry, expected_protocols[index].number,
                     expected_protocols[index].name))
            return 1;
        if (index == 0) {
            first = entry;
            aliases = entry->p_aliases;
        } else if (entry != first || entry->p_aliases != aliases) {
            return 2;
        }
    }
    if (getprotoent() != NULL) return 3;

    /* Both source-shaped reset calls ignore stayopen and restart at ip. */
    setprotoent_function(-7);
    if (!matches(getprotoent(), 0, "ip")) return 4;
    endprotoent();
    if (!matches(getprotoent_function(), 0, "ip")) return 5;
    return 0;
}

static int check_lookup_state(void)
{
    struct protoent *entry;

    entry = getprotobyname_function("tcp");
    if (!matches(entry, 6, "tcp")) return 1;
    if (!matches(getprotoent(), 8, "egp")) return 2;

    entry = getprotobynumber_function(17);
    if (!matches(entry, 17, "udp")) return 3;
    if (!matches(getprotoent_function(), 20, "hmp")) return 4;

    if (getprotobyname("TCP") != NULL) return 5;
    if (getprotoent() != NULL) return 6;
    if (getprotobynumber_function(-1) != NULL) return 7;
    if (getprotoent_function() != NULL) return 8;

    setprotoent(1);
    if (!matches(getprotobyname_function("raw"), 255, "raw")) return 9;
    if (getprotoent() != NULL) return 10;
    return 0;
}

int crabc_x86_64_protocol_database_probe(void)
{
    int status = check_enumeration();

    if (status != 0) return status;
    status = check_lookup_state();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_PROTOCOL_DATABASE_FREESTANDING
int main(void)
{
    return crabc_x86_64_protocol_database_probe();
}
#endif
