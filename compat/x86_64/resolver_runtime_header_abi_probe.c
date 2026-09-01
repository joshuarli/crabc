/* Linux/x86-64 C resolver-runtime public-header ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#error "this probe fixes the GNU h_errno visibility profile"
#endif

#include <netdb.h>
#include <resolv.h>
#include <stddef.h>

/* musl's public spelling deliberately routes legacy resolver status through
 * the accessor.  A direct `extern int h_errno` declaration compiles the
 * ordinary single-thread case but loses the required per-thread boundary. */
#ifndef h_errno
#error "musl h_errno must be an __h_errno_location accessor macro"
#endif

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

typedef struct __res_state *(*res_state_signature)(void);
typedef int (*res_init_signature)(void);
typedef int (*res_query_signature)(const char *, int, int, unsigned char *, int);
typedef int (*res_querydomain_signature)(const char *, const char *, int, int,
    unsigned char *, int);
typedef int (*res_search_signature)(const char *, int, int, unsigned char *, int);
typedef int (*res_send_signature)(const unsigned char *, int, unsigned char *, int);
typedef int (*res_mkquery_signature)(int, const char *, int, int,
    const unsigned char *, int, const unsigned char *, unsigned char *, int);
typedef int (*dn_comp_signature)(const char *, unsigned char *, int,
    unsigned char **, unsigned char **);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86-64 LP64 resolver scalar ABI");
_Static_assert(sizeof(struct __res_state) == 568 && _Alignof(struct __res_state) == 8,
    "musl __res_state x86-64 size/alignment");
_Static_assert(offsetof(struct __res_state, retrans) == 0 &&
    offsetof(struct __res_state, retry) == 4 &&
    offsetof(struct __res_state, options) == 8 &&
    offsetof(struct __res_state, nscount) == 16 &&
    offsetof(struct __res_state, nsaddr_list) == 20 &&
    offsetof(struct __res_state, id) == 68 &&
    offsetof(struct __res_state, dnsrch) == 72 &&
    offsetof(struct __res_state, defdname) == 128 &&
    offsetof(struct __res_state, pfcode) == 384 &&
    offsetof(struct __res_state, sort_list) == 396 &&
    offsetof(struct __res_state, qhook) == 480 &&
    offsetof(struct __res_state, rhook) == 488 &&
    offsetof(struct __res_state, res_h_errno) == 496 &&
    offsetof(struct __res_state, _vcsock) == 500 &&
    offsetof(struct __res_state, _flags) == 504 &&
    offsetof(struct __res_state, _u) == 512,
    "musl __res_state x86-64 field ABI");
_Static_assert(MAXNS == 3 && MAXDNSRCH == 6 && RES_TIMEOUT == 5 &&
    RES_DFLRETRY == 2 && RES_MAXNDOTS == 15 && RES_MAXRETRANS == 30 &&
    RES_MAXRETRY == 5,
    "selected resolver configuration bounds");
_Static_assert(RES_INIT == 0x00000001 && RES_RECURSE == 0x00000040 &&
    RES_DEFNAMES == 0x00000080 && RES_DNSRCH == 0x00000200 &&
    RES_NOIP6DOTINT == 0x00080000,
    "selected resolver state flags");
_Static_assert(CRABC_TYPE_IS(__typeof__(&__res_state), res_state_signature),
    "__res_state declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(*__h_errno_location()), int),
    "__h_errno_location result declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&res_init), res_init_signature),
    "res_init declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&res_query), res_query_signature),
    "res_query declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&res_querydomain), res_querydomain_signature),
    "res_querydomain declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&res_search), res_search_signature),
    "res_search declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&res_send), res_send_signature),
    "res_send declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&res_mkquery), res_mkquery_signature),
    "res_mkquery declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&dn_comp), dn_comp_signature),
    "dn_comp declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&h_errno), int *), "h_errno object declaration");

static res_state_signature state_function __attribute__((used)) = __res_state;
static __typeof__(&__h_errno_location) h_errno_function __attribute__((used)) = __h_errno_location;
static res_query_signature query_function __attribute__((used)) = res_query;

int crabc_x86_64_resolver_runtime_header_abi_probe(void)
{
    return state_function != (res_state_signature)0 &&
        h_errno_function != 0 &&
        query_function != (res_query_signature)0 ? 0 : 1;
}
