/* Pinned-musl/project Linux/x86-64 proto.c declaration and layout gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
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

static endprotoent_signature endprotoent_function __attribute__((used)) =
    endprotoent;
static getprotobyname_signature getprotobyname_function __attribute__((used)) =
    getprotobyname;
static getprotobynumber_signature getprotobynumber_function __attribute__((used)) =
    getprotobynumber;
static getprotoent_signature getprotoent_function __attribute__((used)) =
    getprotoent;
static setprotoent_signature setprotoent_function __attribute__((used)) =
    setprotoent;

int crabc_x86_64_protocol_database_header_abi_probe(void)
{
    return endprotoent_function != (endprotoent_signature)0 &&
            getprotobyname_function != (getprotobyname_signature)0 &&
            getprotobynumber_function != (getprotobynumber_signature)0 &&
            getprotoent_function != (getprotoent_signature)0 &&
            setprotoent_function != (setprotoent_signature)0
        ? 0
        : 1;
}
