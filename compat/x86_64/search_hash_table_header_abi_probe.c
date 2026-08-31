/* Linux/x86-64 <search.h> hash-table declaration and layout probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <search.h>
#include <stddef.h>

typedef int (*hcreate_signature)(size_t);
typedef void (*hdestroy_signature)(void);
typedef ENTRY *(*hsearch_signature)(ENTRY, ACTION);

_Static_assert(sizeof(ENTRY) == 16 && _Alignof(ENTRY) == 8 &&
    offsetof(ENTRY, key) == 0 && offsetof(ENTRY, data) == 8,
    "x86 ENTRY ABI");
_Static_assert(sizeof(ACTION) == 4 && FIND == 0 && ENTER == 1,
    "x86 ACTION ABI and values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&hcreate),
    hcreate_signature) &&
    __builtin_types_compatible_p(__typeof__(&hdestroy), hdestroy_signature) &&
    __builtin_types_compatible_p(__typeof__(&hsearch), hsearch_signature),
    "unconditional hash-table declarations");

#ifdef _GNU_SOURCE
typedef int (*hcreate_r_signature)(size_t, struct hsearch_data *);
typedef void (*hdestroy_r_signature)(struct hsearch_data *);
typedef int (*hsearch_r_signature)(
    ENTRY, ACTION, ENTRY **, struct hsearch_data *);

_Static_assert(sizeof(struct hsearch_data) == 16 &&
    _Alignof(struct hsearch_data) == 8 &&
    offsetof(struct hsearch_data, __tab) == 0 &&
    offsetof(struct hsearch_data, __unused1) == 8 &&
    offsetof(struct hsearch_data, __unused2) == 12,
    "x86 GNU hsearch_data ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&hcreate_r),
    hcreate_r_signature) &&
    __builtin_types_compatible_p(__typeof__(&hdestroy_r),
        hdestroy_r_signature) &&
    __builtin_types_compatible_p(__typeof__(&hsearch_r), hsearch_r_signature),
    "GNU reentrant hash-table declarations");

static hcreate_r_signature hcreate_r_function __attribute__((used)) = hcreate_r;
static hdestroy_r_signature hdestroy_r_function __attribute__((used)) = hdestroy_r;
static hsearch_r_signature hsearch_r_function __attribute__((used)) = hsearch_r;
#endif

static hcreate_signature hcreate_function __attribute__((used)) = hcreate;
static hdestroy_signature hdestroy_function __attribute__((used)) = hdestroy;
static hsearch_signature hsearch_function __attribute__((used)) = hsearch;

int crabc_x86_64_search_hash_table_header_abi_probe(void)
{
    return hcreate_function != 0 && hdestroy_function != 0 &&
        hsearch_function != 0 ? 0 : 1;
}
