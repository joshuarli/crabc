/* Linux/x86-64 <search.h> callback-tree declaration probe. */

#include <search.h>

typedef void *(*tdelete_signature)(const void *restrict, void **restrict,
    int (*)(const void *, const void *));
typedef void *(*tfind_signature)(const void *, void *const *,
    int (*)(const void *, const void *));
typedef void *(*tsearch_signature)(const void *, void **,
    int (*)(const void *, const void *));
typedef void (*twalk_signature)(const void *,
    void (*)(const void *, VISIT, int));

_Static_assert(preorder == 0 && postorder == 1 && endorder == 2 && leaf == 3,
    "musl VISIT values");
_Static_assert(sizeof(VISIT) == 4, "x86 VISIT ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tdelete),
    tdelete_signature) &&
    __builtin_types_compatible_p(__typeof__(&tfind), tfind_signature) &&
    __builtin_types_compatible_p(__typeof__(&tsearch), tsearch_signature) &&
    __builtin_types_compatible_p(__typeof__(&twalk), twalk_signature),
    "unconditional callback-tree declarations");

#ifdef _GNU_SOURCE
typedef void (*tdestroy_signature)(void *, void (*)(void *));
_Static_assert(__builtin_types_compatible_p(__typeof__(&tdestroy),
    tdestroy_signature), "GNU tdestroy declaration");
_Static_assert(sizeof(struct qelem) == 24 && _Alignof(struct qelem) == 8,
    "GNU qelem ABI");
#endif

int crabc_x86_64_search_tree_header_abi_probe(void)
{
    return preorder + postorder + endorder + leaf;
}
