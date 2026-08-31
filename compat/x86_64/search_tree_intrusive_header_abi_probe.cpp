/* C++ companion for the Linux/x86-64 <search.h> callback-tree probe. */

#include <search.h>

using tdelete_signature = void *(*)(const void *, void **,
    int (*)(const void *, const void *));
using tfind_signature = void *(*)(const void *, void *const *,
    int (*)(const void *, const void *));
using tsearch_signature = void *(*)(const void *, void **,
    int (*)(const void *, const void *));
using twalk_signature = void (*)(const void *,
    void (*)(const void *, VISIT, int));

static_assert(preorder == 0 && postorder == 1 && endorder == 2 && leaf == 3,
    "musl VISIT values");
static_assert(__is_same(decltype(&tdelete), tdelete_signature) &&
    __is_same(decltype(&tfind), tfind_signature) &&
    __is_same(decltype(&tsearch), tsearch_signature) &&
    __is_same(decltype(&twalk), twalk_signature),
    "unconditional C-linkage callback-tree declarations");

#ifdef _GNU_SOURCE
using tdestroy_signature = void (*)(void *, void (*)(void *));
static_assert(__is_same(decltype(&tdestroy), tdestroy_signature),
    "GNU C-linkage tdestroy declaration");
static_assert(sizeof(qelem) == 24 && alignof(qelem) == 8,
    "GNU qelem ABI");
#endif

static tdelete_signature tdelete_function __attribute__((used)) = tdelete;
static tfind_signature tfind_function __attribute__((used)) = tfind;
static tsearch_signature tsearch_function __attribute__((used)) = tsearch;
static twalk_signature twalk_function __attribute__((used)) = twalk;
#ifdef _GNU_SOURCE
static tdestroy_signature tdestroy_function __attribute__((used)) = tdestroy;
#endif

int crabc_x86_64_search_tree_header_abi_probe_cpp()
{
    return tdelete_function != nullptr && tfind_function != nullptr &&
        tsearch_function != nullptr && twalk_function != nullptr ? 0 : 1;
}
