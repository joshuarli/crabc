/* C++ companion for the Linux/x86-64 <search.h> hash-table probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <search.h>
#include <stddef.h>

using hcreate_signature = int (*)(size_t);
using hdestroy_signature = void (*)(void);
using hsearch_signature = ENTRY *(*)(ENTRY, ACTION);

static_assert(sizeof(ENTRY) == 16 && alignof(ENTRY) == 8 &&
    offsetof(ENTRY, key) == 0 && offsetof(ENTRY, data) == 8,
    "x86 ENTRY ABI");
static_assert(sizeof(ACTION) == 4 && FIND == 0 && ENTER == 1,
    "x86 ACTION ABI and values");
static_assert(__is_same(decltype(&hcreate), hcreate_signature) &&
    __is_same(decltype(&hdestroy), hdestroy_signature) &&
    __is_same(decltype(&hsearch), hsearch_signature),
    "unconditional C-linkage hash-table declarations");

#ifdef _GNU_SOURCE
using hcreate_r_signature = int (*)(size_t, hsearch_data *);
using hdestroy_r_signature = void (*)(hsearch_data *);
using hsearch_r_signature = int (*)(ENTRY, ACTION, ENTRY **, hsearch_data *);

static_assert(sizeof(hsearch_data) == 16 && alignof(hsearch_data) == 8 &&
    offsetof(hsearch_data, __tab) == 0 &&
    offsetof(hsearch_data, __unused1) == 8 &&
    offsetof(hsearch_data, __unused2) == 12,
    "x86 GNU hsearch_data ABI");
static_assert(__is_same(decltype(&hcreate_r), hcreate_r_signature) &&
    __is_same(decltype(&hdestroy_r), hdestroy_r_signature) &&
    __is_same(decltype(&hsearch_r), hsearch_r_signature),
    "GNU C-linkage reentrant hash-table declarations");

static hcreate_r_signature hcreate_r_function __attribute__((used)) = hcreate_r;
static hdestroy_r_signature hdestroy_r_function __attribute__((used)) = hdestroy_r;
static hsearch_r_signature hsearch_r_function __attribute__((used)) = hsearch_r;
#endif

static hcreate_signature hcreate_function __attribute__((used)) = hcreate;
static hdestroy_signature hdestroy_function __attribute__((used)) = hdestroy;
static hsearch_signature hsearch_function __attribute__((used)) = hsearch;

int crabc_x86_64_search_hash_table_header_abi_probe_cpp()
{
    return hcreate_function != nullptr && hdestroy_function != nullptr &&
        hsearch_function != nullptr ? 0 : 1;
}
