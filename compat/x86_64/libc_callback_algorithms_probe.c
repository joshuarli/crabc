/* Static crabc-libc x86-64 callback-algorithms compatibility fixture. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#if !defined(CRABC_CALLBACK_ALGORITHMS_FREESTANDING)
#include <search.h>
#include <string.h>
#endif

typedef int (*compare_signature)(const void *, const void *);
typedef int (*compare_context_signature)(const void *, const void *, void *);
typedef void *(*bsearch_signature)(
    const void *, const void *, size_t, size_t, compare_signature);
typedef void (*qsort_signature)(void *, size_t, size_t, compare_signature);
typedef void (*qsort_r_signature)(
    void *, size_t, size_t, compare_context_signature, void *);

#if defined(CRABC_CALLBACK_ALGORITHMS_FREESTANDING)
/*
 * musl keeps __qsort_r private to libc; it is intentionally not an installed
 * <stdlib.h> API. The dynamic pinned-musl oracle cannot name its hidden
 * symbol, so only the selected static-archive leg calls it directly.
 */
extern void __qsort_r(
    void *, size_t, size_t, compare_context_signature, void *);
#endif

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&bsearch),
    bsearch_signature), "bsearch declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&qsort),
    qsort_signature), "qsort declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&qsort_r),
    qsort_r_signature), "qsort_r declaration");

struct record {
    int key;
    int serial;
};

struct wide_record {
    int key;
    unsigned char payload[300];
    int serial;
};

struct direction {
    int multiplier;
    int calls;
};

static void *expected_context;
static int context_mismatch;
static int ordinary_qsort_calls;

static int compare_int(const void *left, const void *right)
{
    int a = *(const int *)left;
    int b = *(const int *)right;

    return (a > b) - (a < b);
}

static int compare_record(const void *left, const void *right)
{
    const struct record *a = left;
    const struct record *b = right;

    ordinary_qsort_calls += 1;
    return (a->key > b->key) - (a->key < b->key);
}

static int compare_record_context(
    const void *left, const void *right, void *opaque)
{
    struct direction *direction;
    const struct record *a = left;
    const struct record *b = right;
    int result = (a->key > b->key) - (a->key < b->key);

    if (opaque != expected_context) {
        context_mismatch = 1;
        return 0;
    }
    direction = opaque;
    direction->calls += 1;
    return result * direction->multiplier;
}

static int compare_wide_record(const void *left, const void *right)
{
    const struct wide_record *a = left;
    const struct wide_record *b = right;

    return (a->key > b->key) - (a->key < b->key);
}

static int check_bsearch(void)
{
    static const int sorted[] = { -7, -1, 0, 3, 3, 8, 21 };
    int first = -7;
    int last = 21;
    int duplicate = 3;
    int missing = 9;
    const int *found;

    found = bsearch(&first, sorted, 7, sizeof(sorted[0]), compare_int);
    if (found != sorted)
        return 1;
    found = bsearch(&last, sorted, 7, sizeof(sorted[0]), compare_int);
    if (found != sorted + 6)
        return 2;
    found = bsearch(&duplicate, sorted, 7, sizeof(sorted[0]), compare_int);
    if (found == NULL || *found != duplicate)
        return 3;
    if (bsearch(&missing, sorted, 7, sizeof(sorted[0]), compare_int) != NULL)
        return 4;
    if (bsearch(&missing, sorted, 0, sizeof(sorted[0]), compare_int) != NULL)
        return 5;
    return 0;
}

static int check_qsort(void)
{
    int values[] = { 7, -3, 7, 1, 0, -3, 99, 2 };
    struct record records[] = {
        { 4, 0 }, { 1, 1 }, { 4, 2 }, { -1, 3 }, { 1, 4 }, { 0, 5 }
    };
    int singleton = 11;
    size_t index;

    qsort(values, 8, sizeof(values[0]), compare_int);
    for (index = 1; index < 8; ++index) {
        if (values[index - 1] > values[index])
            return 1;
    }
    ordinary_qsort_calls = 0;
    qsort(records, 6, sizeof(records[0]), compare_record);
    if (ordinary_qsort_calls == 0)
        return 2;
    for (index = 1; index < 6; ++index) {
        if (records[index - 1].key > records[index].key)
            return 3;
    }
    qsort(&singleton, 1, sizeof(singleton), compare_int);
    qsort(&singleton, 0, sizeof(singleton), compare_int);
    return singleton == 11 ? 0 : 4;
}

static int check_context_sort(int use_internal_helper, int multiplier)
{
    struct record records[] = {
        { 1, 0 }, { 5, 1 }, { 3, 2 }, { 5, 3 }, { -2, 4 }, { 0, 5 }
    };
    struct direction direction = { multiplier, 0 };
    size_t index;

    expected_context = &direction;
    context_mismatch = 0;
    if (use_internal_helper) {
#if defined(CRABC_CALLBACK_ALGORITHMS_FREESTANDING)
        __qsort_r(records, 6, sizeof(records[0]), compare_record_context,
                  &direction);
#else
        return 3;
#endif
    } else {
        qsort_r(records, 6, sizeof(records[0]), compare_record_context,
                &direction);
    }
    expected_context = NULL;
    if (context_mismatch || direction.calls == 0)
        return 1;
    for (index = 1; index < 6; ++index) {
        if ((multiplier < 0 && records[index - 1].key < records[index].key) ||
            (multiplier > 0 && records[index - 1].key > records[index].key))
            return 2;
    }
    return 0;
}

#if defined(CRABC_CALLBACK_ALGORITHMS_FREESTANDING) && \
    defined(CRABC_CALLBACK_ALGORITHMS_OVERRIDE_QSORT_R)
static int qsort_r_override_called;

void qsort_r(void *base, size_t nel, size_t width,
             compare_context_signature compare, void *argument)
{
    qsort_r_override_called += 1;
    __qsort_r(base, nel, width, compare, argument);
}
#endif

static int check_qsort_r(void)
{
    int result = check_context_sort(0, -1);

    if (result != 0)
        return result;
#if defined(CRABC_CALLBACK_ALGORITHMS_FREESTANDING) && \
    defined(CRABC_CALLBACK_ALGORITHMS_OVERRIDE_QSORT_R)
    if (qsort_r_override_called == 0)
        return 3;
#endif
#if defined(CRABC_CALLBACK_ALGORITHMS_FREESTANDING)
    result = check_context_sort(1, 1);
    return result == 0 ? 0 : 10 + result;
#else
    return 0;
#endif
}

static int check_wide_records(void)
{
    static const int keys[] = { 9, -1, 4, 4, 0, 12, -7 };
    struct wide_record records[7];
    size_t index;
    size_t byte;

    for (index = 0; index < 7; ++index) {
        records[index].key = keys[index];
        records[index].serial = (int)index;
        for (byte = 0; byte < sizeof(records[index].payload); ++byte)
            records[index].payload[byte] = (unsigned char)(index + byte);
    }
    qsort(records, 7, sizeof(records[0]), compare_wide_record);
    for (index = 1; index < 7; ++index) {
        if (records[index - 1].key > records[index].key)
            return 1;
    }
    for (index = 0; index < 7; ++index) {
        unsigned serial = (unsigned)records[index].serial;

        if (serial >= 7 || records[index].key != keys[serial])
            return 2;
        for (byte = 0; byte < sizeof(records[index].payload); ++byte) {
            if (records[index].payload[byte] !=
                (unsigned char)(serial + byte))
                return 3;
        }
    }
    return 0;
}

#if !defined(CRABC_CALLBACK_ALGORITHMS_FREESTANDING)
/* Comparator reentry uses independent caller records. No callback mutates
 * the array or tree being ordered, and no returned hash entry survives table
 * destruction. The normal allocation provider owns every scratch block. */
struct callback_owner {
    int linear[4];
    size_t count;
    char hash_key[16];
    int hash_value;
    ENTRY *entry;
    int *keys[5];
    unsigned calls, visits, destroyed;
    unsigned visited_keys, destroyed_keys;
    int failed;
};

static struct callback_owner *active_owner;

static void exercise_callback_owner(void)
{
    struct callback_owner *owner = active_owner;
    static const int sorted[] = { -2, 1, 3, 6 };
    int key = 3;
    unsigned char *scratch = malloc(48);
    if (!scratch) { owner->failed = 1; return; }
    memset(scratch, 0x5a, 48);
    unsigned char *grown = realloc(scratch, 96);
    if (!grown) { free(scratch); owner->failed = 1; return; }
    for (size_t index = 0; index < 48; ++index)
        if (grown[index] != 0x5a) owner->failed = 1;
    free(grown);
    if (bsearch(&key, sorted, 4, sizeof key, compare_int) != sorted + 2 ||
            lsearch(&key, owner->linear, &owner->count, sizeof key, compare_int)
                != owner->linear + 1 || owner->count != 2 ||
            lfind(&key, owner->linear, &owner->count, sizeof key, compare_int)
                != owner->linear + 1) owner->failed = 1;
    ENTRY lookup = { owner->hash_key, NULL };
    ENTRY *entry = hsearch(lookup, FIND);
    if (entry != owner->entry || !entry || entry->data != &owner->hash_value ||
            entry->key != owner->hash_key) owner->failed = 1;
    struct queue_node { struct queue_node *next, *previous; int value; };
    struct queue_node first = {0}, second = {0};
    insque(&first, NULL);
    insque(&second, &first);
    if (first.next != &second || second.previous != &first ||
            first.previous || second.next) owner->failed = 1;
    remque(&second);
    if (first.next || second.previous != &first) owner->failed = 1;
    remque(&first);
    ++owner->calls;
}

static int compare_allocating(const void *left, const void *right)
{
    int result = compare_int(left, right);
    exercise_callback_owner();
    return result;
}

static int compare_allocating_context(const void *left, const void *right,
    void *opaque)
{
    if (opaque != active_owner) active_owner->failed = 1;
    return compare_allocating(left, right);
}

static void visit_allocating(const void *node, VISIT visit, int depth)
{
    if (depth < 0) active_owner->failed = 1;
    if (visit == leaf || visit == postorder) {
        const int *key = *(const int *const *)node;
        size_t index;
        for (index = 0; index < 5 && key != active_owner->keys[index]; ++index) {}
        if (index == 5 || (active_owner->visited_keys & (1u << index)))
            active_owner->failed = 1;
        else active_owner->visited_keys |= 1u << index;
        ++active_owner->visits;
    }
    exercise_callback_owner();
}

static void destroy_allocating(void *key)
{
    exercise_callback_owner();
    size_t index;
    for (index = 0; index < 5 && key != active_owner->keys[index]; ++index) {}
    if (index == 5 || (active_owner->destroyed_keys & (1u << index))) {
        active_owner->failed = 1;
        return;
    }
    active_owner->destroyed_keys |= 1u << index;
    ++active_owner->destroyed;
    active_owner->keys[index] = NULL;
    free(key);
}

static int check_reentrant_caller_ownership(void)
{
    struct callback_owner owner = { .linear = { 1 }, .count = 1,
        .hash_key = "callback-owner", .hash_value = 41 };
    ENTRY item = { owner.hash_key, &owner.hash_value };
    if (!hcreate(16) || !(owner.entry = hsearch(item, ENTER))) return 1;
    active_owner = &owner;
    int values[] = { 4, 1, 7, 2, 5 };
    qsort(values, 5, sizeof values[0], compare_allocating);
    qsort_r(values, 5, sizeof values[0], compare_allocating_context, &owner);
    for (size_t index = 1; index < 5; ++index)
        if (values[index-1] > values[index]) owner.failed = 1;
    int sought = 5;
    if (bsearch(&sought, values, 5, sizeof values[0], compare_allocating)
            != values + 3) owner.failed = 1;
    void *root = NULL;
    int **keys = owner.keys;
    for (size_t index = 0; index < 5; ++index) {
        keys[index] = malloc(sizeof *keys[index]);
        if (!keys[index]) return 2;
        *keys[index] = values[index];
        void *node = tsearch(keys[index], &root, compare_allocating);
        if (!node || *(int **)node != keys[index]) return 3;
    }
    twalk(root, visit_allocating);
    if (owner.visits != 5 || owner.visited_keys != 31) owner.failed = 1;
    for (size_t index = 0; index < 5; ++index) {
        void *node = tfind(keys[index], &root, compare_allocating);
        if (!node || *(int **)node != keys[index]) owner.failed = 1;
    }
    /* Deletion releases only its internal node. The caller releases the
     * removed key; the returned parent hint is never dereferenced. */
    if (!tdelete(keys[2], &root, compare_allocating)) {
        tdestroy(root, destroy_allocating);
        hdestroy();
        active_owner = NULL;
        return 4;
    }
    free(keys[2]);
    keys[2] = NULL;
    owner.destroyed_keys = 1u << 2;
    tdestroy(root, destroy_allocating);
    root = NULL;
    if (owner.destroyed != 4 || owner.destroyed_keys != 31 ||
            !owner.calls || owner.count != 2 ||
            owner.linear[1] != 3 || owner.hash_value != 41) owner.failed = 1;
    hdestroy();
    active_owner = NULL;
    return owner.failed ? 4 : 0;
}
#endif

static int callback_algorithms_case(void)
{
    int result;

#if !defined(CRABC_CALLBACK_ALGORITHMS_FREESTANDING)
    result = check_reentrant_caller_ownership();
    if (result) return 40 + result;
#endif
    result = check_bsearch();
    if (result != 0)
        return result;
    result = check_qsort();
    if (result != 0)
        return 10 + result;
    result = check_qsort_r();
    if (result != 0)
        return 20 + result;
    result = check_wide_records();
    return result == 0 ? 0 : 30 + result;
}

#if defined(CRABC_CALLBACK_ALGORITHMS_FREESTANDING)
int crabc_x86_64_callback_algorithms_probe(void)
{
    return callback_algorithms_case();
}
#else
int main(void)
{
    return callback_algorithms_case();
}
#endif
