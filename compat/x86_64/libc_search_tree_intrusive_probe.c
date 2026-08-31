/* Native Linux/x86-64 pinned-musl/crabc <search.h> callback-tree differential. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <search.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

typedef void *(*tdelete_signature)(const void *restrict, void **restrict,
    int (*)(const void *, const void *));
typedef void *(*tfind_signature)(const void *, void *const *,
    int (*)(const void *, const void *));
typedef void *(*tsearch_signature)(const void *, void **,
    int (*)(const void *, const void *));
typedef void (*twalk_signature)(const void *,
    void (*)(const void *, VISIT, int));
typedef void (*tdestroy_signature)(void *, void (*)(void *));

_Static_assert(preorder == 0 && postorder == 1 && endorder == 2 && leaf == 3,
    "musl VISIT values");
_Static_assert(sizeof(VISIT) == 4, "x86 VISIT ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tdelete),
    tdelete_signature) &&
    __builtin_types_compatible_p(__typeof__(&tfind), tfind_signature) &&
    __builtin_types_compatible_p(__typeof__(&tsearch), tsearch_signature) &&
    __builtin_types_compatible_p(__typeof__(&twalk), twalk_signature) &&
    __builtin_types_compatible_p(__typeof__(&tdestroy), tdestroy_signature),
    "selected callback-tree declarations");

static unsigned allocation_calls;
static unsigned release_calls;
static size_t last_allocation_size;
static int fail_next_allocation;

#ifdef CRABC_SEARCH_TREE_FREESTANDING
struct crabc_limit {
    unsigned long current;
    unsigned long maximum;
};

static struct crabc_limit saved_address_space_limit;

static long raw_prlimit64(const struct crabc_limit *new_limit,
    struct crabc_limit *old_limit)
{
    register long result __asm__("rax") = 302;
    register long fourth __asm__("r10") = (long)old_limit;

    __asm__ volatile("syscall"
        : "+a"(result)
        : "D"(0L), "S"(9L), "d"((long)new_limit), "r"(fourth)
        : "rcx", "r11", "memory");
    return result;
}

static int begin_allocation_failure(void)
{
    struct crabc_limit blocked;

    if (raw_prlimit64(NULL, &saved_address_space_limit) != 0)
        return 0;
    blocked.current = 1;
    blocked.maximum = saved_address_space_limit.maximum;
    return raw_prlimit64(&blocked, NULL) == 0;
}

static int end_allocation_failure(void)
{
    return raw_prlimit64(&saved_address_space_limit, NULL) == 0;
}

static int mapping_is_live(const void *pointer)
{
    unsigned char residency;
    void *page = (void *)((uintptr_t)pointer & ~(uintptr_t)4095);

    errno = 0;
    return mincore(page, 4096, &residency) == 0;
}
#else
extern void *__real_malloc(size_t);
extern void __real_free(void *);

void *__wrap_malloc(size_t size)
{
    allocation_calls += 1;
    last_allocation_size = size;
    if (fail_next_allocation) {
        fail_next_allocation = 0;
        errno = ENOMEM;
        return NULL;
    }
    return __real_malloc(size);
}

void __wrap_free(void *pointer)
{
    if (pointer != NULL) release_calls += 1;
    __real_free(pointer);
}

static int begin_allocation_failure(void)
{
    fail_next_allocation = 1;
    return 1;
}

static int end_allocation_failure(void)
{
    return 1;
}
#endif

static void reset_allocation_observation(void)
{
    allocation_calls = 0;
    release_calls = 0;
    last_allocation_size = 0;
    fail_next_allocation = 0;
}

static unsigned compare_calls;
static int compared_existing[128];

static int compare_int(const void *search_key, const void *stored_key)
{
    int left = *(const int *)search_key;
    int right = *(const int *)stored_key;

    if (compare_calls < 128) compared_existing[compare_calls] = right;
    compare_calls += 1;
    return (left > right) - (left < right);
}

static int node_key(const void *node)
{
    return **(const int *const *)node;
}

static int check_null_duplicate_and_rotations(void)
{
    int keys[] = { 50, 30, 40, 10, 70, 60 };
    void *root = NULL;
    void *first;
    void *second;

    reset_allocation_observation();
    compare_calls = 0;
    if (tsearch(&keys[0], NULL, compare_int) != NULL || compare_calls != 0)
        return 1;
    if (tfind(&keys[0], NULL, compare_int) != NULL ||
        tdelete(&keys[0], NULL, compare_int) != NULL || compare_calls != 0)
        return 2;
    twalk(NULL, NULL);
    tdestroy(NULL, NULL);

    first = tsearch(&keys[0], &root, compare_int);
    if (first == NULL || root != first || node_key(first) != 50 ||
        compare_calls != 0)
        return 3;
    compare_calls = 0;
    if (tsearch(&keys[1], &root, compare_int) == NULL ||
        compare_calls != 1 || compared_existing[0] != 50)
        return 4;
    compare_calls = 0;
    if (tsearch(&keys[2], &root, compare_int) == NULL ||
        compare_calls != 2 || compared_existing[0] != 50 ||
        compared_existing[1] != 30 || node_key(root) != 40)
        return 5;
    second = tsearch(&keys[2], &root, compare_int);
    if (second == NULL || second != root || node_key(second) != 40)
        return 6;
#ifndef CRABC_SEARCH_TREE_FREESTANDING
    if (allocation_calls != 3 || last_allocation_size != 32)
        return 7;
#endif
    tdestroy(root, NULL);
#ifdef CRABC_SEARCH_TREE_FREESTANDING
    if (mapping_is_live(first) || mapping_is_live(second)) return 8;
#else
    if (release_calls != 3) return 8;
#endif

    root = NULL;
    if (tsearch(&keys[3], &root, compare_int) == NULL ||
        tsearch(&keys[4], &root, compare_int) == NULL ||
        tsearch(&keys[5], &root, compare_int) == NULL || node_key(root) != 60)
        return 9;
    tdestroy(root, NULL);
    return 0;
}

struct walk_event {
    int key;
    int visit;
    int depth;
};

static struct walk_event walk_events[96];
static unsigned walk_event_count;
static unsigned visit_counts[4];
static int maximum_depth;

static void record_walk(const void *node, VISIT visit, int depth)
{
    if (walk_event_count < 96) {
        walk_events[walk_event_count].key = node_key(node);
        walk_events[walk_event_count].visit = (int)visit;
        walk_events[walk_event_count].depth = depth;
    }
    walk_event_count += 1;
    if ((unsigned)visit < 4) visit_counts[visit] += 1;
    if (depth > maximum_depth) maximum_depth = depth;
}

static int check_balancing_find_and_walk(void)
{
    int keys[15];
    void *nodes[15];
    void *root = NULL;
    unsigned index;

    reset_allocation_observation();
    for (index = 0; index < 15; ++index) {
        keys[index] = (int)index;
        nodes[index] = tsearch(&keys[index], &root, compare_int);
        if (nodes[index] == NULL || node_key(nodes[index]) != (int)index)
            return 1;
    }
    if (node_key(root) != 7) return 2;
    for (index = 0; index < 15; ++index) {
        void *found = tfind(&keys[index], &root, compare_int);
        if (found != nodes[index]) return 3;
    }
    {
        int missing = 99;
        if (tfind(&missing, &root, compare_int) != NULL) return 4;
    }

    walk_event_count = 0;
    visit_counts[0] = visit_counts[1] = visit_counts[2] = visit_counts[3] = 0;
    maximum_depth = 0;
    twalk(root, record_walk);
    if (walk_event_count != 29 || visit_counts[preorder] != 7 ||
        visit_counts[postorder] != 7 || visit_counts[endorder] != 7 ||
        visit_counts[leaf] != 8 || maximum_depth != 3)
        return 5;
    if (walk_events[0].key != 7 || walk_events[0].visit != preorder ||
        walk_events[0].depth != 0 || walk_events[28].key != 7 ||
        walk_events[28].visit != endorder || walk_events[28].depth != 0)
        return 6;
    tdestroy(root, NULL);
#ifdef CRABC_SEARCH_TREE_FREESTANDING
    for (index = 0; index < 15; ++index)
        if (mapping_is_live(nodes[index])) return 7;
#else
    if (allocation_calls != 15 || release_calls != 15) return 7;
#endif
    return 0;
}

static unsigned observed_key_count;
static unsigned observed_key_mask;

static void observe_key(void *key)
{
    int value = *(int *)key;

    observed_key_count += 1;
    if ((unsigned)value < 32) observed_key_mask |= 1u << value;
}

static int check_delete_parent_identity_and_ownership(void)
{
    int keys[] = { 4, 2, 6, 1, 3, 5, 7 };
    int missing = 99;
    void *nodes[7];
    void *root = NULL;
    void *old_root;
    void *parent;
    unsigned index;

    reset_allocation_observation();
    for (index = 0; index < 7; ++index) {
        nodes[index] = tsearch(&keys[index], &root, compare_int);
        if (nodes[index] == NULL) return 1;
    }
    if (tdelete(&missing, &root, compare_int) != NULL || node_key(root) != 4)
        return 2;
    parent = tdelete(&keys[3], &root, compare_int);
    if (parent != nodes[1] || tfind(&keys[3], &root, compare_int) != NULL)
        return 3;
#ifdef CRABC_SEARCH_TREE_FREESTANDING
    if (mapping_is_live(nodes[3]) || !mapping_is_live(nodes[1])) return 4;
#else
    if (release_calls != 1) return 4;
#endif

    old_root = root;
    parent = tdelete(&keys[0], &root, compare_int);
    if (parent != old_root || node_key(old_root) != 3 ||
        tfind(&keys[0], &root, compare_int) != NULL ||
        tfind(&keys[4], &root, compare_int) != old_root)
        return 5;
#ifdef CRABC_SEARCH_TREE_FREESTANDING
    if (mapping_is_live(nodes[4]) || !mapping_is_live(old_root)) return 6;
#else
    if (release_calls != 2) return 6;
#endif

    observed_key_count = 0;
    observed_key_mask = 0;
    tdestroy(root, observe_key);
    if (observed_key_count != 5 ||
        observed_key_mask != ((1u << 2) | (1u << 3) | (1u << 5) |
            (1u << 6) | (1u << 7)))
        return 7;
#ifndef CRABC_SEARCH_TREE_FREESTANDING
    if (release_calls != 7) return 8;
#endif
    return 0;
}

static int check_allocation_failure_rollback_and_repeated_cycles(void)
{
    int keys[] = { 8, 4, 12, 6 };
    void *root = NULL;
    void *old_root;
    void *failed;
    unsigned index;

    reset_allocation_observation();
    for (index = 0; index < 3; ++index)
        if (tsearch(&keys[index], &root, compare_int) == NULL) return 1;
    old_root = root;
    if (!begin_allocation_failure()) return 2;
    errno = 0;
    failed = tsearch(&keys[3], &root, compare_int);
    if (failed != NULL || errno != ENOMEM || root != old_root ||
        tfind(&keys[0], &root, compare_int) == NULL ||
        tfind(&keys[1], &root, compare_int) == NULL ||
        tfind(&keys[2], &root, compare_int) == NULL ||
        tfind(&keys[3], &root, compare_int) != NULL)
        return 3;
    if (!end_allocation_failure()) return 4;
    if (tsearch(&keys[3], &root, compare_int) == NULL) return 5;
    tdestroy(root, NULL);

    for (index = 0; index < 32; ++index) {
        int cycle_keys[] = { (int)index, (int)index + 100 };
        root = NULL;
        if (tsearch(&cycle_keys[0], &root, compare_int) == NULL ||
            tsearch(&cycle_keys[1], &root, compare_int) == NULL)
            return 6;
        tdestroy(root, NULL);
    }
#ifndef CRABC_SEARCH_TREE_FREESTANDING
    if (allocation_calls != release_calls + 1) return 7;
    /* The one failed wrapped allocation has no matching free. */
    if (allocation_calls != 69 || release_calls != 68) return 8;
#endif
    return 0;
}

int crabc_x86_64_search_tree_intrusive_probe(void)
{
    int result = check_null_duplicate_and_rotations();

    if (result != 0) return 10 + result;
    result = check_balancing_find_and_walk();
    if (result != 0) return 30 + result;
    result = check_delete_parent_identity_and_ownership();
    if (result != 0) return 50 + result;
    result = check_allocation_failure_rollback_and_repeated_cycles();
    if (result != 0) return 70 + result;
    return 0;
}

#ifndef CRABC_SEARCH_TREE_FREESTANDING
int main(void)
{
    return crabc_x86_64_search_tree_intrusive_probe();
}
#endif
