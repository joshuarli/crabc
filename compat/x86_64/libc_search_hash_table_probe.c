/* Native Linux/x86-64 pinned-musl/crabc <search.h> hash-table differential. */

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

typedef int (*hcreate_signature)(size_t);
typedef void (*hdestroy_signature)(void);
typedef ENTRY *(*hsearch_signature)(ENTRY, ACTION);
typedef int (*hcreate_r_signature)(size_t, struct hsearch_data *);
typedef void (*hdestroy_r_signature)(struct hsearch_data *);
typedef int (*hsearch_r_signature)(
    ENTRY, ACTION, ENTRY **, struct hsearch_data *);

_Static_assert(sizeof(ENTRY) == 16 && _Alignof(ENTRY) == 8 &&
    offsetof(ENTRY, key) == 0 && offsetof(ENTRY, data) == 8,
    "x86 ENTRY ABI");
_Static_assert(sizeof(struct hsearch_data) == 16 &&
    _Alignof(struct hsearch_data) == 8 &&
    offsetof(struct hsearch_data, __tab) == 0 &&
    offsetof(struct hsearch_data, __unused1) == 8 &&
    offsetof(struct hsearch_data, __unused2) == 12,
    "x86 hsearch_data ABI");
_Static_assert(FIND == 0 && ENTER == 1,
    "musl ACTION values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&hcreate),
    hcreate_signature) &&
    __builtin_types_compatible_p(__typeof__(&hdestroy), hdestroy_signature) &&
    __builtin_types_compatible_p(__typeof__(&hsearch), hsearch_signature) &&
    __builtin_types_compatible_p(__typeof__(&hcreate_r), hcreate_r_signature) &&
    __builtin_types_compatible_p(__typeof__(&hdestroy_r),
        hdestroy_r_signature) &&
    __builtin_types_compatible_p(__typeof__(&hsearch_r), hsearch_r_signature),
    "selected hash-table declarations");

static unsigned allocation_calls;
static unsigned release_calls;
static int fail_next_allocation;

#ifdef CRABC_SEARCH_HASH_TABLE_FREESTANDING
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
extern void *__real_calloc(size_t, size_t);
extern void __real_free(void *);

void *__wrap_calloc(size_t count, size_t size)
{
    allocation_calls += 1;
    if (fail_next_allocation) {
        fail_next_allocation = 0;
        errno = ENOMEM;
        return NULL;
    }
    return __real_calloc(count, size);
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
    fail_next_allocation = 0;
}

static int check_zero_capacity_duplicate_and_destroy(void)
{
    struct hsearch_data table = { 0 };
    int first_data = 11;
    int replacement_data = 12;
    ENTRY first = { "duplicate", &first_data };
    ENTRY replacement = { "duplicate", &replacement_data };
    ENTRY missing = { "missing", NULL };
    ENTRY *stored = NULL;
    ENTRY *duplicate = NULL;
    unsigned releases;

    reset_allocation_observation();
    if (hcreate_r(0, &table) != 1)
        return 1;
    if (table.__tab == NULL)
        return 2;
    if (
#ifndef CRABC_SEARCH_HASH_TABLE_FREESTANDING
        allocation_calls != 2
#else
        0
#endif
    )
        return 3;
    if (hsearch_r(first, ENTER, &stored, &table) != 1 || stored == NULL ||
        stored->key != first.key || stored->data != &first_data)
        return 4;
    if (hsearch_r(replacement, ENTER, &duplicate, &table) != 1 ||
        duplicate != stored || duplicate->key != first.key ||
        duplicate->data != &first_data)
        return 5;
    stored = (ENTRY *)(uintptr_t)1;
    if (hsearch_r(missing, FIND, &stored, &table) != 0 || stored != NULL)
        return 6;
    errno = EDOM;
    hdestroy_r(&table);
    if (table.__tab != NULL || errno != EDOM)
        return 7;
#ifndef CRABC_SEARCH_HASH_TABLE_FREESTANDING
    if (release_calls != 2)
        return 8;
#endif
    releases = release_calls;
    hdestroy_r(&table);
    if (table.__tab != NULL || release_calls != releases)
        return 9;
    return 0;
}

static int check_global_reentrant_independence(void)
{
    struct hsearch_data table = { 0 };
    int global_data = 21;
    int reentrant_data = 22;
    ENTRY global_item = { "shared-key", &global_data };
    ENTRY reentrant_item = { "shared-key", &reentrant_data };
    ENTRY *result = NULL;

    if (hcreate(3) != 1 || hcreate_r(3, &table) != 1)
        return 1;
    if (hsearch(global_item, ENTER) == NULL ||
        hsearch_r(reentrant_item, ENTER, &result, &table) != 1 ||
        result == NULL || result->data != &reentrant_data)
        return 2;
    result = hsearch(global_item, FIND);
    if (result == NULL || result->data != &global_data)
        return 3;
    hdestroy_r(&table);
    result = hsearch(global_item, FIND);
    if (result == NULL || result->data != &global_data)
        return 4;
    hdestroy();
    return 0;
}

static int check_resize_failure_rollback(void)
{
    struct hsearch_data table = { 0 };
    char keys[7][3] = {
        "a0", "a1", "a2", "a3", "a4", "a5", "a6"
    };
    int values[7] = { 30, 31, 32, 33, 34, 35, 36 };
    ENTRY *result = NULL;
    ENTRY *old_mapping_entry = NULL;
    ENTRY *current_mapping_entry = NULL;
    unsigned index;

    reset_allocation_observation();
    if (hcreate_r(0, &table) != 1) return 1;
    for (index = 0; index < 6; ++index) {
        ENTRY item = { keys[index], &values[index] };
        if (hsearch_r(item, ENTER, &result, &table) != 1 ||
            result == NULL || result->data != &values[index])
            return 2;
        if (index == 0) old_mapping_entry = result;
    }

    if (!begin_allocation_failure()) return 3;
    errno = 0;
    {
        ENTRY seventh = { keys[6], &values[6] };
        if (hsearch_r(seventh, ENTER, &result, &table) != 0 ||
            result != NULL || errno != ENOMEM)
            return 4;
        if (!end_allocation_failure()) return 5;
#ifdef CRABC_SEARCH_HASH_TABLE_FREESTANDING
        if (!mapping_is_live(old_mapping_entry)) return 6;
#endif
        if (hsearch_r(seventh, FIND, &result, &table) != 0 || result != NULL)
            return 7;
        if (hsearch_r(seventh, ENTER, &result, &table) != 1 ||
            result == NULL || result->data != &values[6])
            return 8;
        current_mapping_entry = result;
#ifdef CRABC_SEARCH_HASH_TABLE_FREESTANDING
        if (mapping_is_live(old_mapping_entry)) return 9;
#endif
    }
    for (index = 0; index < 7; ++index) {
        ENTRY item = { keys[index], NULL };
        if (hsearch_r(item, FIND, &result, &table) != 1 ||
            result == NULL || result->data != &values[index])
            return 10;
    }
    hdestroy_r(&table);
#ifdef CRABC_SEARCH_HASH_TABLE_FREESTANDING
    if (mapping_is_live(current_mapping_entry))
        return 11;
#else
    if (allocation_calls != 4 || release_calls != 3)
        return 12;
#endif
    return 0;
}

static int check_unsigned_hash_bytes(void)
{
    struct hsearch_data table = { 0 };
    char ascii_key[] = "a";
    char high_key[2] = { (char)0x80, '\0' };
    ENTRY ascii_item = { ascii_key, ascii_key };
    ENTRY high_item = { high_key, high_key };
    ENTRY *ascii_result = NULL;
    ENTRY *high_result = NULL;
    ptrdiff_t entry_delta;

    if (hcreate_r(512, &table) != 1)
        return 1;
    if (hsearch_r(ascii_item, ENTER, &ascii_result, &table) != 1 ||
        hsearch_r(high_item, ENTER, &high_result, &table) != 1 ||
        ascii_result == NULL || high_result == NULL)
        return 2;
    entry_delta = high_result - ascii_result;
    if (entry_delta != 31)
        return 3;
    hdestroy_r(&table);
    return 0;
}

static int check_overflow_and_repeated_create(void)
{
    struct hsearch_data table = { 0 };
    int first_data = 81;
    int second_data = 82;
    ENTRY first_item = { "first-live", &first_data };
    ENTRY second_item = { "second-live", &second_data };
    ENTRY *first_entry = NULL;
    ENTRY *second_entry = NULL;
    unsigned releases;

    errno = 0;
    if (hcreate_r((size_t)-1, &table) != 0 || table.__tab != NULL ||
        errno != ENOMEM)
        return 1;
    hdestroy_r(&table);

    reset_allocation_observation();
    if (hcreate_r(1, &table) != 1 ||
        hsearch_r(first_item, ENTER, &first_entry, &table) != 1 ||
        hcreate_r(1, &table) != 1 ||
        hsearch_r(second_item, ENTER, &second_entry, &table) != 1)
        return 2;
#ifndef CRABC_SEARCH_HASH_TABLE_FREESTANDING
    if (allocation_calls != 4)
        return 3;
#endif
    hdestroy_r(&table);
#ifdef CRABC_SEARCH_HASH_TABLE_FREESTANDING
    if (!mapping_is_live(first_entry) || mapping_is_live(second_entry))
        return 4;
#else
    if (release_calls != 2)
        return 4;
#endif
    releases = release_calls;
    hdestroy_r(&table);
    if (release_calls != releases)
        return 5;

    reset_allocation_observation();
    if (hcreate(1) != 1 ||
        (first_entry = hsearch(first_item, ENTER)) == NULL ||
        hcreate(1) != 1 ||
        (second_entry = hsearch(second_item, ENTER)) == NULL)
        return 6;
#ifndef CRABC_SEARCH_HASH_TABLE_FREESTANDING
    if (allocation_calls != 4)
        return 7;
#endif
    hdestroy();
#ifdef CRABC_SEARCH_HASH_TABLE_FREESTANDING
    if (!mapping_is_live(first_entry) || mapping_is_live(second_entry))
        return 8;
#else
    if (release_calls != 2)
        return 8;
#endif
    releases = release_calls;
    hdestroy();
    if (release_calls != releases)
        return 9;
    return 0;
}

int crabc_x86_64_search_hash_table_probe(void)
{
    int result = check_zero_capacity_duplicate_and_destroy();

    if (result != 0) return 10 + result;
    result = check_global_reentrant_independence();
    if (result != 0) return 30 + result;
    result = check_resize_failure_rollback();
    if (result != 0) return 50 + result;
    result = check_unsigned_hash_bytes();
    if (result != 0) return 70 + result;
    result = check_overflow_and_repeated_create();
    if (result != 0) return 90 + result;
    return 0;
}

#ifndef CRABC_SEARCH_HASH_TABLE_FREESTANDING
int main(void)
{
    return crabc_x86_64_search_hash_table_probe();
}
#endif
