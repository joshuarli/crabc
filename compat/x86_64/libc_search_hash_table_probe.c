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

/* Report API observations without selecting stdio in the freestanding image. */
static int trace_observations(const char *name, const int *values, size_t count)
{
    static const char digits[] = "0123456789abcdef";
    char line[96];
    size_t length = 0;
    size_t index;
    register long result __asm__("rax") = 1;

    while (name[length] != '\0') {
        if (length >= sizeof line - 2) return 0;
        line[length] = name[length];
        ++length;
    }
    if (length + count * 2 + 2 > sizeof line) return 0;
    line[length++] = ':';
    for (index = 0; index < count; ++index) {
        if (values[index] < 0 || values[index] > 255) return 0;
        line[length++] = digits[(unsigned)values[index] >> 4];
        line[length++] = digits[(unsigned)values[index] & 15];
    }
    line[length++] = '\n';
    __asm__ volatile("syscall"
        : "+a"(result)
        : "D"(1L), "S"(line), "d"((long)length)
        : "rcx", "r11", "memory");
    return result == (long)length;
}

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
    {
        int observations[] = {
            duplicate == stored, duplicate->key == first.key,
            duplicate->data == &first_data
        };
        if (!trace_observations("duplicate", observations, 3)) return 10;
    }
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
    {
        int observations[] = { stored == NULL, table.__tab == NULL };
        if (!trace_observations("miss-destroy", observations, 2)) return 11;
    }
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
    int observations[3];

    if (hcreate(3) != 1 || hcreate_r(3, &table) != 1)
        return 1;
    if (hsearch(global_item, ENTER) == NULL ||
        hsearch_r(reentrant_item, ENTER, &result, &table) != 1 ||
        result == NULL || result->data != &reentrant_data)
        return 2;
    observations[0] = result->data == &reentrant_data;
    result = hsearch(global_item, FIND);
    if (result == NULL || result->data != &global_data)
        return 3;
    observations[1] = result->data == &global_data;
    hdestroy_r(&table);
    result = hsearch(global_item, FIND);
    if (result == NULL || result->data != &global_data)
        return 4;
    observations[2] = result->data == &global_data;
    hdestroy();
    if (!trace_observations("global-record", observations, 3)) return 5;
    return 0;
}

static int check_collisions_and_record_ownership(void)
{
    struct hsearch_data first = { 0 };
    struct hsearch_data second = { 0 };
    char keys[4][2] = { "a", "i", "q", "y" };
    char equal_keys[4][2] = { "a", "i", "q", "y" };
    int first_values[4] = { 41, 42, 43, 44 };
    int second_values[4] = { 51, 52, 53, 54 };
    int changed_value = 64;
    int observations[16] = { 0 };
    ENTRY *first_entries[4] = { NULL };
    ENTRY *second_entries[4] = { NULL };
    ENTRY *result = NULL;
    unsigned index;

    /* All four hashes have the same low three bits at the minimum size. */
    if (hcreate_r(0, &first) != 1 || hcreate_r(0, &second) != 1)
        return 1;
    for (index = 0; index < 4; ++index) {
        unsigned reverse = 3 - index;
        ENTRY left = { keys[index], &first_values[index] };
        ENTRY right = { keys[reverse], &second_values[reverse] };

        if (hsearch_r(left, ENTER, &first_entries[index], &first) != 1 ||
            hsearch_r(right, ENTER, &second_entries[reverse], &second) != 1 ||
            first_entries[index] == NULL || second_entries[reverse] == NULL)
            return 2;
        observations[index] = first_entries[index]->key == keys[index];
        observations[4 + index] =
            second_entries[reverse]->data == &second_values[reverse];
    }
    for (index = 0; index < 4; ++index) {
        ENTRY duplicate = { equal_keys[index], &changed_value };

        if (hsearch_r(duplicate, ENTER, &result, &first) != 1 ||
            result != first_entries[index] || result->key != keys[index] ||
            result->data != &first_values[index])
            return 3;
        observations[8 + index] = result->key != equal_keys[index];
        if (hsearch_r(duplicate, FIND, &result, &second) != 1 ||
            result != second_entries[index] ||
            result->data != &second_values[index])
            return 4;
        observations[12 + index] = result != first_entries[index];
    }
    if (!trace_observations("colliding-records", observations, 16))
        return 5;

    first_entries[2]->data = &changed_value;
    {
        ENTRY lookup = { equal_keys[2], NULL };
        ENTRY *left = NULL;
        ENTRY *right = NULL;
        int changed[4];

        if (hsearch_r(lookup, FIND, &left, &first) != 1 ||
            hsearch_r(lookup, FIND, &right, &second) != 1 ||
            left == NULL || right == NULL)
            return 6;
        changed[0] = left == first_entries[2];
        changed[1] = left->data == &changed_value;
        changed[2] = right == second_entries[2];
        changed[3] = right->data == &second_values[2];
        if (!trace_observations("entry-mutation", changed, 4)) return 7;
        if (!changed[0] || !changed[1] || !changed[2] || !changed[3])
            return 8;
    }

    hdestroy_r(&first);
    if (first.__tab != NULL) return 9;
    for (index = 0; index < 4; ++index) {
        ENTRY lookup = { equal_keys[index], NULL };

        if (hsearch_r(lookup, FIND, &result, &second) != 1 ||
            result != second_entries[index])
            return 10;
    }
    if (hcreate_r(0, &first) != 1) return 11;
    {
        ENTRY lookup = { equal_keys[2], NULL };
        int absent = hsearch_r(lookup, FIND, &result, &first);
        int lifecycle[] = { first.__tab != NULL, absent, result == NULL,
            second.__tab != NULL };

        if (!trace_observations("record-lifecycle", lifecycle, 4))
            return 12;
        if (absent != 0 || result != NULL) return 13;
    }
    hdestroy_r(&first);
    hdestroy_r(&second);
    return 0;
}

static int check_failed_create_recovery(void)
{
    struct hsearch_data table = { 0 };
    int created;
    int failure_errno;
    int observations[6];

    if (!begin_allocation_failure()) return 1;
    errno = 0;
    created = hcreate_r(8, &table);
    failure_errno = errno;
    if (!end_allocation_failure()) return 2;
    observations[0] = created;
    observations[1] = failure_errno;
    observations[2] = table.__tab == NULL;
    if (created != 0 || failure_errno != ENOMEM || table.__tab != NULL)
        return 3;
    observations[3] = hcreate_r(8, &table);
    if (observations[3] != 1) return 4;
    hdestroy_r(&table);

    if (!begin_allocation_failure()) return 5;
    errno = 0;
    created = hcreate(8);
    failure_errno = errno;
    if (!end_allocation_failure()) return 6;
    observations[4] = created;
    observations[5] = failure_errno;
    if (created != 0 || failure_errno != ENOMEM) return 7;
    if (!trace_observations("create-failure-retry", observations, 6))
        return 8;
    if (hcreate(8) != 1) return 9;
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
    int failed_errno;
    int observations[4];
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
        failed_errno = errno;
        observations[0] = result == NULL;
        observations[1] = failed_errno;
        if (!end_allocation_failure()) return 5;
#ifdef CRABC_SEARCH_HASH_TABLE_FREESTANDING
        if (!mapping_is_live(old_mapping_entry)) return 6;
#endif
        if (hsearch_r(seventh, FIND, &result, &table) != 0 || result != NULL)
            return 7;
        observations[2] = result == NULL;
        if (hsearch_r(seventh, ENTER, &result, &table) != 1 ||
            result == NULL || result->data != &values[6])
            return 8;
        observations[3] = result->data == &values[6];
        if (!trace_observations("resize-failure-retry", observations, 4))
            return 13;
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
    char equal_high_key[2] = { (char)0x80, '\0' };
    ENTRY ascii_item = { ascii_key, ascii_key };
    ENTRY high_item = { high_key, high_key };
    ENTRY equal_high_item = { equal_high_key, ascii_key };
    ENTRY *ascii_result = NULL;
    ENTRY *high_result = NULL;
    ENTRY *found = NULL;
    int observations[4];

    if (hcreate_r(512, &table) != 1)
        return 1;
    if (hsearch_r(ascii_item, ENTER, &ascii_result, &table) != 1 ||
        hsearch_r(high_item, ENTER, &high_result, &table) != 1 ||
        ascii_result == NULL || high_result == NULL)
        return 2;
    if (hsearch_r(equal_high_item, FIND, &found, &table) != 1 ||
        found != high_result || found->key != high_key ||
        found->data != high_key)
        return 3;
    observations[0] = ascii_result != high_result;
    observations[1] = high_result == found;
    observations[2] = found->key != equal_high_key;
    observations[3] = found->data == high_key;
    if (!trace_observations("high-byte-key", observations, 4)) return 4;
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
    ENTRY *lookup = NULL;
    int observations[6];
    int overflow_errno;
    unsigned releases;

    errno = 0;
    if (hcreate_r((size_t)-1, &table) != 0 || table.__tab != NULL ||
        errno != ENOMEM)
        return 1;
    overflow_errno = errno;
    hdestroy_r(&table);
    observations[0] = overflow_errno;

    reset_allocation_observation();
    if (hcreate_r(1, &table) != 1 ||
        hsearch_r(first_item, ENTER, &first_entry, &table) != 1 ||
        hcreate_r(1, &table) != 1 ||
        hsearch_r(second_item, ENTER, &second_entry, &table) != 1)
        return 2;
    observations[1] = hsearch_r(first_item, FIND, &lookup, &table);
    observations[2] = lookup == NULL;
    observations[3] = hsearch_r(second_item, FIND, &lookup, &table);
    if (observations[1] != 0 || !observations[2] ||
        observations[3] != 1 || lookup != second_entry)
        return 10;
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
    lookup = hsearch(first_item, FIND);
    observations[4] = lookup == NULL;
    lookup = hsearch(second_item, FIND);
    observations[5] = lookup == second_entry;
    if (!observations[4] || !observations[5]) return 11;
    if (!trace_observations("repeat-create", observations, 6)) return 12;
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
    result = check_collisions_and_record_ownership();
    if (result != 0) return 130 + result;
    result = check_failed_create_recovery();
    if (result != 0) return 150 + result;
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
