/* Static x86-64 lfind/lsearch C ABI and pinned-musl behavioral fixture.
 *
 * One fixture executes unchanged through pinned musl and the selected true
 * static archive. It proves first-match lookup, an existing lsearch hit,
 * miss-copy/count semantics, a non-int record stride, and zero-count callback
 * suppression without selecting a container or allocation boundary.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <search.h>

typedef int (*linear_search_compare_signature)(const void *, const void *);
typedef void *(*lfind_signature)(
    const void *, const void *, size_t *, size_t, linear_search_compare_signature);
typedef void *(*lsearch_signature)(
    const void *, void *, size_t *, size_t, linear_search_compare_signature);

_Static_assert(sizeof(size_t) == 8 && sizeof(void *) == 8,
    "x86 LP64 size_t and pointer widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lfind),
    lfind_signature), "lfind declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lsearch),
    lsearch_signature), "lsearch declaration");

struct record {
    int key;
    unsigned char payload[37];
    int serial;
};

_Static_assert(sizeof(struct record) > sizeof(int),
    "linear search must retain a non-int record stride");

static int comparison_calls;
static int zero_count_calls;
static size_t *observed_count;
static size_t expected_count;
static int observed_count_mutated;

static void begin_count_observation(size_t *count)
{
    comparison_calls = 0;
    observed_count = count;
    expected_count = *count;
    observed_count_mutated = 0;
}

static int compare_int(const void *left, const void *right)
{
    const int a = *(const int *)left;
    const int b = *(const int *)right;

    if (*observed_count != expected_count)
        observed_count_mutated = 1;
    comparison_calls += 1;
    return (a > b) - (a < b);
}

static int compare_record(const void *left, const void *right)
{
    const struct record *a = left;
    const struct record *b = right;

    if (*observed_count != expected_count)
        observed_count_mutated = 1;
    comparison_calls += 1;
    return (a->key > b->key) - (a->key < b->key);
}

static int compare_zero_count(const void *left, const void *right)
{
    const int a = *(const int *)left;
    const int b = *(const int *)right;

    zero_count_calls += 1;
    return (a > b) - (a < b);
}

static int check_lfind(void)
{
    static const int records[] = { 4, -1, 4, 9 };
    const lfind_signature function = lfind;
    const int duplicate = 4;
    const int missing = 7;
    size_t count = 4;
    int *found;

    begin_count_observation(&count);
    found = function(&duplicate, records, &count, sizeof(records[0]),
                     compare_int);
    if (found != records || count != 4 || comparison_calls == 0 ||
        observed_count_mutated)
        return 1;

    begin_count_observation(&count);
    if (lfind(&missing, records, &count, sizeof(records[0]), compare_int) !=
        NULL)
        return 2;
    if (count != 4 || comparison_calls != 4 || observed_count_mutated)
        return 3;
    return 0;
}

static int check_lsearch(void)
{
    struct record records[4] = {
        { 5, { 0x11, 0x12 }, 1 },
        { -3, { 0x21, 0x22 }, 2 },
        { 5, { 0x31, 0x32 }, 3 },
        { 99, { 0x41, 0x42 }, 4 },
    };
    const struct record existing = { 5, { 0 }, 0 };
    const struct record inserted = { -8, { 0xa1, 0xa2, 0xa3, 0xa4 }, 91 };
    const lsearch_signature function = lsearch;
    size_t count = 3;
    struct record *found;

    begin_count_observation(&count);
    found = function(&existing, records, &count, sizeof(records[0]),
                     compare_record);
    if (found != records || count != 3 || comparison_calls != 1 ||
        observed_count_mutated)
        return 1;
    if (found->serial != 1 || found->payload[0] != 0x11)
        return 2;

    begin_count_observation(&count);
    found = lsearch(&inserted, records, &count, sizeof(records[0]),
                    compare_record);
    if (found != records + 3 || count != 4 || comparison_calls != 3 ||
        observed_count_mutated)
        return 3;
    if (found->key != -8 || found->serial != 91 ||
        found->payload[0] != 0xa1 || found->payload[3] != 0xa4 ||
        found->payload[36] != 0)
        return 4;
    return 0;
}

static int check_zero_count(void)
{
    int records[1] = { 91 };
    const int key = -2;
    size_t count = 0;
    int *found;

    zero_count_calls = 0;
    if (lfind(&key, records, &count, sizeof(records[0]),
              compare_zero_count) != NULL)
        return 1;
    if (count != 0 || zero_count_calls != 0)
        return 2;

    zero_count_calls = 0;
    found = lsearch(&key, records, &count, sizeof(records[0]),
                    compare_zero_count);
    if (found != records || count != 1 || records[0] != -2)
        return 3;
    return zero_count_calls == 0 ? 0 : 4;
}

int crabc_x86_64_linear_search_probe(void)
{
    int result = check_lfind();

    if (result != 0)
        return result;
    result = check_lsearch();
    if (result != 0)
        return 10 + result;
    result = check_zero_count();
    return result == 0 ? 0 : 20 + result;
}

#ifndef CRABC_LINEAR_SEARCH_FREESTANDING
int main(void)
{
    return crabc_x86_64_linear_search_probe();
}
#endif
