/* Static x86-64 bsearch C ABI and behavioral differential fixture.
 *
 * The duplicate-key case pins musl's midpoint equality return, while the
 * zero-count case proves that no callback is evaluated before the loop.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdlib.h>

typedef int (*bsearch_compare_signature)(const void *, const void *);
typedef void *(*bsearch_signature)(
    const void *, const void *, size_t, size_t, bsearch_compare_signature);

_Static_assert(sizeof(size_t) == 8 && sizeof(void *) == 8,
    "x86 LP64 size_t and pointer widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&bsearch),
    bsearch_signature), "bsearch declaration");

struct record {
    int key;
    unsigned char payload[37];
    int serial;
};

static int comparison_calls;
static int zero_count_calls;

static int compare_int(const void *left, const void *right)
{
    const int a = *(const int *)left;
    const int b = *(const int *)right;

    comparison_calls += 1;
    return (a > b) - (a < b);
}

static int compare_int_zero_count(const void *left, const void *right)
{
    const int a = *(const int *)left;
    const int b = *(const int *)right;

    zero_count_calls += 1;
    return (a > b) - (a < b);
}

static int compare_record(const void *left, const void *right)
{
    const struct record *a = left;
    const struct record *b = right;

    comparison_calls += 1;
    return (a->key > b->key) - (a->key < b->key);
}

static int check_integer_search(void)
{
    static const int sorted[] = { -9, -3, 0, 2, 7, 12, 19 };
    static const int duplicates[] = { -2, 3, 3, 3, 8 };
    const bsearch_signature function = bsearch;
    const int first = -9;
    const int last = 19;
    const int duplicate = 3;
    const int missing = 4;
    const int *found;

    comparison_calls = 0;
    found = function(&first, sorted, 7, sizeof(sorted[0]), compare_int);
    if (found != sorted || comparison_calls == 0)
        return 1;
    found = bsearch(&last, sorted, 7, sizeof(sorted[0]), compare_int);
    if (found != sorted + 6)
        return 2;
    found = bsearch(&duplicate, duplicates, 5, sizeof(duplicates[0]),
                    compare_int);
    if (found != duplicates + 2)
        return 3;
    if (bsearch(&missing, sorted, 7, sizeof(sorted[0]), compare_int) != NULL)
        return 4;
    return 0;
}

static int check_record_search(void)
{
    static const struct record sorted[] = {
        { -5, { 0x11 }, 1 }, { 0, { 0x22 }, 2 },
        { 8, { 0x33 }, 3 }, { 12, { 0x44 }, 4 },
    };
    const struct record key = { 8, { 0 }, 0 };
    const struct record *found;

    comparison_calls = 0;
    found = bsearch(&key, sorted, 4, sizeof(sorted[0]), compare_record);
    if (found != sorted + 2 || comparison_calls == 0)
        return 1;
    if (found->serial != 3 || found->payload[0] != 0x33)
        return 2;
    return 0;
}

static int check_zero_count(void)
{
    static const int sorted[] = { 1 };
    const int key = 1;

    zero_count_calls = 0;
    if (bsearch(&key, sorted, 0, sizeof(sorted[0]),
                compare_int_zero_count) != NULL)
        return 1;
    return zero_count_calls == 0 ? 0 : 2;
}

int crabc_x86_64_bsearch_probe(void)
{
    int result = check_integer_search();

    if (result != 0)
        return result;
    result = check_record_search();
    if (result != 0)
        return 10 + result;
    result = check_zero_count();
    return result == 0 ? 0 : 20 + result;
}

#ifndef CRABC_BSEARCH_FREESTANDING
int main(void)
{
    return crabc_x86_64_bsearch_probe();
}
#endif
