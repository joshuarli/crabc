/* Static x86-64 qsort C ABI and pinned-musl behavioral differential fixture.
 *
 * One fixture executes unchanged through pinned musl and the selected true
 * static archive. It covers direct/function-pointer calls, duplicate keys,
 * a record width larger than musl's 256-byte cycling buffer, and zero-count
 * callback suppression without asserting a portable stability guarantee.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdlib.h>

typedef int (*qsort_compare_signature)(const void *, const void *);
typedef void (*qsort_signature)(void *, size_t, size_t,
                                qsort_compare_signature);

_Static_assert(sizeof(size_t) == 8 && sizeof(void *) == 8,
    "x86 LP64 size_t and pointer widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&qsort),
    qsort_signature), "qsort declaration");

struct record {
    int key;
    int serial;
};

struct wide_record {
    int key;
    unsigned char payload[300];
    int serial;
};

_Static_assert(sizeof(struct wide_record) == 308,
    "wide qsort record crosses musl's 256-byte cycling buffer");

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

static int compare_wide_record(const void *left, const void *right)
{
    const struct wide_record *a = left;
    const struct wide_record *b = right;

    comparison_calls += 1;
    return (a->key > b->key) - (a->key < b->key);
}

static int check_integer_sort(void)
{
    int values[] = { 7, -3, 7, 1, 0, -3, 99, 2, -11 };
    static const int expected[] = { -11, -3, -3, 0, 1, 2, 7, 7, 99 };
    const qsort_signature function = qsort;
    size_t index;

    comparison_calls = 0;
    function(values, 9, sizeof(values[0]), compare_int);
    if (comparison_calls == 0)
        return 1;
    for (index = 0; index < 9; ++index) {
        if (values[index] != expected[index])
            return 2;
    }
    return 0;
}

static int check_record_sort(void)
{
    static const int keys[] = { 4, 1, 4, -1, 1, 0, -1, 9 };
    struct record records[] = {
        { 4, 0 }, { 1, 1 }, { 4, 2 }, { -1, 3 },
        { 1, 4 }, { 0, 5 }, { -1, 6 }, { 9, 7 },
    };
    size_t index;
    unsigned seen = 0;

    comparison_calls = 0;
    qsort(records, 8, sizeof(records[0]), compare_record);
    if (comparison_calls == 0)
        return 1;
    for (index = 1; index < 8; ++index) {
        if (records[index - 1].key > records[index].key)
            return 2;
    }
    for (index = 0; index < 8; ++index) {
        if (records[index].serial < 0 || records[index].serial >= 8)
            return 3;
        if (records[index].key != keys[records[index].serial])
            return 4;
        seen |= 1u << records[index].serial;
    }
    return seen == 0xffu ? 0 : 5;
}

static int check_wide_record_sort(void)
{
    static const int keys[] = { 9, -1, 4, 4, 0, 12, -7 };
    struct wide_record records[7];
    size_t index;
    size_t byte;
    unsigned seen = 0;

    for (index = 0; index < 7; ++index) {
        records[index].key = keys[index];
        records[index].serial = (int)index;
        for (byte = 0; byte < sizeof(records[index].payload); ++byte)
            records[index].payload[byte] = (unsigned char)(index + byte);
    }

    comparison_calls = 0;
    qsort(records, 7, sizeof(records[0]), compare_wide_record);
    if (comparison_calls == 0)
        return 1;
    for (index = 1; index < 7; ++index) {
        if (records[index - 1].key > records[index].key)
            return 2;
    }
    for (index = 0; index < 7; ++index) {
        unsigned serial = (unsigned)records[index].serial;

        if (serial >= 7 || records[index].key != keys[serial])
            return 3;
        seen |= 1u << serial;
        for (byte = 0; byte < sizeof(records[index].payload); ++byte) {
            if (records[index].payload[byte] !=
                (unsigned char)(serial + byte))
                return 4;
        }
    }
    return seen == 0x7fu ? 0 : 5;
}

static int check_zero_count(void)
{
    int sentinel = 11;

    zero_count_calls = 0;
    qsort(&sentinel, 0, sizeof(sentinel), compare_int_zero_count);
    if (sentinel != 11)
        return 1;
    return zero_count_calls == 0 ? 0 : 2;
}

int crabc_x86_64_qsort_probe(void)
{
    int result = check_integer_sort();

    if (result != 0)
        return result;
    result = check_record_sort();
    if (result != 0)
        return 10 + result;
    result = check_wide_record_sort();
    if (result != 0)
        return 20 + result;
    result = check_zero_count();
    return result == 0 ? 0 : 30 + result;
}

#ifndef CRABC_QSORT_FREESTANDING
int main(void)
{
    return crabc_x86_64_qsort_probe();
}
#endif
