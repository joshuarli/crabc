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

static int callback_algorithms_case(void)
{
    int result;

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
