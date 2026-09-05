/* Native compiler-only witness for the in-progress owned TRE port.
 *
 * It deliberately names only regcomp/regfree.  `regexec` and `regerror` are
 * not part of this checkpoint, so this is not a POSIX regex runtime probe or
 * a replacement for the selected bounded `libc-regex` gate.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <regex.h>
#include <stddef.h>
#include <stdint.h>

static int compile_and_release(const char *pattern, int flags, size_t nsub)
{
    regex_t expression;
    int result = regcomp(&expression, pattern, flags);
    if (result != 0) return 1;
    if (expression.re_nsub != nsub) {
        regfree(&expression);
        return 2;
    }
    regfree(&expression);
    return 0;
}

static int expect_compile_result(const char *pattern, int flags, int expected)
{
    regex_t expression;
    int result = regcomp(&expression, pattern, flags);
    if (result == 0) regfree(&expression);
    return result == expected ? 0 : 1;
}

static int check_compiler_semantics(void)
{
    if (compile_and_release("a{1,3}", REG_EXTENDED, 0)) return 1;
    if (compile_and_release("\\(a\\)", 0, 1)) return 2;
    if (compile_and_release("(a|b){2}", REG_EXTENDED, 1)) return 3;
    if (compile_and_release("\\(a\\)\\1", 0, 1)) return 4;
    if (compile_and_release("([[:alpha:]]|é){2,}", REG_EXTENDED | REG_ICASE, 1)) return 5;

    if (expect_compile_result("[", REG_EXTENDED, REG_EBRACK)) return 6;
    if (expect_compile_result("a{3,1}", REG_EXTENDED, REG_BADBR)) return 7;
    if (expect_compile_result("\\1", 0, REG_ESUBREG)) return 8;
    if (expect_compile_result("(a", REG_EXTENDED, REG_EPAREN)) return 9;
    return 0;
}

#ifdef CRABC_OWNED_REGEX_COMPILER_FREESTANDING

/* The candidate fixture interposes its allocation provider.  The compiler's
 * opaque C-ABI allocation tails must arrive here, rather than being folded to
 * the crate's private allocator.  This intentionally simple monotonic heap
 * exercises only this finite compiler fixture. It retains exact allocation
 * identities, so a foreign or duplicate release cannot hide behind a matching
 * allocation/free count. */
enum { HEAP_BYTES = 1 << 20, ALLOCATION_RECORD_CAPACITY = 4096 };

union test_heap {
    long double maximum_alignment;
    unsigned char bytes[HEAP_BYTES];
};

struct allocation_record {
    void *pointer;
    size_t size;
    int live;
};

static union test_heap heap;
static size_t heap_cursor;
static int allocation_budget;
static size_t allocation_successes;
static size_t allocation_releases;
static size_t allocation_record_count;
static int allocation_violation;
static struct allocation_record allocation_records[ALLOCATION_RECORD_CAPACITY];

static size_t align_up(size_t value)
{
    const size_t alignment = _Alignof(max_align_t);
    return (value + alignment - 1) & ~(alignment - 1);
}

static void reset_allocator(int budget)
{
    heap_cursor = 0;
    allocation_budget = budget;
    allocation_successes = 0;
    allocation_releases = 0;
    allocation_record_count = 0;
    allocation_violation = 0;
}

static struct allocation_record *find_allocation(void *pointer)
{
    size_t index;
    for (index = 0; index < allocation_record_count; index++)
        if (allocation_records[index].pointer == pointer)
            return &allocation_records[index];
    return 0;
}

static int all_allocations_released(void)
{
    size_t index;
    if (allocation_violation || allocation_successes != allocation_releases ||
        allocation_successes != allocation_record_count)
        return 0;
    for (index = 0; index < allocation_record_count; index++)
        if (allocation_records[index].live)
            return 0;
    return 1;
}

void *malloc(size_t size)
{
    size_t begin;
    size_t end;
    void *pointer;
    if (allocation_budget == 0) return 0;
    if (allocation_budget > 0) allocation_budget--;
    if (allocation_record_count == ALLOCATION_RECORD_CAPACITY) {
        allocation_violation = 1;
        return 0;
    }
    if (size == 0) size = 1;
    begin = align_up(heap_cursor);
    if (begin > HEAP_BYTES || size > HEAP_BYTES - begin)
        return 0;
    pointer = heap.bytes + begin;
    if ((uintptr_t)pointer % _Alignof(max_align_t) != 0) {
        allocation_violation = 1;
        return 0;
    }
    end = begin + size;
    heap_cursor = align_up(end);
    allocation_records[allocation_record_count].pointer = pointer;
    allocation_records[allocation_record_count].size = size;
    allocation_records[allocation_record_count].live = 1;
    allocation_record_count++;
    allocation_successes++;
    return pointer;
}

void free(void *pointer)
{
    struct allocation_record *record;
    if (pointer == 0) return;
    record = find_allocation(pointer);
    if (record == 0 || !record->live) {
        allocation_violation = 1;
        return;
    }
    record->live = 0;
    allocation_releases++;
}

void *calloc(size_t count, size_t size)
{
    unsigned char *result;
    size_t bytes;
    size_t index;
    if (count != 0 && size > (size_t)-1 / count) return 0;
    bytes = count * size;
    result = malloc(bytes);
    if (result == 0) return 0;
    for (index = 0; index < bytes; index++) result[index] = 0;
    return result;
}

void *realloc(void *pointer, size_t size)
{
    struct allocation_record *old_record;
    unsigned char *replacement;
    size_t copied;
    size_t index;
    if (pointer == 0) return malloc(size);
    old_record = find_allocation(pointer);
    if (old_record == 0 || !old_record->live) {
        allocation_violation = 1;
        return 0;
    }
    replacement = malloc(size);
    if (replacement == 0) return 0;
    copied = old_record->size < size ? old_record->size : size;
    for (index = 0; index < copied; index++)
        replacement[index] = ((unsigned char *)pointer)[index];
    free(pointer);
    return replacement;
}

static int allocation_edge_is_released(const char *pattern, int flags, int expected)
{
    regex_t expression;
    int result = regcomp(&expression, pattern, flags);
    if (result == 0) regfree(&expression);
    if (result != expected) return 1;
    return all_allocations_released() ? 0 : 2;
}

static int check_allocator_identity_rejection(void)
{
    unsigned char foreign = 0;
    void *pointer;

    reset_allocator(-1);
    pointer = malloc(1);
    if (pointer == 0) return 1;
    free(pointer);
    free(pointer);
    if (!allocation_violation) return 2;

    reset_allocator(-1);
    free(&foreign);
    if (!allocation_violation) return 3;

    reset_allocator(-1);
    pointer = malloc(1);
    if (pointer == 0) return 4;
    free(pointer);
    if (realloc(pointer, 2) != 0 || !allocation_violation) return 5;
    return 0;
}

struct compiler_allocation_case {
    const char *pattern;
    int flags;
    int expected;
};

/* Measure the ordinary source path, then fail each allocation position in
 * turn. This covers the fixture's nested-group/tag-copy expansion, BRE
 * backreference, negated named-class, and syntax-error paths. It does not
 * claim exhaustive allocation coverage for every valid regex grammar shape. */
static int check_allocation_case(const struct compiler_allocation_case *test)
{
    size_t baseline;
    int budget;

    reset_allocator(-1);
    if (allocation_edge_is_released(test->pattern, test->flags, test->expected))
        return 1;
    baseline = allocation_successes;
    if (baseline > (size_t)INT32_MAX) return 2;

    for (budget = 0; budget <= (int)baseline; budget++) {
        regex_t expression;
        int result;
        reset_allocator(budget);
        result = regcomp(&expression, test->pattern, test->flags);
        if (result == 0) regfree(&expression);
        if (budget == (int)baseline) {
            if (result != test->expected || allocation_successes != baseline)
                return 10 + budget;
        } else if (result != REG_ESPACE) {
            return 100 + budget;
        }
        if (!all_allocations_released()) return 200 + budget;
    }
    return 0;
}

static int check_failure_cleanup(void)
{
    static const struct compiler_allocation_case cases[] = {
        { "(a|b){2,3}", REG_EXTENDED, 0 },
        { "\\(a\\)\\1", 0, 0 },
        { "[^[:digit:]x]+", REG_EXTENDED | REG_NEWLINE, 0 },
        { "[", REG_EXTENDED, REG_EBRACK },
    };
    size_t index;
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++)
        if (check_allocation_case(&cases[index]))
            return (int)index + 1;
    return 0;
}

int crabc_x86_64_owned_regex_compiler_probe(void)
{
    int result;
    result = check_allocator_identity_rejection();
    if (result != 0) return result;
    reset_allocator(-1);
    result = check_compiler_semantics();
    if (result != 0) return result;
    return check_failure_cleanup();
}

#else

int main(void)
{
    return check_compiler_semantics();
}

#endif
