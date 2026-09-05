/* Native execution witness for the private owned TRE source port.
 *
 * The same semantic suite runs against pinned musl and the copied, privately
 * routed static archive.  The freestanding candidate also records each C-ABI
 * allocation so both regcomp's persistent graph and regexec's temporary
 * parallel/backtracking state must be released on normal and REG_ESPACE paths.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native little-endian Linux/x86-64 LP64"
#endif

#include <limits.h>
#include <locale.h>
#include <regex.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static int execute(const char *pattern, int cflags, const char *text,
    size_t nmatch, const regmatch_t *expected)
{
    regex_t expression;
    regmatch_t actual[4];
    size_t index;
    int result = regcomp(&expression, pattern, cflags);
    if (result != 0) return 1;
    result = regexec(&expression, text, nmatch, actual, 0);
    if (result != 0) {
        regfree(&expression);
        return 2 + result;
    }
    for (index = 0; index < nmatch; index++)
        if (actual[index].rm_so != expected[index].rm_so ||
            actual[index].rm_eo != expected[index].rm_eo) {
            regfree(&expression);
            return 32 + (int)index;
        }
    regfree(&expression);
    return 0;
}

static int expect_no_match(const char *pattern, int cflags, const char *text,
    int eflags)
{
    regex_t expression;
    int result = regcomp(&expression, pattern, cflags);
    if (result != 0) return 1;
    result = regexec(&expression, text, 0, 0, eflags);
    regfree(&expression);
    return result == REG_NOMATCH ? 0 : 2 + result;
}

/* Isolate the table terminator source regression from matching work.  musl's
 * `"\0Unknown error"` has an implicit final literal NUL; the Rust table must
 * retain both the empty separator and that final terminator. */
static int check_unknown_error_terminator(void)
{
    char unknown[14];
    char bounded_unknown[1];
    if (regerror(-1, 0, unknown, sizeof unknown) != 14) return 1;
    if (unknown[0] != 'U' || unknown[12] != 'r' || unknown[13]) return 2;
    if (regerror(INT_MAX, 0, bounded_unknown, sizeof bounded_unknown) != 14) return 3;
    if (bounded_unknown[0]) return 4;
    return 0;
}

static int check_error_table(void)
{
    char whole[64];
    char small[4];
    if (regerror(REG_EBRACK, 0, whole, sizeof whole) != 12) return 1;
    if (whole[0] != 'M' || whole[9] != ']' || whole[10] != '\'' || whole[11]) return 2;
    if (regerror(REG_EBRACK, 0, small, sizeof small) != 12) return 3;
    if (small[0] != 'M' || small[1] != 'i' || small[2] != 's' || small[3]) return 4;
    if (check_unknown_error_terminator()) return 5;
    return 0;
}

/* Keep zero-length backreference progress separate from the aggregate
 * semantic suite so a timeout identifies the source retry/visited-state edge
 * directly, rather than a later unrelated check. */
static int check_empty_backreference(void)
{
    static const regmatch_t expected[] = {{0, 0}, {0, 0}};
    return execute("\\(a*\\)\\1", 0, "", 2, expected);
}

static int semantic_suite(void)
{
    static const regmatch_t longest[] = {{1, 3}};
    static const regmatch_t alternation[] = {{1, 3}, {2, 3}};
    static const regmatch_t anchored[] = {{0, 1}};
    static const regmatch_t alpha[] = {{0, 2}};
    static const regmatch_t negated[] = {{2, 4}};
    static const regmatch_t icase[] = {{0, 1}};
    static const regmatch_t backref[] = {{1, 3}, {1, 2}};
    static const regmatch_t multibyte[] = {{1, 5}};
    int result;

    if ((result = execute("a|ab", REG_EXTENDED, "zab", 1, longest))) return 10 + result;
    if ((result = execute("(a|b)+", REG_EXTENDED, "zab", 2, alternation))) return 50 + result;
    if ((result = execute("^a$", REG_EXTENDED | REG_NEWLINE, "a\nx", 1, anchored))) return 90 + result;
    if ((result = execute("[[:alpha:]]+", REG_EXTENDED, "ab9", 1, alpha))) return 130 + result;
    if ((result = execute("[^[:digit:]]+", REG_EXTENDED, "10xy2", 1, negated))) return 170 + result;
    if ((result = execute("[a]", REG_EXTENDED | REG_ICASE, "A", 1, icase))) return 210 + result;
    if ((result = execute("\\(a\\)\\1", 0, "zaa", 2, backref))) return 250 + result;
    if ((result = check_empty_backreference())) return 290 + result;
    if ((result = execute("é+", REG_EXTENDED, "zééx", 1, multibyte))) return 330 + result;
    if ((result = expect_no_match("^a$", REG_EXTENDED, "a\nx", 0))) return 370 + result;
    if ((result = expect_no_match("^a", REG_EXTENDED, "a", REG_NOTBOL))) return 390 + result;
    if ((result = expect_no_match("a$", REG_EXTENDED, "a", REG_NOTEOL))) return 410 + result;
    if ((result = check_error_table())) return 430 + result;
    return 0;
}

#ifdef CRABC_OWNED_REGEX_EXECUTION_FREESTANDING

enum { HEAP_BYTES = 1 << 20, RECORD_CAPACITY = 4096 };

union test_heap {
    max_align_t maximum_alignment;
    unsigned char bytes[HEAP_BYTES];
};

struct allocation_record {
    void *pointer;
    size_t size;
    int live;
};

static union test_heap heap;
static size_t cursor;
static int allocation_budget;
static size_t allocation_successes;
static size_t allocation_releases;
static size_t record_count;
static int allocation_violation;
static struct allocation_record records[RECORD_CAPACITY];

static size_t aligned(size_t value)
{
    const size_t alignment = _Alignof(max_align_t);
    return (value + alignment - 1) & ~(alignment - 1);
}

static void reset_allocator(int budget)
{
    cursor = 0;
    allocation_budget = budget;
    allocation_successes = 0;
    allocation_releases = 0;
    record_count = 0;
    allocation_violation = 0;
}

static struct allocation_record *find_record(void *pointer)
{
    size_t index;
    for (index = 0; index < record_count; index++)
        if (records[index].pointer == pointer) return &records[index];
    return 0;
}

static int all_released(void)
{
    size_t index;
    if (allocation_violation || allocation_successes != allocation_releases ||
        allocation_successes != record_count) return 0;
    for (index = 0; index < record_count; index++)
        if (records[index].live) return 0;
    return 1;
}

void *malloc(size_t size)
{
    size_t begin, end;
    void *pointer;
    if (allocation_budget == 0) return 0;
    if (allocation_budget > 0) allocation_budget--;
    if (record_count == RECORD_CAPACITY) return 0;
    if (!size) size = 1;
    begin = aligned(cursor);
    if (begin > HEAP_BYTES || size > HEAP_BYTES - begin) return 0;
    pointer = heap.bytes + begin;
    if ((uintptr_t)pointer % _Alignof(max_align_t)) {
        allocation_violation = 1;
        return 0;
    }
    end = begin + size;
    cursor = aligned(end);
    records[record_count].pointer = pointer;
    records[record_count].size = size;
    records[record_count].live = 1;
    record_count++;
    allocation_successes++;
    return pointer;
}

void free(void *pointer)
{
    struct allocation_record *record;
    if (!pointer) return;
    record = find_record(pointer);
    if (!record || !record->live) {
        allocation_violation = 1;
        return;
    }
    record->live = 0;
    allocation_releases++;
}

void *calloc(size_t count, size_t size)
{
    size_t bytes, index;
    unsigned char *pointer;
    if (count && size > (size_t)-1 / count) return 0;
    bytes = count * size;
    pointer = malloc(bytes);
    if (!pointer) return 0;
    for (index = 0; index < bytes; index++) pointer[index] = 0;
    return pointer;
}

void *realloc(void *pointer, size_t size)
{
    struct allocation_record *record;
    unsigned char *replacement;
    size_t copied, index;
    if (!pointer) return malloc(size);
    record = find_record(pointer);
    if (!record || !record->live) {
        allocation_violation = 1;
        return 0;
    }
    replacement = malloc(size);
    if (!replacement) return 0;
    copied = record->size < size ? record->size : size;
    for (index = 0; index < copied; index++) replacement[index] = ((unsigned char *)pointer)[index];
    free(pointer);
    return replacement;
}

static int execution_allocation_case(const char *pattern, int cflags, const char *text)
{
    regex_t expression;
    regmatch_t matches[2];
    size_t before, execution_allocations;
    int budget, result;

    reset_allocator(-1);
    if (regcomp(&expression, pattern, cflags)) return 1;
    before = allocation_successes;
    if (regexec(&expression, text, 2, matches, 0)) {
        regfree(&expression);
        return 2;
    }
    execution_allocations = allocation_successes - before;
    regfree(&expression);
    if (!execution_allocations || !all_released()) return 3;

    for (budget = 0; budget < (int)execution_allocations; budget++) {
        reset_allocator(-1);
        if (regcomp(&expression, pattern, cflags)) return 10 + budget;
        allocation_budget = budget;
        result = regexec(&expression, text, 2, matches, 0);
        regfree(&expression);
        if (result != REG_ESPACE || !all_released()) return 100 + budget;
    }
    return 0;
}

int crabc_x86_64_owned_regex_execution_probe(void)
{
    int result;
    /* Locale setup may initialize process-wide locale state before the exact
     * allocation ledger starts; the regex calls below are the measured edge. */
    if (!setlocale(LC_CTYPE, "C.UTF-8")) return 1;
#if defined(CRABC_OWNED_REGEX_EMPTY_BACKREFERENCE_ONLY)
    reset_allocator(-1);
    result = check_empty_backreference();
    return result ? result : !all_released();
#elif defined(CRABC_OWNED_REGEX_REGERROR_TABLE_ONLY)
    return check_unknown_error_terminator();
#else
    reset_allocator(-1);
    result = semantic_suite();
    if (result || !all_released()) return result ? result : 2;
    if ((result = execution_allocation_case("([a-z]|[[:digit:]])+", REG_EXTENDED, "a9b"))) return 20 + result;
    if ((result = execution_allocation_case("\\(a\\)\\1", 0, "aa"))) return 200 + result;
    return 0;
#endif
}

#else

int main(int argc, char *argv[])
{
    if (!setlocale(LC_CTYPE, "C.UTF-8")) return 1;
    if (argc == 2 && !strcmp(argv[1], "--empty-backreference"))
        return check_empty_backreference();
    if (argc == 2 && !strcmp(argv[1], "--regerror-table"))
        return check_unknown_error_terminator();
    if (argc != 1) return 64;
    return semantic_suite();
}

#endif
