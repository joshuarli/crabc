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
 * is enough for the bounded fixture and records every ownership edge; free is
 * a counter because the test resets the whole backing store between cases. */
enum { HEAP_BYTES = 1 << 20 };

union test_heap {
    long double maximum_alignment;
    unsigned char bytes[HEAP_BYTES];
};

struct allocation_header {
    size_t size;
};

static union test_heap heap;
static size_t heap_cursor;
static int allocation_budget;
static size_t allocation_successes;
static size_t allocation_releases;

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
}

void *malloc(size_t size)
{
    size_t begin;
    size_t end;
    struct allocation_header *header;
    if (allocation_budget == 0) return 0;
    if (allocation_budget > 0) allocation_budget--;
    if (size == 0) size = 1;
    begin = align_up(heap_cursor);
    if (begin > HEAP_BYTES - sizeof(*header) ||
        size > HEAP_BYTES - begin - sizeof(*header))
        return 0;
    header = (struct allocation_header *)(void *)(heap.bytes + begin);
    header->size = size;
    end = begin + sizeof(*header) + size;
    heap_cursor = align_up(end);
    allocation_successes++;
    return header + 1;
}

void free(void *pointer)
{
    if (pointer != 0) allocation_releases++;
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
    struct allocation_header *old_header;
    unsigned char *replacement;
    size_t copied;
    size_t index;
    if (pointer == 0) return malloc(size);
    old_header = (struct allocation_header *)pointer - 1;
    replacement = malloc(size);
    if (replacement == 0) return 0;
    copied = old_header->size < size ? old_header->size : size;
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
    return allocation_successes == allocation_releases ? 0 : 2;
}

/* Force both syntax-error cleanup and each source allocation-failure exit.
 * The fixed probe never grows TRE's 512-entry stack or its 32-literal array,
 * but the interposed realloc remains complete if this input evolves. */
static int check_failure_cleanup(void)
{
    int budget;
    reset_allocator(-1);
    if (allocation_edge_is_released("[", REG_EXTENDED, REG_EBRACK)) return 1;
    for (budget = 0; budget < 48; budget++) {
        regex_t expression;
        int result;
        reset_allocator(budget);
        result = regcomp(&expression, "(a|b){2}", REG_EXTENDED);
        if (result == 0) regfree(&expression);
        if (result != 0 && result != REG_ESPACE) return 10 + budget;
        if (allocation_successes != allocation_releases) return 70 + budget;
    }
    return 0;
}

int crabc_x86_64_owned_regex_compiler_probe(void)
{
    int result;
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
