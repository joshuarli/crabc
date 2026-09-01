/*
 * Native Linux/x86-64 C scandir allocation-client regression.
 *
 * The same project-header fixture first runs through pinned musl 1.2.6 and
 * then through an opt-in mixed-runtime crabc candidate.  It fixes one narrow
 * contract: scandir copies accepted transient DIR records into caller-owned
 * C allocations, optionally sorts the resulting pointer array, restores
 * errno after normal enumeration, and does not publish an output list when
 * opening the directory fails.  It does not select scandirat, directory
 * walking, an allocator/runtime family, CRT/sysroot ownership, promotion, or
 * public x86 support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

enum {
    CRABC_AT_FDCWD = -100,
    CRABC_AT_REMOVEDIR = 0x200,
};

typedef int (*scandir_compare_signature)(const struct dirent **,
    const struct dirent **);
typedef int (*scandir_signature)(const char *, struct dirent ***,
    int (*)(const struct dirent *), scandir_compare_signature);

_Static_assert(sizeof(size_t) == 8 && sizeof(void *) == 8,
    "x86-64 LP64 widths");
_Static_assert(SYS_close == 3 && SYS_openat == 257 && SYS_mkdirat == 258 &&
    SYS_unlinkat == 263,
    "Linux x86-64 scandir fixture syscall numbers");
_Static_assert(CRABC_TYPE_IS(__typeof__(&scandir), scandir_signature),
    "scandir declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&alphasort), scandir_compare_signature),
    "alphasort declaration");

#ifdef CRABC_SCANDIR_CANDIDATE
extern size_t __crabc_x86_scandir_v1(void);
#endif

/*
 * The mixed-runtime runner links this fixture with --wrap for the three C
 * allocator spellings.  It deliberately distinguishes scandir's vector
 * reallocations and small copied-dirent allocations from musl opendir's
 * private DIR allocation: the candidate directory leaf is allocator-free,
 * while pinned musl's opendir is not.  Recording only the returned scandir
 * allocations gives both executions one observable rollback contract.
 */
#ifdef CRABC_SCANDIR_ALLOCATION_WRAP
enum scandir_failure_target {
    CRABC_FAIL_NOTHING,
    CRABC_FAIL_VECTOR_REALLOC,
    CRABC_FAIL_COPIED_ENTRY_MALLOC,
};

extern void *__real_malloc(size_t);
extern void *__real_realloc(void *, size_t);
extern void __real_free(void *);

static enum scandir_failure_target failure_target;
static unsigned failure_ordinal;
static unsigned realloc_calls;
static unsigned copied_entry_malloc_calls;
static unsigned tracked_release_calls;
static void *tracked_vector;
static void *tracked_entries[8];
static unsigned tracked_entry_count;

static void reset_allocation_observation(void)
{
    unsigned index;

    failure_target = CRABC_FAIL_NOTHING;
    failure_ordinal = 0;
    realloc_calls = 0;
    copied_entry_malloc_calls = 0;
    tracked_release_calls = 0;
    tracked_vector = NULL;
    for (index = 0; index < sizeof(tracked_entries) / sizeof(tracked_entries[0]);
        ++index)
        tracked_entries[index] = NULL;
    tracked_entry_count = 0;
}

static void begin_allocation_failure(enum scandir_failure_target target,
    unsigned ordinal)
{
    reset_allocation_observation();
    failure_target = target;
    failure_ordinal = ordinal;
}

static void end_allocation_failure(void)
{
    failure_target = CRABC_FAIL_NOTHING;
}

void *__wrap_realloc(void *pointer, size_t size)
{
    void *result;

    ++realloc_calls;
    if (failure_target == CRABC_FAIL_VECTOR_REALLOC &&
        realloc_calls == failure_ordinal) {
        errno = ENOMEM;
        return NULL;
    }
    result = __real_realloc(pointer, size);
    if (result != NULL) tracked_vector = result;
    return result;
}

void *__wrap_malloc(size_t size)
{
    void *result;

    /* A scandir copy is exactly one bounded public dirent record.  The raw
     * fixture makes this size classification independent of startup and
     * musl's larger private DIR allocation. */
    if (size <= sizeof(struct dirent)) {
        ++copied_entry_malloc_calls;
        if (failure_target == CRABC_FAIL_COPIED_ENTRY_MALLOC &&
            copied_entry_malloc_calls == failure_ordinal) {
            errno = ENOMEM;
            return NULL;
        }
    }
    result = __real_malloc(size);
    if (result != NULL && size <= sizeof(struct dirent) &&
        tracked_entry_count < sizeof(tracked_entries) / sizeof(tracked_entries[0]))
        tracked_entries[tracked_entry_count++] = result;
    return result;
}

void __wrap_free(void *pointer)
{
    unsigned index;

    if (pointer == tracked_vector && pointer != NULL) {
        ++tracked_release_calls;
        tracked_vector = NULL;
    }
    for (index = 0; index < tracked_entry_count; ++index) {
        if (pointer == tracked_entries[index] && pointer != NULL) {
            ++tracked_release_calls;
            tracked_entries[index] = NULL;
            break;
        }
    }
    __real_free(pointer);
}
#endif

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_failed(long result)
{
    return result < 0 && result >= -4095;
}

static int raw_create_directory(const char *path)
{
    return raw_syscall3(SYS_mkdirat, CRABC_AT_FDCWD, (long)path, 0700) == 0;
}

static int raw_create_file(const char *path)
{
    long descriptor = raw_syscall4(SYS_openat, CRABC_AT_FDCWD, (long)path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    if (raw_failed(descriptor)) return 0;
    return raw_syscall1(SYS_close, descriptor) == 0;
}

static int raw_remove(const char *path, int flags)
{
    return raw_syscall3(SYS_unlinkat, CRABC_AT_FDCWD, (long)path, flags) == 0;
}

static int strings_equal(const char *left, const char *right)
{
    size_t index = 0;

    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int select_non_dot(const struct dirent *entry)
{
    return entry->d_name[0] != '.';
}

static int select_none(const struct dirent *entry)
{
    (void)entry;
    return 0;
}

static void free_scandir_result(struct dirent **entries, int count)
{
    int index;

    for (index = 0; index < count; ++index) free(entries[index]);
    free(entries);
}

static int check_owned_sorted_result(void)
{
    static struct dirent *sentinel_entry;
    static const char *const expected[] = { "alpha", "beta", "zeta" };
    struct dirent **entries = &sentinel_entry;
    int count;
    int index;

    errno = E2BIG;
    count = scandir("scandir-directory", &entries, select_non_dot, alphasort);
    if (count != 3 || entries == NULL || errno != E2BIG) return 1;
    for (index = 0; index < count; ++index) {
        if (entries[index] == NULL || !strings_equal(entries[index]->d_name,
                expected[index])) {
            free_scandir_result(entries, count);
            return 2;
        }
    }
    if (entries[0] == entries[1] || entries[0] == entries[2] ||
        entries[1] == entries[2]) {
        free_scandir_result(entries, count);
        return 3;
    }

    /* The directory stream is already closed by scandir.  Removing its
     * contents before reading the copies catches an accidental borrowed-DIR
     * result without making pathname state part of the selected ABI. */
    if (!raw_remove("scandir-directory/alpha", 0) ||
        !raw_remove("scandir-directory/beta", 0) ||
        !raw_remove("scandir-directory/zeta", 0) ||
        !raw_remove("scandir-directory", CRABC_AT_REMOVEDIR)) {
        free_scandir_result(entries, count);
        return 4;
    }
    for (index = 0; index < count; ++index) {
        if (!strings_equal(entries[index]->d_name, expected[index])) {
            free_scandir_result(entries, count);
            return 5;
        }
    }
    errno = EDOM;
    free_scandir_result(entries, count);
    return errno == EDOM ? 0 : 6;
}

static int check_empty_result(void)
{
    static struct dirent *sentinel_entry;
    struct dirent **entries = &sentinel_entry;

    if (!raw_create_directory("scandir-empty")) return 1;
    errno = EINTR;
    if (scandir("scandir-empty", &entries, select_none, NULL) != 0 ||
        entries != NULL || errno != EINTR) {
        raw_remove("scandir-empty", CRABC_AT_REMOVEDIR);
        return 2;
    }
    return raw_remove("scandir-empty", CRABC_AT_REMOVEDIR) ? 0 : 3;
}

static int check_open_failure_does_not_publish(void)
{
    static struct dirent *sentinel_entry;
    struct dirent **entries = &sentinel_entry;

    errno = 0;
    return scandir("scandir-missing", &entries, NULL, NULL) == -1 &&
        errno == ENOENT && entries == &sentinel_entry ? 0 : 1;
}

#ifdef CRABC_SCANDIR_ALLOCATION_WRAP
static int check_allocation_failure_case(enum scandir_failure_target target,
    unsigned ordinal, unsigned expected_reallocs, unsigned expected_copies,
    unsigned expected_releases)
{
    static struct dirent *sentinel_entry;
    struct dirent **entries = &sentinel_entry;
    int result;

    begin_allocation_failure(target, ordinal);
    errno = E2BIG;
    result = scandir("scandir-allocation-failure", &entries, select_non_dot,
        NULL);
    end_allocation_failure();
    if (result != -1) return 10;
    if (errno != ENOMEM) return 11;
    if (entries != &sentinel_entry) return 12;
    if (realloc_calls != expected_reallocs) return 13;
    if (copied_entry_malloc_calls != expected_copies) return 14;
    if (tracked_release_calls != expected_releases) return 15;
    return 0;
}

static int check_allocation_failure_rollback(void)
{
    struct dirent **entries = NULL;
    int count;

    if (!raw_create_directory("scandir-allocation-failure")) return 1;
    if (!raw_create_file("scandir-allocation-failure/one") ||
        !raw_create_file("scandir-allocation-failure/two") ||
        !raw_create_file("scandir-allocation-failure/three") ||
        !raw_create_file("scandir-allocation-failure/four")) {
        raw_remove("scandir-allocation-failure/one", 0);
        raw_remove("scandir-allocation-failure/two", 0);
        raw_remove("scandir-allocation-failure/three", 0);
        raw_remove("scandir-allocation-failure/four", 0);
        raw_remove("scandir-allocation-failure", CRABC_AT_REMOVEDIR);
        return 2;
    }

    /* First vector, first copied record, then 1 -> 3 -> 7 vector growth.
     * Each case checks the unpublished-output sentinel, ENOMEM, and that the
     * tracked successful scandir allocations were released exactly once. */
    count = check_allocation_failure_case(CRABC_FAIL_VECTOR_REALLOC, 1, 1, 0, 0);
    if (count != 0) return 30 + count;
    count = check_allocation_failure_case(CRABC_FAIL_COPIED_ENTRY_MALLOC, 1, 1, 1, 1);
    if (count != 0) return 50 + count;
    count = check_allocation_failure_case(CRABC_FAIL_VECTOR_REALLOC, 3, 3, 3, 4);
    if (count != 0) return 70 + count;

    /* Failure injection must not leave this leaf with retained scan state. */
    reset_allocation_observation();
    errno = EINTR;
    count = scandir("scandir-allocation-failure", &entries, select_non_dot,
        NULL);
    if (count != 4 || entries == NULL || errno != EINTR) {
        free_scandir_result(entries, count > 0 ? count : 0);
        return 6;
    }
    free_scandir_result(entries, count);
    return raw_remove("scandir-allocation-failure/one", 0) &&
        raw_remove("scandir-allocation-failure/two", 0) &&
        raw_remove("scandir-allocation-failure/three", 0) &&
        raw_remove("scandir-allocation-failure/four", 0) &&
        raw_remove("scandir-allocation-failure", CRABC_AT_REMOVEDIR) ? 0 : 7;
}
#endif

int crabc_x86_64_scandir_probe(void)
{
#ifdef CRABC_SCANDIR_ALLOCATION_WRAP
    int allocation_failure_status;
#endif
#ifdef CRABC_SCANDIR_CANDIDATE
    if (__crabc_x86_scandir_v1() != 1) return 100;
#endif
    if (!raw_create_directory("scandir-directory")) return 1;
    if (!raw_create_file("scandir-directory/zeta") ||
        !raw_create_file("scandir-directory/alpha") ||
        !raw_create_file("scandir-directory/beta")) {
        raw_remove("scandir-directory/zeta", 0);
        raw_remove("scandir-directory/alpha", 0);
        raw_remove("scandir-directory/beta", 0);
        raw_remove("scandir-directory", CRABC_AT_REMOVEDIR);
        return 2;
    }
    if (check_owned_sorted_result() != 0) return 3;
    if (check_empty_result() != 0) return 4;
    if (check_open_failure_does_not_publish() != 0) return 5;
#ifdef CRABC_SCANDIR_ALLOCATION_WRAP
    allocation_failure_status = check_allocation_failure_rollback();
    if (allocation_failure_status != 0) return 60 + allocation_failure_status;
#endif
    return 0;
}

int main(void)
{
    return crabc_x86_64_scandir_probe();
}
