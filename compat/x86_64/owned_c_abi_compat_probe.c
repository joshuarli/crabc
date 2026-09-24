// Installed-product behavior for the selected libc.c-abi-compat capabilities
// that previously had only private selected-archive evidence: callback-tree,
// hash-table and intrusive-queue search, the qsort context helper, bounded
// gettext state, diagnostic strings and legacy observations, and the C
// malloc-family policy boundary. One object runs through pinned musl 1.2.6
// and every owned product mode; each compared scenario prints only facts that
// musl defines, never pointer values, allocator placement, or host totals.
//
// The termination scenarios end the process through the selected exit,
// quick-exit, immediate-exit, err(3), and assertion entries; the runner
// requires each one's status, stdout, and stderr to equal musl's.
//
// The `profile` scenario is candidate-only. It records the documented crabc
// limits (inert setkey/encrypt and the no-catalog catgets/catclose profile)
// that pinned musl implements differently, so it is never compared.
#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fmtmsg.h>
#include <libintl.h>
#include <locale.h>
#include <malloc.h>
#include <netdb.h>
#include <sched.h>
#include <nl_types.h>
#include <pthread.h>
#include <search.h>
#include <stdarg.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <unistd.h>

// Musl's uninstalled context-sort helper. Its static archive definition is a
// hidden global and the frozen crabc shared ABI exports it; the public
// qsort_r is its weak same-definition alias.
void __qsort_r(void *, size_t, size_t, int (*)(const void *, const void *, void *), void *);
// Musl's assert() expansion target; <assert.h> declares it only as the
// macro's implementation, so name it directly with musl's signature.
_Noreturn void __assert_fail(const char *, const char *, int, const char *);
int __xpg_strerror_r(int, char *, size_t);
pid_t _Fork(void);

static int failures;

static void check(int condition, const char *label)
{
    if (!condition) {
        printf("FAIL %s\n", label);
        failures++;
    }
}

// Evaluate one call before sampling errno; argument evaluation order inside a
// single printf call is unspecified.
#define REPORT_ERRNO(label, expression)                  \
    do {                                                 \
        errno = 0;                                       \
        int reported_result = (expression);              \
        int reported_errno = errno;                      \
        printf("%s=%d,%d\n", label, reported_result, reported_errno); \
    } while (0)

static int compare_int(const void *left, const void *right)
{
    int a = *(const int *)left;
    int b = *(const int *)right;
    return (a > b) - (a < b);
}

static int compare_int_context(const void *left, const void *right, void *context)
{
    int direction = *(const int *)context;
    return direction * compare_int(left, right);
}

// tsearch keys are addresses of these values, so identity is observable.
static int keys[64];
static int walk_depth_sum;
static char walk_trace[2048];
static size_t walk_length;

static void record_walk(const void *node, VISIT visit, int depth)
{
    static const char names[] = "pPel";
    int value = **(int *const *)node;
    walk_depth_sum += depth;
    if (walk_length + 8 < sizeof walk_trace)
        walk_length += (size_t)snprintf(walk_trace + walk_length, sizeof walk_trace - walk_length,
                                        "%c%d%s", names[visit], value, visit == leaf || visit == endorder ? " " : "");
}

static int freed_keys;
static void release_key(void *key)
{
    *(int *)key = -*(int *)key;
    freed_keys++;
}

static void scenario_search(void)
{
    void *root = 0;
    int index;

    // Ascending insertion forces repeated single and double AVL rotations.
    for (index = 0; index < 31; index++) {
        keys[index] = index * 3 + 1;
        void *node = tsearch(&keys[index], &root, compare_int);
        check(node != 0 && *(int **)node == &keys[index], "tsearch insert");
    }
    int duplicate = 4;
    void *existing = tsearch(&duplicate, &root, compare_int);
    check(existing != 0 && *(int **)existing == &keys[1], "tsearch duplicate identity");
    void *found = tfind(&duplicate, &root, compare_int);
    check(found == existing, "tfind identity");
    int absent = 5;
    check(tfind(&absent, &root, compare_int) == 0, "tfind miss");
    check(tsearch(&absent, 0, compare_int) == 0, "tsearch null root");
    check(tfind(&absent, 0, compare_int) == 0, "tfind null root");
    check(tdelete(&absent, 0, compare_int) == 0, "tdelete null root");
    check(tdelete(&absent, &root, compare_int) == 0, "tdelete miss");

    twalk(root, record_walk);
    printf("tree-walk=%s\n", walk_trace);
    printf("tree-depth-sum=%d\n", walk_depth_sum);

    // Delete interior, leaf, and root keys and report parent identities.
    // Deleting the root returns an arbitrary non-null pointer that may name
    // released storage, so that result is only tested for nullness.
    int targets[] = { 46, 1, 91, 16, 49 };
    for (index = 0; index < (int)(sizeof targets / sizeof targets[0]); index++) {
        int was_root = root && **(int **)root == targets[index];
        void *parent = tdelete(&targets[index], &root, compare_int);
        if (was_root)
            printf("tdelete %d root-result-nonnull=%d\n", targets[index], parent != 0);
        else
            printf("tdelete %d parent=%d\n", targets[index], parent ? **(int **)parent : -1);
    }
    walk_length = 0;
    walk_depth_sum = 0;
    walk_trace[0] = 0;
    twalk(root, record_walk);
    printf("tree-walk-after-delete=%s\n", walk_trace);
    printf("tree-root-key=%d\n", root ? **(int **)root : 0);

    // Empty tree traversal and GNU destruction with key release.
    twalk(0, record_walk);
    tdestroy(0, release_key);
    tdestroy(root, release_key);
    printf("tdestroy-freed-keys=%d\n", freed_keys);
    printf("tdestroy-key-sample=%d,%d\n", keys[0], keys[30]);

    // Repeated create/destroy cycles keep ownership balanced.
    for (index = 0; index < 64; index++) {
        void *cycle_root = 0;
        int value;
        for (value = 0; value < 16; value++) {
            keys[value] = value;
            check(tsearch(&keys[value], &cycle_root, compare_int) != 0, "tsearch cycle");
        }
        for (value = 0; value < 16; value += 2)
            check(tdelete(&keys[value], &cycle_root, compare_int) != 0, "tdelete cycle");
        tdestroy(cycle_root, 0);
    }

    // Intrusive queue: linear and circular forms.
    struct qelem a = { 0 }, b = { 0 }, c = { 0 };
    insque(&a, 0);
    insque(&b, &a);
    insque(&c, &a);
    check(a.q_forw == &c && c.q_forw == &b && b.q_forw == 0, "insque linear forward");
    check(b.q_back == &c && c.q_back == &a && a.q_back == 0, "insque linear back");
    remque(&c);
    check(a.q_forw == &b && b.q_back == &a, "remque linear");
    struct qelem ring = { 0 }, member = { 0 };
    ring.q_forw = ring.q_back = &ring;
    insque(&member, &ring);
    check(ring.q_forw == &member && ring.q_back == &member, "insque circular");
    remque(&member);
    check(ring.q_forw == &ring && ring.q_back == &ring, "remque circular");
    printf("queue=ok\n");

    // Process-global hash table: zero-capacity create, growth, duplicates.
    char names[40][8];
    ENTRY item, *result;
    check(hcreate(0) != 0, "hcreate zero");
    for (index = 0; index < 40; index++) {
        snprintf(names[index], sizeof names[index], "k%02d", index);
        item.key = names[index];
        item.data = (void *)(intptr_t)(index + 100);
        result = hsearch(item, ENTER);
        check(result != 0 && result->data == item.data, "hsearch enter");
    }
    char duplicate_key[] = "k07";
    item.key = duplicate_key;
    item.data = (void *)(intptr_t)999;
    result = hsearch(item, ENTER);
    check(result != 0 && (intptr_t)result->data == 107 && result->key == names[7], "hsearch duplicate first");
    char missing_key[] = "zz";
    item.key = missing_key;
    check(hsearch(item, FIND) == 0, "hsearch find miss");
    char high_bit_key[] = "\xff\x80";
    item.key = high_bit_key;
    item.data = (void *)(intptr_t)7;
    check(hsearch(item, ENTER) != 0, "hsearch high-bit enter");
    intptr_t sum = 0;
    for (index = 0; index < 40; index++) {
        item.key = names[index];
        result = hsearch(item, FIND);
        sum += result ? (intptr_t)result->data : -100000;
    }
    printf("hash-global-sum=%ld\n", (long)sum);
    hdestroy();
    hdestroy();

    // Independent GNU caller records.
    struct hsearch_data first = { 0 }, second = { 0 };
    check(hcreate_r(4, &first) != 0 && hcreate_r(1000, &second) != 0, "hcreate_r");
    for (index = 0; index < 20; index++) {
        item.key = names[index];
        item.data = (void *)(intptr_t)index;
        check(hsearch_r(item, ENTER, &result, &first) != 0, "hsearch_r first");
        item.data = (void *)(intptr_t)(index * 2);
        check(hsearch_r(item, ENTER, &result, index % 2 ? &second : &first) != 0, "hsearch_r second");
    }
    item.key = names[3];
    check(hsearch_r(item, FIND, &result, &second) != 0 && (intptr_t)result->data == 6, "hsearch_r independent");
    item.key = names[4];
    check(hsearch_r(item, FIND, &result, &second) == 0 && result == 0, "hsearch_r miss nulls");
    hdestroy_r(&first);
    hdestroy_r(&second);
    hdestroy_r(&second);
    check(first.__tab == 0 && second.__tab == 0, "hdestroy_r clears");
    errno = 0;
    check(hcreate_r((size_t)-1, &first) == 0 && errno == ENOMEM, "hcreate_r overflow");
    printf("hash-reentrant=ok\n");
}

static void scenario_qsort(void)
{
    int values[97];
    int index;
    int direction = -1;

    for (index = 0; index < 97; index++)
        values[index] = (index * 37) % 97 - 40;
    qsort(values, 97, sizeof values[0], compare_int);
    printf("qsort=%d,%d,%d\n", values[0], values[48], values[96]);
    qsort_r(values, 97, sizeof values[0], compare_int_context, &direction);
    printf("qsort_r=%d,%d,%d\n", values[0], values[48], values[96]);
    direction = 1;
    __qsort_r(values, 97, sizeof values[0], compare_int_context, &direction);
    printf("__qsort_r=%d,%d,%d\n", values[0], values[48], values[96]);
    for (index = 1; index < 97; index++)
        check(values[index - 1] <= values[index], "__qsort_r order");
    // Odd element widths exercise the byte-cycling path.
    char words[5][3] = { "dd", "bb", "ee", "aa", "cc" };
    qsort(words, 5, 3, (int (*)(const void *, const void *))strcmp);
    printf("qsort-width3=%s%s%s%s%s\n", words[0], words[1], words[2], words[3], words[4]);
    qsort(values, 0, sizeof values[0], compare_int);
    qsort(values, 1, sizeof values[0], compare_int);
    printf("qsort-small=ok\n");
}

static void scenario_gettext(void)
{
    static char domains[12][16];
    static char directories[12][32];
    int index;

    printf("default-domain=%s\n", textdomain(0));
    errno = 1234;
    printf("gettext=%s\n", gettext("hello"));
    printf("dgettext=%s\n", dgettext("app", "hello"));
    printf("dcgettext=%s\n", dcgettext("app", "hello", LC_MESSAGES));
    printf("ngettext=%s,%s\n", ngettext("one", "many", 1), ngettext("one", "many", 2));
    printf("dngettext=%s,%s\n", dngettext("app", "one", "many", 1), dngettext("app", "one", "many", 0));
    printf("dcngettext=%s\n", dcngettext("app", "one", "many", 5, LC_MESSAGES));
    printf("dcngettext-bad-category=%s\n", dcngettext("app", "one", "many", 1, 1000));
    printf("gettext-errno=%d\n", errno);

    char *selected = textdomain("crabc-domain");
    printf("textdomain=%s\n", selected ? selected : "(null)");
    printf("textdomain-query-same=%d\n", textdomain(0) == selected);
    char overlong[300];
    memset(overlong, 'd', sizeof overlong - 1);
    overlong[sizeof overlong - 1] = 0;
    REPORT_ERRNO("textdomain-overlong-null", textdomain(overlong) == 0);
    printf("textdomain-after-overlong=%s\n", textdomain(0));
    printf("textdomain-empty=[%s]\n", textdomain(""));
    printf("gettext-empty-domain=%s\n", gettext("still-identity"));

    // Twelve distinct domains, then rebinding and a query of each.
    for (index = 0; index < 12; index++) {
        snprintf(domains[index], sizeof domains[index], "domain%02d", index);
        snprintf(directories[index], sizeof directories[index], "/usr/share/locale%02d", index);
        char *bound = bindtextdomain(domains[index], directories[index]);
        printf("bind %s=%s\n", domains[index], bound ? bound : "(null)");
    }
    char *rebound = bindtextdomain(domains[3], "/opt/locale");
    printf("rebind=%s\n", rebound ? rebound : "(null)");
    char *restored = bindtextdomain(domains[3], directories[3]);
    printf("restore=%s\n", restored ? restored : "(null)");
    for (index = 0; index < 12; index++) {
        char *queried = bindtextdomain(domains[index], 0);
        printf("query %s=%s\n", domains[index], queried ? queried : "(null)");
    }
    printf("query-unbound=%s\n", bindtextdomain("unbound", 0) ? "set" : "null");
    printf("bind-null-domain=%s\n", bindtextdomain(0, "/x") ? "set" : "null");
    REPORT_ERRNO("bind-overlong-domain-null", bindtextdomain(overlong, "/x") == 0);
    printf("dgettext-bound=%s\n", dgettext(domains[5], "bound-identity"));

    printf("codeset-query=%s\n", bind_textdomain_codeset("app", 0));
    printf("codeset-utf8=%s\n", bind_textdomain_codeset("app", "utf-8"));
    REPORT_ERRNO("codeset-latin1-null", bind_textdomain_codeset("app", "ISO-8859-1") == 0);

    errno = 0;
    nl_catd catalog = catopen("/nonexistent/crabc.cat", 0);
    printf("catopen-path=%d,%d\n", catalog == (nl_catd)-1, errno);
    errno = 0;
    catalog = catopen("crabc", NL_CAT_LOCALE);
    printf("catopen-nlspath-unset=%d,%d\n", catalog == (nl_catd)-1, errno);
}

static void scenario_diagnostics(void)
{
    char buffer[64];
    int number;

    for (number = -1; number <= 66; number++)
        printf("strsignal %d=%s\n", number, strsignal(number));
    for (number = -1; number <= 134; number++)
        printf("strerror %d=%s\n", number, strerror(number));
    printf("strerror-large=%s\n", strerror(100000));

    int status = strerror_r(ENOENT, buffer, sizeof buffer);
    printf("strerror_r=%d,%s\n", status, buffer);
    memset(buffer, 'x', sizeof buffer);
    status = strerror_r(ENOENT, buffer, 5);
    printf("strerror_r-short=%d,%s,%c\n", status, buffer, buffer[5]);
    memset(buffer, 'x', sizeof buffer);
    status = strerror_r(ENOENT, buffer, 0);
    printf("strerror_r-zero=%d,%c\n", status, buffer[0]);
    status = __xpg_strerror_r(EINVAL, buffer, sizeof buffer);
    printf("__xpg_strerror_r=%d,%s\n", status, buffer);

    for (number = -1; number <= 6; number++)
        printf("hstrerror %d=%s\n", number, hstrerror(number));
    fflush(stdout);
    h_errno = HOST_NOT_FOUND;
    herror("lookup");
    h_errno = TRY_AGAIN;
    herror(0);
    h_errno = 77;
    herror("");
    fflush(stderr);

    printf("secure_getenv=%s\n", secure_getenv("CRABC_PROBE") ? secure_getenv("CRABC_PROBE") : "(null)");
    printf("secure_getenv-missing=%s\n", secure_getenv("CRABC_MISSING") ? "set" : "null");
    printf("issetugid=%d\n", issetugid());

    // Musl derives both processor counts from the calling thread's
    // sched_getaffinity mask and page counts from sysinfo; compare with those
    // kernel observations rather than printing host-specific totals.
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    int affinity_count = sched_getaffinity(0, sizeof affinity, &affinity) == 0 ? CPU_COUNT(&affinity) : -1;
    struct sysinfo information;
    int have_information = sysinfo(&information) == 0;
    unsigned long unit = have_information && information.mem_unit ? information.mem_unit : 1;
    long total_pages = have_information ? (long)((unsigned long long)information.totalram * unit / 4096) : -1;
    int processors = get_nprocs();
    int configured = get_nprocs_conf();
    long physical = get_phys_pages();
    long available = get_avphys_pages();
    printf("get_nprocs=%d positive=%d\n", processors == affinity_count, processors > 0);
    printf("get_nprocs_conf=%d\n", configured == affinity_count);
    printf("get_phys_pages=%d positive=%d\n", physical == total_pages, physical > 0);
    printf("get_avphys_pages=%d\n", available > 0 && available <= physical);
}

static int aligned_to(const void *pointer, size_t alignment)
{
    return ((uintptr_t)pointer & (alignment - 1)) == 0;
}

static void scenario_allocation(void)
{
    void *pointer;
    void *output;
    int status;

    errno = 4321;
    pointer = malloc(0);
    printf("malloc-zero=%d,%d\n", pointer != 0, errno);
    printf("usable-null=%zu\n", malloc_usable_size(0));
    free(pointer);
    free(0);
    printf("free-errno=%d\n", errno);

    REPORT_ERRNO("malloc-huge", malloc(SIZE_MAX) == 0);
    REPORT_ERRNO("malloc-ptrdiff", malloc((size_t)PTRDIFF_MAX + 1) == 0);

    errno = 4321;
    unsigned char *zeroed = calloc(33, 7);
    int all_zero = zeroed != 0;
    for (size_t index = 0; zeroed && index < 33 * 7; index++)
        all_zero &= zeroed[index] == 0;
    printf("calloc=%d,%d,%d\n", zeroed != 0, all_zero, errno);
    printf("calloc-usable=%d\n", zeroed && malloc_usable_size(zeroed) >= 33 * 7);
    void *zero_count = calloc(0, 16);
    void *zero_size = calloc(16, 0);
    printf("calloc-zero=%d,%d\n", zero_count != 0, zero_size != 0);
    free(zero_count);
    free(zero_size);
    REPORT_ERRNO("calloc-overflow", calloc(SIZE_MAX / 2, 3) == 0);

    // realloc preserves content across growth and shrink; failure keeps it.
    for (int index = 0; index < 33 * 7; index++)
        zeroed[index] = (unsigned char)index;
    unsigned char *grown = realloc(zeroed, 100000);
    int preserved = grown != 0;
    for (int index = 0; grown && index < 33 * 7; index++)
        preserved &= grown[index] == (unsigned char)index;
    printf("realloc-grow=%d,%d\n", preserved, aligned_to(grown, 16));
    REPORT_ERRNO("realloc-huge", realloc(grown, SIZE_MAX) == 0);
    printf("realloc-huge-preserved=%d\n", grown[200] == 200);
    unsigned char *shrunk = realloc(grown, 10);
    printf("realloc-shrink=%d,%d\n", shrunk != 0, shrunk && shrunk[9] == 9);
    unsigned char *fresh = realloc(0, 24);
    printf("realloc-null=%d,%d\n", fresh != 0, fresh && malloc_usable_size(fresh) >= 24);
    free(fresh);

    errno = 0;
    void *array = reallocarray(0, 10, 10);
    printf("reallocarray=%d,%d\n", array != 0, errno);
    REPORT_ERRNO("reallocarray-overflow", reallocarray(array, SIZE_MAX / 2, 3) == 0);
    array = reallocarray(array, 20, 20);
    printf("reallocarray-grow=%d\n", array != 0 && malloc_usable_size(array) >= 400);
    free(array);
    free(shrunk);

    errno = 4321;
    pointer = aligned_alloc(256, 1000);
    printf("aligned_alloc=%d,%d,%d\n", pointer != 0, aligned_to(pointer, 256), errno);
    free(pointer);
    REPORT_ERRNO("aligned_alloc-bad", aligned_alloc(24, 48) == 0);
    REPORT_ERRNO("aligned_alloc-huge", aligned_alloc(64, SIZE_MAX) == 0);

    errno = 4321;
    output = (void *)(uintptr_t)0x1234;
    status = posix_memalign(&output, 4096, 12345);
    printf("posix_memalign=%d,%d,%d,%d\n", status, output != 0, aligned_to(output, 4096), errno);
    free(output);
    output = (void *)(uintptr_t)0x1234;
    status = posix_memalign(&output, 4, 16);
    printf("posix_memalign-small=%d,%d,%d\n", status, output == (void *)(uintptr_t)0x1234, errno);
    status = posix_memalign(&output, 48, 16);
    printf("posix_memalign-bad=%d,%d,%d\n", status, output == (void *)(uintptr_t)0x1234, errno);
    status = posix_memalign(&output, 64, SIZE_MAX);
    printf("posix_memalign-huge=%d,%d,%d\n", status, output == (void *)(uintptr_t)0x1234, errno);

    errno = 4321;
    pointer = memalign(128, 77);
    printf("memalign=%d,%d,%d\n", pointer != 0, aligned_to(pointer, 128), errno);
    free(pointer);
    REPORT_ERRNO("memalign-bad", memalign(96, 16) == 0);

    long page = sysconf(_SC_PAGESIZE);
    pointer = valloc(1);
    printf("valloc=%d,%d\n", pointer != 0, aligned_to(pointer, (size_t)page));
    printf("valloc-usable=%d\n", pointer && malloc_usable_size(pointer) >= 1);
    free(pointer);

    // Many live objects of mixed sizes remain individually observable.
    void *live[256];
    size_t index;
    for (index = 0; index < 256; index++)
        live[index] = malloc(index * 37 % 5000);
    int usable = 1;
    for (index = 0; index < 256; index++)
        usable &= live[index] && malloc_usable_size(live[index]) >= index * 37 % 5000;
    for (index = 0; index < 256; index += 2)
        free(live[index]);
    for (index = 1; index < 256; index += 2)
        live[index] = realloc(live[index], index * 11);
    for (index = 1; index < 256; index += 2) {
        usable &= live[index] && malloc_usable_size(live[index]) >= index * 11;
        free(live[index]);
    }
    printf("live-set=%d\n", usable);
}

// Function identity: C gives distinct functions distinct addresses. Only
// musl's own same-definition aliases may compare equal. Loads go through
// volatile storage so the compiler cannot fold any comparison.
typedef void (*entry_point)(void);
#define ENTRY(name) { #name, (entry_point)name }
static const struct {
    const char *name;
    entry_point address;
} entries[] = {
    ENTRY(bind_textdomain_codeset), ENTRY(bindtextdomain), ENTRY(catclose), ENTRY(catgets),
    ENTRY(catopen), ENTRY(dcgettext), ENTRY(dcngettext), ENTRY(dgettext), ENTRY(dngettext),
    ENTRY(gettext), ENTRY(ngettext), ENTRY(textdomain),
    ENTRY(_Exit), ENTRY(_Fork), ENTRY(__assert_fail), ENTRY(__errno_location),
    ENTRY(__xpg_strerror_r), ENTRY(_exit), ENTRY(at_quick_exit), ENTRY(atexit), ENTRY(err),
    ENTRY(errx), ENTRY(exit), ENTRY(herror), ENTRY(hstrerror), ENTRY(perror),
    ENTRY(quick_exit), ENTRY(secure_getenv), ENTRY(strerror), ENTRY(strerror_r),
    ENTRY(strsignal), ENTRY(verr), ENTRY(verrx), ENTRY(vwarn), ENTRY(vwarnx), ENTRY(warn),
    ENTRY(warnx),
    ENTRY(encrypt), ENTRY(fmtmsg), ENTRY(get_avphys_pages), ENTRY(get_nprocs),
    ENTRY(get_nprocs_conf), ENTRY(get_phys_pages), ENTRY(issetugid), ENTRY(setkey),
    ENTRY(__qsort_r), ENTRY(qsort_r), ENTRY(qsort),
    ENTRY(hcreate), ENTRY(hcreate_r), ENTRY(hdestroy), ENTRY(hdestroy_r), ENTRY(hsearch),
    ENTRY(hsearch_r),
    ENTRY(insque), ENTRY(remque), ENTRY(tdelete), ENTRY(tdestroy), ENTRY(tfind),
    ENTRY(tsearch), ENTRY(twalk),
};

static void scenario_identity(void)
{
    static entry_point volatile addresses[sizeof entries / sizeof entries[0]];
    size_t count = sizeof entries / sizeof entries[0];
    size_t left, right;

    for (left = 0; left < count; left++)
        addresses[left] = entries[left].address;
    for (left = 0; left < count; left++)
        for (right = left + 1; right < count; right++)
            if (addresses[left] == addresses[right])
                printf("same-entry %s=%s\n", entries[left].name, entries[right].name);
    printf("entries=%zu\n", count);
}

static void report_vwarn(int with_errno, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    if (with_errno)
        vwarn(format, arguments);
    else
        vwarnx(format, arguments);
    va_end(arguments);
}

static _Noreturn void report_verr(int with_errno, int status, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    if (with_errno)
        verr(status, format, arguments);
    verrx(status, format, arguments);
}

static int errno_worker_value;
static int *errno_worker_location;
static void *errno_worker(void *unused)
{
    (void)unused;
    errno = 91;
    errno_worker_location = __errno_location();
    errno_worker_value = errno;
    return 0;
}

// Diagnostics that return: err(3) warnings, perror, and errno ownership.
static void scenario_reporting(void)
{
    fflush(stdout);
    errno = ENOENT;
    warn("warn %d", 1);
    printf("warn-errno=%d\n", errno);
    errno = EACCES;
    warn(0);
    warnx("warnx %s", "text");
    warnx(0);
    errno = EINVAL;
    report_vwarn(1, "vwarn %d", 3);
    report_vwarn(0, "vwarnx %d", 4);
    errno = EBADF;
    perror("perror");
    errno = EPERM;
    perror("");
    errno = ERANGE;
    perror(0);
    printf("perror-errno=%d\n", errno);
    fflush(stderr);

    int *main_location = __errno_location();
    printf("errno-location-main=%d\n", main_location == &errno);
    errno = 17;
    pthread_t thread;
    check(pthread_create(&thread, 0, errno_worker, 0) == 0, "errno worker create");
    check(pthread_join(thread, 0) == 0, "errno worker join");
    printf("errno-location-thread=%d,%d,%d\n", errno_worker_location != main_location,
           errno_worker_value, errno);
}

static void exit_handler_one(void) { printf("atexit one\n"); }
static void exit_handler_nested(void) { printf("atexit nested\n"); }
static void exit_handler_two(void)
{
    printf("atexit two\n");
    check(atexit(exit_handler_nested) == 0, "nested atexit");
}
static void exit_handler_three(void) { printf("atexit three\n"); }
static void exit_handler_forbidden(void) { printf("atexit must not run\n"); }
static void quick_handler_one(void) { printf("at_quick_exit one\n"); fflush(stdout); }
static void quick_handler_two(void) { printf("at_quick_exit two\n"); fflush(stdout); }

// Each scenario prints its buffered prologue and then terminates; the
// runner compares the resulting status and streams with musl.
static _Noreturn void scenario_termination(const char *name)
{
    if (!strcmp(name, "exit")) {
        check(atexit(exit_handler_one) == 0 && atexit(exit_handler_two) == 0 &&
              atexit(exit_handler_three) == 0, "atexit");
        printf("exit buffered\n");
        exit(11);
    }
    if (!strcmp(name, "quick-exit")) {
        check(atexit(exit_handler_forbidden) == 0, "atexit before quick_exit");
        check(at_quick_exit(quick_handler_one) == 0 && at_quick_exit(quick_handler_two) == 0,
              "at_quick_exit");
        printf("quick-exit buffered\n");
        quick_exit(12);
    }
    if (!strcmp(name, "_exit") || !strcmp(name, "_Exit")) {
        check(atexit(exit_handler_forbidden) == 0, "atexit before immediate exit");
        // Musl's stdout starts line-buffered and switches to full buffering
        // on its first write to a non-terminal, so only the first line
        // reaches the file before the immediate exit discards the second.
        printf("immediate exit first line\n");
        printf("immediate exit discards this buffered line\n");
        if (name[1] == 'e')
            _exit(13);
        _Exit(14);
    }
    if (!strcmp(name, "fork")) {
        pid_t parent = getpid();
        fflush(stdout);
        pid_t child = _Fork();
        if (child == 0)
            _exit(getppid() == parent && getpid() != parent ? 21 : 22);
        int status = 0;
        check(child > 0 && waitpid(child, &status, 0) == child, "_Fork wait");
        printf("_Fork child=%d,%d\n", WIFEXITED(status), WEXITSTATUS(status));
        exit(failures ? 1 : 0);
    }
    fflush(stdout);
    errno = ENOENT;
    if (!strcmp(name, "err"))
        err(4, "err %d", 1);
    if (!strcmp(name, "errx"))
        errx(5, "errx %s", "text");
    if (!strcmp(name, "verr"))
        report_verr(1, 6, "verr %d", 2);
    if (!strcmp(name, "verrx"))
        report_verr(0, 7, "verrx %d", 3);
    if (!strcmp(name, "assert"))
        __assert_fail("left == right", "owned_c_abi_compat_probe.c", 42, "scenario_termination");
    exit(2);
}

// Candidate-only documented profile limits. Pinned musl implements DES and
// file-backed message catalogs; crabc deliberately does neither.
static void scenario_profile(void)
{
    char key[64];
    char block[64];
    memset(key, 1, sizeof key);
    memset(block, 0, sizeof block);
    block[3] = 1;
    errno = 77;
    setkey(key);
    encrypt(block, 0);
    encrypt(block, 1);
    printf("des-inert=%d,%d,%d\n", key[0] == 1 && key[63] == 1, block[3] == 1 && block[4] == 0, errno);
    printf("catgets-default=%s\n", catgets((nl_catd)-1, 1, 1, "default-message"));
    printf("catclose=%d\n", catclose((nl_catd)-1));
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    if (!strcmp(argv[1], "search"))
        scenario_search();
    else if (!strcmp(argv[1], "qsort"))
        scenario_qsort();
    else if (!strcmp(argv[1], "gettext"))
        scenario_gettext();
    else if (!strcmp(argv[1], "diagnostics"))
        scenario_diagnostics();
    else if (!strcmp(argv[1], "allocation"))
        scenario_allocation();
    else if (!strcmp(argv[1], "identity"))
        scenario_identity();
    else if (!strcmp(argv[1], "reporting"))
        scenario_reporting();
    else if (!strncmp(argv[1], "terminate-", 10))
        scenario_termination(argv[1] + 10);
    else if (!strcmp(argv[1], "profile"))
        scenario_profile();
    else
        return 2;
    printf("owned-c-abi-compat-%s-%s\n", argv[1], failures ? "failed" : "ok");
    return failures ? 1 : 0;
}
