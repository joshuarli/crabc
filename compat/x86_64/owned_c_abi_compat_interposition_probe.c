// Public allocator ownership of the selected search and gettext clients.
//
// Pinned musl 1.2.6 allocates tsearch nodes with public malloc/free,
// hsearch tables with public calloc/free, and textdomain's current-domain
// buffer with public malloc, while bindtextdomain uses the private
// __libc_calloc seam. This executable replaces the public malloc family and
// records every call made inside explicit windows, so pinned musl and each
// owned dynamic entry must produce the same allocation trace. Only logical
// allocation ordinals are printed, never addresses.
#define _GNU_SOURCE
#include <errno.h>
#include <libintl.h>
#include <search.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { STORAGE_BYTES = 1 << 20, MAXIMUM_ALLOCS = 1024, MAXIMUM_EVENTS = 256 };

struct allocation {
    unsigned char *address;
    size_t length;
    int released;
    long logical;
};

struct event {
    char kind;
    size_t first;
    size_t second;
    long ordinal;
    long result;
};

static _Alignas(max_align_t) unsigned char storage[STORAGE_BYTES];
static struct allocation allocations[MAXIMUM_ALLOCS];
static struct event events[MAXIMUM_EVENTS];
static size_t storage_used;
static size_t allocation_count;
static size_t event_count;
static long logical_count;
static int recording;
static int reject_next;
static int misuse;
static atomic_int allocator_lock;

static void lock_allocator(void)
{
    while (atomic_exchange_explicit(&allocator_lock, 1, memory_order_acquire))
        ;
}

static void unlock_allocator(void)
{
    atomic_store_explicit(&allocator_lock, 0, memory_order_release);
}

static long ordinal_of(void *pointer)
{
    size_t index;
    for (index = 0; index < allocation_count; index++)
        if (allocations[index].address == pointer)
            return (long)index;
    return -1;
}

// Allocations made inside recording windows receive logical ids in call
// order; allocations outside the windows (startup, stdio) print as "other".
static long logical_of(long ordinal)
{
    return ordinal < 0 ? -1 : allocations[ordinal].logical;
}

static void record(char kind, size_t first, size_t second, long ordinal, long result)
{
    if (!recording)
        return;
    if (event_count == MAXIMUM_EVENTS) {
        misuse = 1;
        return;
    }
    events[event_count++] = (struct event){ kind, first, second, ordinal, result };
}

static void *allocate_unlocked(size_t length)
{
    size_t alignment = _Alignof(max_align_t);
    size_t offset = (storage_used + alignment - 1) & ~(alignment - 1);

    if (recording && reject_next) {
        reject_next = 0;
        errno = ENOMEM;
        return 0;
    }
    if (length == 0)
        length = 1;
    if (allocation_count == MAXIMUM_ALLOCS || offset > STORAGE_BYTES || length > STORAGE_BYTES - offset) {
        errno = ENOMEM;
        return 0;
    }
    storage_used = offset + length;
    allocations[allocation_count] = (struct allocation){ storage + offset, length, 0, recording ? logical_count++ : -1 };
    return allocations[allocation_count++].address;
}

static void release_unlocked(void *pointer)
{
    long ordinal;

    if (pointer == 0)
        return;
    ordinal = ordinal_of(pointer);
    if (ordinal < 0 || allocations[ordinal].released) {
        misuse = 1;
        return;
    }
    memset(allocations[ordinal].address, 0x5a, allocations[ordinal].length);
    allocations[ordinal].released = 1;
}

void *malloc(size_t length)
{
    lock_allocator();
    void *result = allocate_unlocked(length);
    record('m', length, 0, -1, result ? logical_of(ordinal_of(result)) : -1);
    unlock_allocator();
    return result;
}

void *calloc(size_t count, size_t length)
{
    void *result = 0;

    lock_allocator();
    if (count != 0 && length > (size_t)-1 / count) {
        errno = ENOMEM;
    } else {
        result = allocate_unlocked(count * length);
        if (result)
            memset(result, 0, count * length);
    }
    record('c', count, length, -1, result ? logical_of(ordinal_of(result)) : -1);
    unlock_allocator();
    return result;
}

void *realloc(void *pointer, size_t length)
{
    void *result = 0;
    long ordinal;

    lock_allocator();
    ordinal = pointer ? ordinal_of(pointer) : -1;
    if (pointer && (ordinal < 0 || allocations[ordinal].released)) {
        misuse = 1;
    } else {
        result = allocate_unlocked(length);
        if (result && pointer) {
            size_t old = allocations[ordinal].length;
            memcpy(result, pointer, old < length ? old : length);
            release_unlocked(pointer);
        }
    }
    record('r', length, 0, pointer ? logical_of(ordinal) : -2, result ? logical_of(ordinal_of(result)) : -1);
    unlock_allocator();
    return result;
}

void free(void *pointer)
{
    lock_allocator();
    long ordinal = pointer ? ordinal_of(pointer) : -1;
    record('f', 0, 0, pointer ? logical_of(ordinal) : -2, 0);
    release_unlocked(pointer);
    unlock_allocator();
}

static void begin(void)
{
    event_count = 0;
    recording = 1;
}

static void print_id(long id)
{
    if (id == -2)
        printf("null");
    else if (id < 0)
        printf("other");
    else
        printf("#%ld", id);
}

static void end(const char *label)
{
    size_t index;

    recording = 0;
    printf("%s:", label);
    for (index = 0; index < event_count; index++) {
        struct event *event = &events[index];
        switch (event->kind) {
        case 'm':
            printf(" malloc(%zu)=", event->first);
            break;
        case 'c':
            printf(" calloc(%zu,%zu)=", event->first, event->second);
            break;
        case 'r':
            printf(" realloc(");
            print_id(event->ordinal);
            printf(",%zu)=", event->first);
            break;
        case 'f':
            printf(" free(");
            print_id(event->ordinal);
            printf(")");
            continue;
        }
        if (event->result < 0)
            printf("failed");
        else
            print_id(event->result);
    }
    printf("\n");
}

static int compare_int(const void *left, const void *right)
{
    int a = *(const int *)left;
    int b = *(const int *)right;
    return (a > b) - (a < b);
}

static int released_keys;
static void release_key(void *key)
{
    (void)key;
    released_keys++;
}

static int scenario_tree(void)
{
    static int keys[] = { 50, 20, 80, 10, 30, 70, 90, 25 };
    void *root = 0;
    size_t index;
    int status = 0;

    begin();
    for (index = 0; index < sizeof keys / sizeof keys[0]; index++)
        status |= tsearch(&keys[index], &root, compare_int) == 0;
    end("tsearch");

    begin();
    status |= tsearch(&keys[3], &root, compare_int) == 0;
    status |= tfind(&keys[4], &root, compare_int) == 0;
    end("tsearch-existing");

    // A node with a left subtree releases its in-order predecessor.
    begin();
    status |= tdelete(&keys[1], &root, compare_int) == 0;
    status |= tdelete(&keys[6], &root, compare_int) == 0;
    end("tdelete");

    begin();
    reject_next = 1;
    int extra = 60;
    void *failed = tsearch(&extra, &root, compare_int);
    int failed_errno = errno;
    void *missing = tfind(&extra, &root, compare_int);
    void *retried = tsearch(&extra, &root, compare_int);
    end("tsearch-failure");
    printf("tsearch-failure-result=%d,%d,%d,%d\n", failed == 0, failed_errno == ENOMEM, missing == 0, retried != 0);

    begin();
    tdestroy(root, release_key);
    end("tdestroy");
    printf("tdestroy-keys=%d\n", released_keys);
    return status;
}

static int scenario_hash(void)
{
    static char names[16][8];
    ENTRY item, *result;
    struct hsearch_data reentrant = { 0 };
    int index;
    int status = 0;

    for (index = 0; index < 16; index++)
        snprintf(names[index], sizeof names[index], "h%02d", index);

    begin();
    status |= hcreate(3) == 0;
    end("hcreate");

    begin();
    for (index = 0; index < 7; index++) {
        item.key = names[index];
        item.data = 0;
        status |= hsearch(item, ENTER) == 0;
    }
    end("hsearch-grow");

    // Reject the next growth: the entry is rolled back and remains absent.
    begin();
    for (index = 7; index < 12; index++) {
        item.key = names[index];
        item.data = 0;
        status |= hsearch(item, ENTER) == 0;
    }
    reject_next = 1;
    item.key = names[12];
    result = hsearch(item, ENTER);
    int failed_errno = errno;
    ENTRY *absent = hsearch(item, FIND);
    ENTRY *retried = hsearch(item, ENTER);
    end("hsearch-failure");
    printf("hsearch-failure-result=%d,%d,%d,%d\n", result == 0, failed_errno == ENOMEM, absent == 0, retried != 0);

    begin();
    hdestroy();
    hdestroy();
    end("hdestroy");

    begin();
    status |= hcreate_r(20, &reentrant) == 0;
    item.key = names[0];
    status |= hsearch_r(item, ENTER, &result, &reentrant) == 0;
    hdestroy_r(&reentrant);
    hdestroy_r(&reentrant);
    end("hsearch_r");

    begin();
    reject_next = 1;
    int created = hcreate_r(4, &reentrant);
    int create_errno = errno;
    end("hcreate_r-failure");
    printf("hcreate_r-failure-result=%d,%d,%d\n", created == 0, create_errno == ENOMEM, reentrant.__tab == 0);
    return status;
}

static int scenario_gettext(void)
{
    int status = 0;

    begin();
    status |= textdomain("first-domain") == 0;
    status |= textdomain("second-domain") == 0;
    status |= textdomain(0) == 0;
    end("textdomain");

    // Musl's binding records use its private __libc_calloc seam.
    begin();
    status |= bindtextdomain("first-domain", "/usr/share/locale") == 0;
    status |= bindtextdomain("second-domain", "/opt/locale") == 0;
    status |= bindtextdomain("first-domain", 0) == 0;
    status |= dgettext("first-domain", "identity") == 0;
    end("bindtextdomain");
    printf("current-domain=%s\n", textdomain(0));
    return status;
}

int main(int argc, char **argv)
{
    int status;

    if (argc != 2)
        return 2;
    if (!strcmp(argv[1], "tree"))
        status = scenario_tree();
    else if (!strcmp(argv[1], "hash"))
        status = scenario_hash();
    else if (!strcmp(argv[1], "gettext"))
        status = scenario_gettext();
    else
        return 2;
    status |= misuse;
    printf("owned-c-abi-compat-interpose-%s-%s\n", argv[1], status ? "failed" : "ok");
    return status ? 1 : 0;
}
