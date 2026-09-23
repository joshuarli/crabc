// Verify that owned C APIs which publish or retire malloc-family storage keep
// the executable's provider selected.  asprintf publishes caller-owned bytes;
// the passwd lookup's private getline allocation is retired before return.
// lio_listio's list state and the nonreentrant host cache also use that
// provider, while AIO queue storage and the locked timezone cache belong to
// libc's private allocator.
#define _GNU_SOURCE
#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stddef.h>
#include <stdatomic.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { STORAGE_BYTES = 1 << 20, MAXIMUM_ALLOCS = 32, FREED_FILL = 42 };

struct allocation {
    unsigned char *address;
    size_t length;
    int released;
};

static _Alignas(max_align_t) unsigned char storage[STORAGE_BYTES];
static struct allocation allocations[MAXIMUM_ALLOCS];
static size_t storage_used;
static _Atomic size_t allocation_count;
static _Atomic size_t allocation_attempts;
static _Atomic int allocator_misuse;
static _Atomic int reject_allocations;
static _Atomic int allocator_lock;

// An incorrect public-allocation edge may run from an AIO worker. Keep the
// observer valid in that case too, so it reports the ownership violation
// without introducing a data race of its own.
static void lock_allocator(void)
{
    while (atomic_exchange_explicit(&allocator_lock, 1, memory_order_acquire))
        ;
}

static void unlock_allocator(void)
{
    atomic_store_explicit(&allocator_lock, 0, memory_order_release);
}

static struct allocation *find_allocation(void *pointer)
{
    size_t index;

    for (index = 0; index < allocation_count; index++)
        if (allocations[index].address == pointer)
            return &allocations[index];
    return 0;
}

static int reserve_storage(size_t length, size_t *offset)
{
    size_t alignment = _Alignof(max_align_t);
    size_t padding = storage_used % alignment;

    if (padding != 0)
        padding = alignment - padding;
    if (padding > STORAGE_BYTES - storage_used)
        return 0;
    *offset = storage_used + padding;
    if (length > STORAGE_BYTES - *offset)
        return 0;
    storage_used = *offset + length;
    return 1;
}

static void *allocate_unlocked(size_t length)
{
    size_t offset;

    allocation_attempts++;
    if (reject_allocations)
        return 0;
    if (length == 0)
        length = 1;
    if (allocation_count == MAXIMUM_ALLOCS || !reserve_storage(length, &offset))
        return 0;
    allocations[allocation_count] = (struct allocation){ storage + offset, length, 0 };
    return allocations[allocation_count++].address;
}

static void release_unlocked(void *pointer)
{
    struct allocation *allocation;

    if (pointer == 0)
        return;
    allocation = find_allocation(pointer);
    if (allocation == 0 || allocation->released) {
        allocator_misuse = 1;
        return;
    }
    memset(allocation->address, FREED_FILL, allocation->length);
    allocation->released = 1;
}

static void *reallocate_unlocked(void *pointer, size_t length)
{
    struct allocation *allocation;
    void *replacement;

    if (pointer == 0)
        return allocate_unlocked(length);
    allocation = find_allocation(pointer);
    if (allocation == 0 || allocation->released) {
        allocator_misuse = 1;
        return 0;
    }
    if (length == 0) {
        release_unlocked(pointer);
        return 0;
    }
    replacement = allocate_unlocked(length);
    if (replacement == 0)
        return 0;
    memcpy(replacement, pointer, allocation->length < length ? allocation->length : length);
    release_unlocked(pointer);
    return replacement;
}

static void *allocate_zeroed_unlocked(size_t count, size_t length)
{
    void *result;

    if (count != 0 && length > (size_t)-1 / count)
        return 0;
    result = allocate_unlocked(count * length);
    if (result != 0)
        memset(result, 0, count * length);
    return result;
}

void *malloc(size_t length)
{
    lock_allocator();
    void *result = allocate_unlocked(length);
    unlock_allocator();
    return result;
}

void free(void *pointer)
{
    lock_allocator();
    release_unlocked(pointer);
    unlock_allocator();
}

void *realloc(void *pointer, size_t length)
{
    lock_allocator();
    void *result = reallocate_unlocked(pointer, length);
    unlock_allocator();
    return result;
}

void *calloc(size_t count, size_t length)
{
    lock_allocator();
    void *result = allocate_zeroed_unlocked(count, length);
    unlock_allocator();
    return result;
}

static int released_storage_is_unchanged_since(size_t first)
{
    size_t index;
    int unchanged = 0;

    lock_allocator();
    if (first == allocation_count)
        goto done;
    for (index = first; index < allocation_count; index++) {
        size_t byte;

        if (!allocations[index].released)
            goto done;
        for (byte = 0; byte < allocations[index].length; byte++)
            if (allocations[index].address[byte] != FREED_FILL)
                goto done;
    }
    unchanged = 1;
done:
    unlock_allocator();
    return unchanged;
}

static int check_asprintf_result(void)
{
    char *result = 0;
    size_t first = allocation_count;

    if (asprintf(&result, "%s %d", "caller-owned", 64) != 15)
        return 10;
    if (result == 0 || strcmp(result, "caller-owned 64") != 0)
        return 11;
    if (find_allocation(result) == 0)
        return 12;
    free(result);
    return allocator_misuse || !released_storage_is_unchanged_since(first) ? 13 : 0;
}

static int check_passwd_getdelim_release(void)
{
    struct passwd record;
    struct passwd *result = 0;
    char buffer[512];
    size_t first = allocation_count;

    if (getpwnam_r("crabc", &record, buffer, sizeof buffer, &result) != 0)
        return 20;
    if (result != &record || strcmp(record.pw_name, "crabc") != 0
        || strcmp(record.pw_shell, "/bin/sh") != 0)
        return 21;
    result = (void *)1;
    if (getpwnam_r("missing", &record, buffer, sizeof buffer, &result) != 0
        || result != 0)
        return 22;
    return allocator_misuse || !released_storage_is_unchanged_since(first) ? 23 : 0;
}

static int check_host_cache_provider(void)
{
    struct hostent *first_host;
    struct hostent *second_host;
    size_t first = allocation_count;
    size_t byte;

    first_host = gethostbyname("127.0.0.1");
    if (first_host == 0 || first_host->h_addrtype != AF_INET
        || allocation_count != first + 1)
        return 40;
    second_host = gethostbyname("127.0.0.1");
    if (second_host == 0 || second_host->h_addrtype != AF_INET
        || allocation_count != first + 2)
        return 41;
    if (!allocations[first].released || allocations[first + 1].released)
        return 42;
    for (byte = 0; byte < allocations[first].length; byte++)
        if (allocations[first].address[byte] != FREED_FILL)
            return 43;
    return allocator_misuse ? 44 : 0;
}

static int check_timezone_cache_provider(void)
{
    static char value[] = "TZ=EST5EDT,M3.2.0/02:00:00,M11.1.0/02:00:00";
    size_t first;
    size_t attempts;

    if (putenv(value) != 0)
        return 50;
    first = allocation_count;
    attempts = allocation_attempts;
    reject_allocations = 1;
    tzset();
    reject_allocations = 0;
    if (allocation_count != first || allocation_attempts != attempts)
        return 51;
    if (strcmp(tzname[0], "EST") != 0 || strcmp(tzname[1], "EDT") != 0)
        return 52;
    return allocator_misuse ? 53 : 0;
}

static _Atomic int aio_cleanup_complete;

static void aio_cleanup_notification(union sigval value)
{
    (void)value;
    atomic_store_explicit(&aio_cleanup_complete, 1, memory_order_release);
}

static int check_lio_state_and_private_queue(void)
{
    struct aiocb control;
    struct aiocb before;
    struct aiocb *controls[] = { &control };
    char byte = 'a';
    size_t first = allocation_count;
    size_t attempts = allocation_attempts;
    int descriptor = open("/tmp/lio-allocator-state", O_CREAT | O_TRUNC | O_RDWR, 0600);

    if (descriptor < 0)
        return 30;
    memset(&control, 0, sizeof control);
    control.aio_fildes = descriptor;
    control.aio_lio_opcode = LIO_WRITE;
    control.aio_buf = &byte;
    control.aio_nbytes = 1;
    control.aio_sigevent.sigev_notify = SIGEV_THREAD;
    control.aio_sigevent.sigev_notify_function = aio_cleanup_notification;
    memcpy(&before, &control, sizeof before);

    // Failure of the executable's allocator must happen before submission.
    // The control block is still caller-owned and byte-for-byte unchanged.
    reject_allocations = 1;
    errno = 0;
    if (lio_listio(LIO_WAIT, controls, 1, 0) != -1 || errno != EAGAIN
        || allocation_attempts != attempts + 1 || allocation_count != first
        || memcmp(&before, &control, sizeof control) != 0)
        return 31;
    reject_allocations = 0;

    if (lio_listio(LIO_WAIT, controls, 1, 0) != 0
        || aio_error(&control) != 0 || aio_return(&control) != 1
        || close(descriptor) != 0 || unlink("/tmp/lio-allocator-state") != 0)
        return 32;
    // Request notification follows private queue retirement in aio.c. Wait
    // for it before inspecting the interposer so a late wrong-public-free
    // cannot escape the observer after terminal aiocb publication.
    while (!atomic_load_explicit(&aio_cleanup_complete, memory_order_acquire))
        usleep(1000);
    // The public flexible list state is the sole new allocation. Descriptor
    // map levels and per-request queues must never cross this interposer.
    if (allocation_attempts != attempts + 2 || allocation_count != first + 1)
        return 33;
    return allocator_misuse || !released_storage_is_unchanged_since(first) ? 34 : 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    if (strcmp(argv[1], "asprintf") == 0)
        return check_asprintf_result();
    if (strcmp(argv[1], "passwd") == 0)
        return check_passwd_getdelim_release();
    if (strcmp(argv[1], "host") == 0)
        return check_host_cache_provider();
    if (strcmp(argv[1], "timezone") == 0)
        return check_timezone_cache_provider();
    if (strcmp(argv[1], "lio") == 0)
        return check_lio_state_and_private_queue();
    return 3;
}
