/* Owned static product cross-thread allocation-ownership consumer.
 *
 * Four producer threads allocate through every public allocation family and
 * hand each live block to four consumer threads through one bounded queue.
 * Consumers verify contents and usable size, then free, grow, or shrink the
 * foreign block while its allocating owner is still alive. After every
 * handoff is consumed each producer allocates again from its own heap, keeps
 * half of those blocks, and exits. The initial thread then reallocates and
 * frees the surviving blocks of the exited owners.
 *
 * The program uses only public C allocation and pthread interfaces, so the
 * same source runs against pinned musl and both owned static link modes. It
 * prints one completion line; every failure exits with a distinct status.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "owned static allocator ownership requires native Linux/x86-64 LP64"
#endif

#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    producer_count = 4,
    consumer_count = 4,
    blocks_per_producer = 3072,
    survivor_rounds = 256,
    queue_capacity = 64,
};

static const size_t sizes[] = {
    3, 7, 16, 24, 63, 100, 256, 1000, 4096, 5000, 16384, 65536,
    131089, 262144, 1048576, 3145728,
};

struct block {
    unsigned char *pointer;
    size_t size;
    unsigned char tag;
};

static struct {
    pthread_mutex_t lock;
    pthread_cond_t readable;
    pthread_cond_t writable;
    struct block slots[queue_capacity];
    size_t head;
    size_t count;
    unsigned finished_producers;
} queue = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .readable = PTHREAD_COND_INITIALIZER,
    .writable = PTHREAD_COND_INITIALIZER,
};

static pthread_barrier_t handoffs_consumed;

struct survivors {
    struct block blocks[survivor_rounds / 2];
    size_t count;
};

static struct survivors survivors[producer_count];

static void fail(int status) __attribute__((noreturn));

static void fail(int status)
{
    _exit(status);
}

static void fill(const struct block *block)
{
    block->pointer[0] = block->tag;
    block->pointer[block->size / 2] = (unsigned char)(block->tag ^ 0x5a);
    block->pointer[block->size - 1] = (unsigned char)(block->tag + 1);
}

static int intact(const struct block *block, size_t visible)
{
    size_t middle = block->size / 2;

    return block->pointer[0] == block->tag &&
        (middle >= visible || block->pointer[middle] == (unsigned char)(block->tag ^ 0x5a)) &&
        (block->size - 1 >= visible ||
            block->pointer[block->size - 1] == (unsigned char)(block->tag + 1));
}

/* Allocate through the selected entry for `index`; each result must be
 * aligned for its route. Successful-allocation errno preservation is a
 * separate allocator/C ABI contract and is not asserted by this consumer. */
static struct block allocate(size_t index, unsigned char tag)
{
    struct block block = { NULL, sizes[index % (sizeof sizes / sizeof sizes[0])], tag };
    void *aligned = NULL;

    switch (index % 5) {
    case 0:
        block.pointer = malloc(block.size);
        break;
    case 1:
        block.pointer = calloc(1, block.size);
        if (block.pointer != NULL) {
            for (size_t offset = 0; offset < block.size; offset += 97) {
                if (block.pointer[offset] != 0)
                    fail(40);
            }
        }
        break;
    case 2:
        block.pointer = aligned_alloc(64, (block.size + 63) & ~(size_t)63);
        if (((uintptr_t)block.pointer & 63) != 0)
            fail(41);
        break;
    case 3:
        if (posix_memalign(&aligned, 4096, block.size) != 0)
            fail(42);
        block.pointer = aligned;
        if (((uintptr_t)block.pointer & 4095) != 0)
            fail(43);
        break;
    default:
        block.pointer = malloc(8);
        if (block.pointer == NULL)
            fail(44);
        block.pointer = realloc(block.pointer, block.size);
        break;
    }
    if (block.pointer == NULL)
        fail(45);
    if (malloc_usable_size(block.pointer) < block.size)
        fail(46);
    fill(&block);
    return block;
}

static void push(struct block block)
{
    pthread_mutex_lock(&queue.lock);
    while (queue.count == queue_capacity)
        pthread_cond_wait(&queue.writable, &queue.lock);
    queue.slots[(queue.head + queue.count) % queue_capacity] = block;
    ++queue.count;
    pthread_cond_signal(&queue.readable);
    pthread_mutex_unlock(&queue.lock);
}

static int pop(struct block *block)
{
    pthread_mutex_lock(&queue.lock);
    while (queue.count == 0 && queue.finished_producers != producer_count)
        pthread_cond_wait(&queue.readable, &queue.lock);
    if (queue.count == 0) {
        pthread_mutex_unlock(&queue.lock);
        return 0;
    }
    *block = queue.slots[queue.head];
    queue.head = (queue.head + 1) % queue_capacity;
    --queue.count;
    pthread_cond_signal(&queue.writable);
    pthread_mutex_unlock(&queue.lock);
    return 1;
}

static void *producer(void *opaque)
{
    size_t identity = (size_t)(uintptr_t)opaque;
    struct survivors *kept = &survivors[identity];

    for (size_t index = 0; index < blocks_per_producer; ++index)
        push(allocate(index * 7 + identity, (unsigned char)(identity * 61 + index)));
    pthread_mutex_lock(&queue.lock);
    ++queue.finished_producers;
    pthread_cond_broadcast(&queue.readable);
    pthread_mutex_unlock(&queue.lock);

    /* Every remote free and reallocation above completed while this owner
     * stayed alive. Its own heap must still serve and reclaim allocations. */
    int barrier = pthread_barrier_wait(&handoffs_consumed);
    if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD)
        fail(47);
    for (size_t index = 0; index < survivor_rounds; ++index) {
        struct block block = allocate(index * 3 + identity, (unsigned char)(identity + index));

        if (index % 2 == 0) {
            free(block.pointer);
        } else {
            kept->blocks[kept->count++] = block;
        }
    }
    return NULL;
}

static void *consumer(void *unused)
{
    struct block block;
    size_t consumed = 0;

    (void)unused;
    while (pop(&block)) {
        unsigned char *moved;
        size_t grown = block.size * 2 + 1;
        size_t shrunk = block.size / 2 + 1;

        if (!intact(&block, block.size) || malloc_usable_size(block.pointer) < block.size)
            fail(50);
        switch (consumed++ % 3) {
        case 0:
            free(block.pointer);
            break;
        case 1:
            moved = realloc(block.pointer, grown);
            if (moved == NULL)
                fail(51);
            block.pointer = moved;
            if (!intact(&block, block.size) || malloc_usable_size(moved) < grown)
                fail(52);
            free(moved);
            break;
        default:
            moved = realloc(block.pointer, shrunk);
            if (moved == NULL)
                fail(53);
            block.pointer = moved;
            if (!intact(&block, shrunk) || malloc_usable_size(moved) < shrunk)
                fail(54);
            free(moved);
            break;
        }
    }
    int barrier = pthread_barrier_wait(&handoffs_consumed);
    if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD)
        fail(55);
    return (void *)(uintptr_t)consumed;
}

int main(void)
{
    pthread_t producers[producer_count];
    pthread_t consumers[consumer_count];
    size_t consumed = 0;
    size_t reclaimed = 0;

    if (pthread_barrier_init(&handoffs_consumed, NULL, producer_count + consumer_count) != 0)
        return 60;
    for (size_t index = 0; index < producer_count; ++index) {
        if (pthread_create(&producers[index], NULL, producer, (void *)(uintptr_t)index) != 0)
            return 61;
    }
    for (size_t index = 0; index < consumer_count; ++index) {
        if (pthread_create(&consumers[index], NULL, consumer, NULL) != 0)
            return 62;
    }
    for (size_t index = 0; index < consumer_count; ++index) {
        void *result = NULL;

        if (pthread_join(consumers[index], &result) != 0)
            return 63;
        consumed += (size_t)(uintptr_t)result;
    }
    for (size_t index = 0; index < producer_count; ++index) {
        if (pthread_join(producers[index], NULL) != 0)
            return 64;
    }
    if (consumed != (size_t)producer_count * blocks_per_producer)
        return 65;

    /* Each surviving block belongs to an owner that has exited. */
    for (size_t owner = 0; owner < producer_count; ++owner) {
        for (size_t index = 0; index < survivors[owner].count; ++index) {
            struct block *block = &survivors[owner].blocks[index];
            unsigned char *moved;

            if (!intact(block, block->size))
                return 66;
            moved = realloc(block->pointer, block->size + 4096);
            if (moved == NULL)
                return 67;
            block->pointer = moved;
            if (!intact(block, block->size))
                return 68;
            free(moved);
            ++reclaimed;
        }
    }
    if (reclaimed != producer_count * (survivor_rounds / 2))
        return 69;
    if (pthread_barrier_destroy(&handoffs_consumed) != 0)
        return 70;
    if (write(1, "owned-allocator-remote-ok\n", 26) != 26)
        return 71;
    return 0;
}
