/*
 * Installed fork/allocator composition against pinned musl 1.2.6.
 *
 * A multithreaded parent holds live small, medium, large and mmap-sized
 * allocations on its initial thread and on a worker while a third thread
 * churns malloc/free. `fork` is called from the initial thread, from the
 * worker, or after the worker has exited and been joined. The child must see
 * every inherited block intact, reallocate and free them, run the ordinary
 * allocation set, create a thread, fork again and exit normally. Registered
 * pthread_atfork handlers allocate in every phase; their order is recorded.
 * A repeated scenario forks 64 times while three threads allocate every
 * class and free each other's blocks. A single-threaded `_Fork` child runs
 * no handler and still allocates.
 *
 * Output is written with dprintf after each child has been reaped, so the
 * transcript is deterministic and identical for every conforming libc.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

pid_t _Fork(void);

#define CHECK(c) do { if (!(c)) { dprintf(2, "native allocator fork line %d errno %d\n", __LINE__, errno); _exit(1); } } while (0)

static const size_t sizes[] = { 48, 3000, 40000, 300000, 3u << 20 };
#define CLASSES (sizeof sizes / sizeof *sizes)

struct block { unsigned char *pointer; size_t size; unsigned char byte; };

static void fill(struct block *blocks, unsigned char byte) {
    for (size_t i = 0; i < CLASSES; i++) {
        blocks[i] = (struct block){ malloc(sizes[i]), sizes[i], byte };
        CHECK(blocks[i].pointer);
        memset(blocks[i].pointer, byte, sizes[i]);
    }
}

static int intact(const struct block *block) {
    for (size_t i = 0; i < block->size; i++)
        if (block->pointer[i] != block->byte) return 0;
    return 1;
}

/* Every other inherited block is moved through realloc before release. */
static void release(struct block *blocks) {
    for (size_t i = 0; i < CLASSES; i++) {
        CHECK(intact(&blocks[i]));
        if (i % 2 == 0) {
            unsigned char *moved = realloc(blocks[i].pointer, blocks[i].size + 17);
            CHECK(moved);
            for (size_t j = 0; j < blocks[i].size; j++) CHECK(moved[j] == blocks[i].byte);
            free(moved);
        } else {
            free(blocks[i].pointer);
        }
        blocks[i].pointer = 0;
    }
}

/* The ordinary allocation set expected of a child and of its handlers. */
static void allocation_set(void) {
    unsigned char *small = malloc(64);
    CHECK(small);
    memset(small, 0x5a, 64);
    unsigned char *zeroed = calloc(1000, 4);
    CHECK(zeroed);
    for (size_t i = 0; i < 4000; i++) CHECK(zeroed[i] == 0);
    void *aligned = aligned_alloc(4096, 8192);
    CHECK(aligned && ((size_t)aligned & 4095) == 0);
    void *memaligned = 0;
    CHECK(posix_memalign(&memaligned, 256, 100) == 0 && ((size_t)memaligned & 255) == 0);
    unsigned char *grown = realloc(small, 90000);
    CHECK(grown);
    for (size_t i = 0; i < 64; i++) CHECK(grown[i] == 0x5a);
    CHECK(malloc_usable_size(grown) >= 90000);
    free(grown);
    free(zeroed);
    free(aligned);
    free(memaligned);
}

static void churn_once(void) {
    void *block = malloc(64);
    CHECK(block);
    free(block);
}

/* Handler transcript: prepare/parent/child identity in call order. */
static char events[64];
static int event_count;
static void record(char event) {
    CHECK(event_count < (int)sizeof events - 1);
    events[event_count++] = event;
    churn_once();
}
static void *child_handler_block;
static void prepare_a(void) { record('A'); }
static void prepare_b(void) { record('B'); }
static void prepare_c(void) { record('C'); }
static void parent_a(void) { record('a'); }
static void parent_b(void) { record('b'); }
static void parent_c(void) { record('c'); }
static void child_a(void) { record('1'); }
static void child_b(void) { record('2'); }
static void child_c(void) {
    record('3');
    /* A child handler may run the whole set and keep a block for main. */
    allocation_set();
    child_handler_block = malloc(333);
    CHECK(child_handler_block);
}

static void print_events(const char *who) {
    events[event_count] = 0;
    dprintf(1, "%s handlers %s\n", who, events);
    event_count = 0;
}

static void wait_success(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        dprintf(2, "child status %#x\n", status);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void *round_trip_worker(void *unused) {
    (void)unused;
    allocation_set();
    return 0;
}

static struct block initial_blocks[CLASSES];
static struct block worker_blocks[CLASSES];

/* Churner ring: each slot holds zero or one live block whose first 16
 * bytes are 0x77; the smallest churned request is 48 bytes. */
#define RING 8
static unsigned char *ring[RING];
static int stop_churn;

static void *churner(void *unused) {
    (void)unused;
    for (unsigned round = 0; !__atomic_load_n(&stop_churn, __ATOMIC_ACQUIRE); round++) {
        unsigned char *old = __atomic_exchange_n(&ring[round % RING], 0, __ATOMIC_ACQ_REL);
        free(old);
        unsigned char *block = malloc(sizes[round % 3] + round % 64);
        CHECK(block);
        memset(block, 0x77, 16);
        __atomic_store_n(&ring[round % RING], block, __ATOMIC_RELEASE);
    }
    for (int i = 0; i < RING; i++) free(__atomic_exchange_n(&ring[i], 0, __ATOMIC_ACQ_REL));
    return 0;
}

static void release_ring(void) {
    for (int i = 0; i < RING; i++) {
        unsigned char *block = __atomic_exchange_n(&ring[i], 0, __ATOMIC_ACQ_REL);
        if (!block) continue;
        for (int j = 0; j < 16; j++) CHECK(block[j] == 0x77);
        free(block);
    }
}

/* Everything a repaired child must support; exits the child normally. */
static void child_body(const char *scenario, int with_worker_blocks) {
    print_events("child");
    CHECK(child_handler_block);
    free(child_handler_block);
    child_handler_block = 0;
    release(initial_blocks);
    if (with_worker_blocks) release(worker_blocks);
    release_ring();
    allocation_set();
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, round_trip_worker, 0) == 0);
    CHECK(pthread_join(thread, 0) == 0);
    pid_t grandchild = fork();
    CHECK(grandchild >= 0);
    if (grandchild == 0) {
        print_events("grandchild");
        free(child_handler_block);
        allocation_set();
        exit(0);
    }
    wait_success(grandchild);
    print_events("child-after-grandchild");
    dprintf(1, "%s child ok\n", scenario);
    exit(0);
}

static void fork_and_check(const char *scenario, int with_worker_blocks) {
    event_count = 0;
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) child_body(scenario, with_worker_blocks);
    wait_success(child);
    print_events("parent");
}

static int worker_ready, worker_release;

static void *live_worker(void *argument) {
    int origin = *(const int *)argument;
    fill(worker_blocks, 0x63);
    __atomic_store_n(&worker_ready, 1, __ATOMIC_RELEASE);
    if (origin) {
        fork_and_check("worker", 1);
    } else {
        while (!__atomic_load_n(&worker_release, __ATOMIC_ACQUIRE)) sched_yield();
    }
    release(worker_blocks);
    return 0;
}

static void live_scenario(int worker_origin) {
    pthread_t churn, worker;
    CHECK(pthread_create(&churn, 0, churner, 0) == 0);
    CHECK(pthread_create(&worker, 0, live_worker, &worker_origin) == 0);
    while (!__atomic_load_n(&worker_ready, __ATOMIC_ACQUIRE)) sched_yield();
    if (!worker_origin) {
        fork_and_check("initial", 1);
        __atomic_store_n(&worker_release, 1, __ATOMIC_RELEASE);
    }
    CHECK(pthread_join(worker, 0) == 0);
    __atomic_store_n(&stop_churn, 1, __ATOMIC_RELEASE);
    CHECK(pthread_join(churn, 0) == 0);
}

/* Repeated prepared copies while three threads allocate every class and
 * free each other's blocks through one shared ring. Each child inherits
 * whatever was live, frees it, allocates and exits normally. */
#define SHARED_RING 24
#define REPEATS 64
static unsigned char *shared_ring[SHARED_RING];

static void *shared_churner(void *argument) {
    unsigned seed = (unsigned)(size_t)argument;
    for (unsigned round = 0; !__atomic_load_n(&stop_churn, __ATOMIC_ACQUIRE); round++) {
        seed = seed * 1103515245u + 12345u;
        unsigned slot = (seed >> 8) % SHARED_RING;
        free(__atomic_exchange_n(&shared_ring[slot], 0, __ATOMIC_ACQ_REL));
        unsigned char *block = malloc(sizes[(seed >> 20) % CLASSES]);
        CHECK(block);
        memset(block, 0x77, 16);
        free(__atomic_exchange_n(&shared_ring[slot], block, __ATOMIC_ACQ_REL));
    }
    return 0;
}

static void repeat_scenario(void) {
    pthread_t churners[3];
    for (size_t i = 0; i < 3; i++)
        CHECK(pthread_create(&churners[i], 0, shared_churner, (void *)(i + 1)) == 0);
    for (int repeat = 0; repeat < REPEATS; repeat++) {
        event_count = 0;
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            for (int i = 0; i < SHARED_RING; i++) {
                unsigned char *block = shared_ring[i];
                if (!block) continue;
                for (int j = 0; j < 16; j++) CHECK(block[j] == 0x77);
                free(block);
            }
            free(child_handler_block);
            allocation_set();
            exit(0);
        }
        wait_success(child);
    }
    __atomic_store_n(&stop_churn, 1, __ATOMIC_RELEASE);
    for (size_t i = 0; i < 3; i++) CHECK(pthread_join(churners[i], 0) == 0);
    for (int i = 0; i < SHARED_RING; i++) free(shared_ring[i]);
    dprintf(1, "repeat children %d\n", REPEATS);
}

static void *exiting_worker(void *unused) {
    (void)unused;
    fill(worker_blocks, 0x63);
    return 0;
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    fill(initial_blocks, 0x35);
    CHECK(pthread_atfork(prepare_a, parent_a, child_a) == 0);
    CHECK(pthread_atfork(prepare_b, parent_b, child_b) == 0);
    CHECK(pthread_atfork(prepare_c, parent_c, child_c) == 0);
    if (!strcmp(argv[1], "initial")) {
        live_scenario(0);
    } else if (!strcmp(argv[1], "worker")) {
        live_scenario(1);
    } else if (!strcmp(argv[1], "joined")) {
        pthread_t worker;
        CHECK(pthread_create(&worker, 0, exiting_worker, 0) == 0);
        CHECK(pthread_join(worker, 0) == 0);
        fork_and_check("joined", 1);
        release(worker_blocks);
    } else if (!strcmp(argv[1], "repeat")) {
        repeat_scenario();
    } else if (!strcmp(argv[1], "underscore")) {
        /* Unprepared single-owner image: no handler runs on either side. */
        event_count = 0;
        pid_t child = _Fork();
        CHECK(child >= 0);
        if (child == 0) {
            print_events("child");
            release(initial_blocks);
            allocation_set();
            _exit(0);
        }
        wait_success(child);
        print_events("parent");
    } else {
        CHECK(0);
    }
    release(initial_blocks);
    allocation_set();
    dprintf(1, "%s parent ok\n", argv[1]);
    return 0;
}
