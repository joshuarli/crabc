#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { dprintf(2, "prepared fork line %d errno %d\n", __LINE__, errno); _exit(1); } } while (0)

struct client { unsigned char *pointer; size_t size; size_t alignment; unsigned char byte; };
static struct client initial[4], worker[4];
static int ready, release_worker, worker_origin;
static __thread unsigned int tls_marker;
static char events[32];
static size_t count;

/* Page-offset and singleton clients remain live while their owner vanishes
 * in the child. Each pointer is released exactly once in each process image. */
static void fill(struct client *clients, unsigned char byte) {
    const size_t alignments[] = { 64, 4096, 65536, 1048576 };
    const size_t sizes[] = { 77, 3001, 40001, 300001 };
    for (size_t i = 0; i < 4; ++i) {
        void *pointer = NULL;
        CHECK(posix_memalign(&pointer, alignments[i], sizes[i]) == 0);
        CHECK(pointer && (uintptr_t)pointer % alignments[i] == 0);
        clients[i] = (struct client){ pointer, sizes[i], alignments[i], byte };
        memset(pointer, byte, sizes[i]);
    }
}

static void verify(const struct client *clients) {
    for (size_t i = 0; i < 4; ++i) {
        CHECK((uintptr_t)clients[i].pointer % clients[i].alignment == 0);
        for (size_t j = 0; j < clients[i].size; ++j) CHECK(clients[i].pointer[j] == clients[i].byte);
    }
}

static void consume(struct client *clients) {
    verify(clients);
    for (size_t i = 0; i < 4; ++i) {
        unsigned char *moved = realloc(clients[i].pointer, clients[i].size + 8193);
        CHECK(moved);
        for (size_t j = 0; j < clients[i].size; ++j) CHECK(moved[j] == clients[i].byte);
        free(moved);
        clients[i].pointer = NULL;
    }
}

static void ordinary_allocations(void) {
    unsigned char *block = malloc(79);
    unsigned char *zero = calloc(31, 17);
    void *aligned = aligned_alloc(4096, 8192);
    CHECK(block && zero && aligned && (uintptr_t)aligned % 4096 == 0);
    memset(block, 0x6d, 79);
    for (size_t i = 0; i < 31 * 17; ++i) CHECK(zero[i] == 0);
    block = realloc(block, 70001);
    CHECK(block);
    for (size_t i = 0; i < 79; ++i) CHECK(block[i] == 0x6d);
    free(block);
    free(zero);
    free(aligned);
}

static void event(char value) {
    CHECK(count + 1 < sizeof events);
    events[count++] = value;
    ordinary_allocations();
}
#define HANDLERS(letter, parent, child) \
    static void prepare_##letter(void) { event(#letter[0]); } \
    static void parent_##letter(void) { event(parent); } \
    static void child_##letter(void) { event(child); }
HANDLERS(A, 'a', '1')
HANDLERS(B, 'b', '2')
HANDLERS(C, 'c', '3')
HANDLERS(D, 'd', '4')

static void expect_events(const char *expected) {
    events[count] = 0;
    CHECK(strcmp(events, expected) == 0);
    count = 0;
}

static void wait_success(pid_t child) {
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void *child_thread(void *unused) {
    (void)unused;
    CHECK(tls_marker == 0);
    ordinary_allocations();
    return NULL;
}

static void fork_clients(void) {
    unsigned int marker = tls_marker;
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHECK(tls_marker == marker);
        expect_events("CBA123");
        consume(initial);
        consume(worker);
        ordinary_allocations();
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, child_thread, NULL) == 0);
        CHECK(pthread_join(thread, NULL) == 0);
        /* Registration in the repaired child appends to the inherited list;
         * both directions must retain their order at its next fork. */
        CHECK(pthread_atfork(prepare_D, parent_D, child_D) == 0);
        pid_t grandchild = fork();
        CHECK(grandchild >= 0);
        if (grandchild == 0) {
            expect_events("DCBA1234");
            ordinary_allocations();
            _exit(0);
        }
        wait_success(grandchild);
        expect_events("DCBAabcd");
        _exit(0);
    }
    wait_success(child);
    expect_events("CBAabc");
    CHECK(tls_marker == marker);
    verify(initial);
    verify(worker);
    ordinary_allocations();
}

static void *live_worker(void *unused) {
    (void)unused;
    tls_marker = 0x63;
    fill(worker, 0x73);
    __atomic_store_n(&ready, 1, __ATOMIC_RELEASE);
    if (worker_origin) fork_clients();
    else while (!__atomic_load_n(&release_worker, __ATOMIC_ACQUIRE)) sched_yield();
    consume(worker);
    return NULL;
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    CHECK(strcmp(argv[1], "initial") == 0 || strcmp(argv[1], "worker") == 0);
    worker_origin = strcmp(argv[1], "worker") == 0;
    tls_marker = 0x35;
    fill(initial, 0x39);
    CHECK(pthread_atfork(prepare_A, parent_A, child_A) == 0);
    /* Owned registrations have allocated storage rather than a small fixed
     * table. Null callbacks remain valid entries in either traversal. */
    for (size_t i = 0; i < 40; ++i) CHECK(pthread_atfork(NULL, NULL, NULL) == 0);
    CHECK(pthread_atfork(prepare_B, parent_B, child_B) == 0);
    CHECK(pthread_atfork(prepare_C, parent_C, child_C) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, live_worker, NULL) == 0);
    while (!__atomic_load_n(&ready, __ATOMIC_ACQUIRE)) sched_yield();
    if (!worker_origin) {
        fork_clients();
        __atomic_store_n(&release_worker, 1, __ATOMIC_RELEASE);
    }
    CHECK(pthread_join(thread, NULL) == 0);
    consume(initial);
    CHECK(tls_marker == 0x35);
    dprintf(1, "%s aligned clients, TLS, handlers and successor registration ok\n", argv[1]);
    return 0;
}
