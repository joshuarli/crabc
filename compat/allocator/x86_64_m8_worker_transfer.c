/* A joined worker's public allocation remains owned by libc after pthread_exit.
 * The initial thread grows it through reallocarray, checks failure preservation,
 * and frees it after the worker's cleanup and TSD destructor have run.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) abort(); } while (0)

static pthread_key_t key;
static int cleanup_count;
static int destructor_count;

static void cleanup(void *unused) {
    (void)unused;
    unsigned char *block = malloc(4096);
    CHECK(block != NULL);
    memset(block, 0x31, 4096);
    for (size_t i = 0; i < 4096; i++) CHECK(block[i] == 0x31);
    free(block);
    cleanup_count++;
}

static void destructor(void *pointer) {
    unsigned char *block = pointer;
    CHECK(block[0] == 0x42 && block[8191] == 0x42);
    free(block);
    destructor_count++;
}

static void *worker(void *unused) {
    (void)unused;
    unsigned char *block = malloc(8192);
    unsigned char *tsd = malloc(8192);
    CHECK(block != NULL && tsd != NULL);
    memset(block, 0x5a, 8192);
    memset(tsd, 0x42, 8192);
    CHECK(pthread_setspecific(key, tsd) == 0);
    pthread_cleanup_push(cleanup, NULL);
    pthread_exit(block);
    pthread_cleanup_pop(0);
    return NULL;
}

int main(void) {
    CHECK(pthread_key_create(&key, destructor) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    void *result = NULL;
    CHECK(pthread_join(thread, &result) == 0);
    CHECK(result != NULL && cleanup_count == 1 && destructor_count == 1);
    unsigned char *block = result;
    for (size_t i = 0; i < 8192; i++) CHECK(block[i] == 0x5a);

    errno = EDOM;
    unsigned char *grown = reallocarray(block, 3, 8192);
    CHECK(grown != NULL && errno == EDOM);
    for (size_t i = 0; i < 8192; i++) CHECK(grown[i] == 0x5a);
    memset(grown + 8192, 0x6b, 16384);
    errno = 0;
    void *failed = reallocarray(grown, SIZE_MAX, 2);
    CHECK(failed == NULL && errno == ENOMEM);
    for (size_t i = 0; i < 8192; i++) CHECK(grown[i] == 0x5a);
    for (size_t i = 8192; i < 24576; i++) CHECK(grown[i] == 0x6b);
    errno = EDOM;
    free(grown);
    CHECK(errno == EDOM);
    CHECK(pthread_key_delete(key) == 0);
    puts("worker exit cleanup and TSD: 1 1");
    puts("joined reallocarray growth and overflow preservation: ok");
    return 0;
}
