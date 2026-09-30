#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { dprintf(2, "worker refusal line %d\n", __LINE__); _exit(1); } } while (0)

static _Thread_local unsigned int tls_marker = 0x5a61;
static pthread_key_t key;
static atomic_uint callbacks;
struct round {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int ready;
    unsigned int cleanup_calls, destructor_calls;
    unsigned char *worker_client, *last_client;
};

#ifdef CRABC_NATIVE_WORKER_AUDIT
struct owner_audit {
    size_t owner_installed, page_engine_active, attached_worker_owners, reclaimed_worker_descriptors;
};
int __crabc_x86_owned_allocator_worker_owner_test_audit(struct owner_audit *);
static struct owner_audit audit(void) {
    struct owner_audit value;
    CHECK(__crabc_x86_owned_allocator_worker_owner_test_audit(&value) == 0);
    return value;
}
static void require_live_owner(void) {
    struct owner_audit value = audit();
    CHECK(value.owner_installed == 1 && value.page_engine_active == 1);
}
#else
static void require_live_owner(void) {}
#endif

static unsigned char *filled(size_t size, unsigned char value) {
    unsigned char *client = malloc(size);
    CHECK(client);
    memset(client, value, size);
    return client;
}
static void intact(const unsigned char *client, size_t size, unsigned char value) {
    for (size_t index = 0; index < size; ++index) CHECK(client[index] == value);
}
static void destructor(void *opaque) {
    struct round *round = opaque;
    require_live_owner();
    CHECK(tls_marker == 0x45678 && round->cleanup_calls == 1);
    CHECK(pthread_getspecific(key) == NULL && ++round->destructor_calls <= 4);
    unsigned char value = (unsigned char)(0x40 + round->destructor_calls);
    unsigned char *client = filled(97, value);
    client = realloc(client, 241);
    CHECK(client);
    intact(client, 97, value);
    memset(client, value, 241);
    if (round->destructor_calls < 4) {
        free(client);
        CHECK(pthread_setspecific(key, round) == 0);
    } else {
        /* The cancelled worker leaves this allocation live for its joiner. */
        round->last_client = client;
    }
}
static void cleanup(void *opaque) {
    struct round *round = opaque;
    require_live_owner();
    CHECK(tls_marker == 0x45678 && pthread_getspecific(key) == round);
    CHECK(round->destructor_calls == 0);
    intact(round->worker_client, 113, 0x71);
    free(filled(73, 0x29));
    ++round->cleanup_calls;
    /* Cancellation of cond_wait reacquires this mutex before cleanup. */
    CHECK(pthread_mutex_unlock(&round->mutex) == 0);
}
static void *parked_worker(void *opaque) {
    struct round *round = opaque;
    CHECK(tls_marker == 0x5a61 && pthread_getspecific(key) == NULL);
    tls_marker = 0x45678;
    round->worker_client = filled(113, 0x71);
    CHECK(pthread_setspecific(key, round) == 0);
    CHECK(pthread_mutex_lock(&round->mutex) == 0);
    pthread_cleanup_push(cleanup, round);
    round->ready = 1;
    CHECK(pthread_cond_broadcast(&round->condition) == 0);
    for (;;) CHECK(pthread_cond_wait(&round->condition, &round->mutex) == 0);
    pthread_cleanup_pop(1);
    return NULL;
}
static void *later_worker(void *opaque) {
    CHECK(tls_marker == 0x5a61 && pthread_getspecific(key) == NULL);
    atomic_fetch_add(&callbacks, 1);
    unsigned char *client = filled(64, 0x38);
    intact(client, 64, 0x38);
    free(client);
    return opaque;
}
int main(void) {
    struct round round = { .mutex = PTHREAD_MUTEX_INITIALIZER,
                           .condition = PTHREAD_COND_INITIALIZER };
    unsigned int creator_key_value = 0x12;
    CHECK(pthread_key_create(&key, destructor) == 0);
    CHECK(pthread_setspecific(key, &creator_key_value) == 0);
    tls_marker = 0x12345;
    unsigned char *main_client = filled(257, 0x19);
    pthread_t parked;
    CHECK(pthread_create(&parked, NULL, parked_worker, &round) == 0);
    CHECK(pthread_mutex_lock(&round.mutex) == 0);
    while (!round.ready) CHECK(pthread_cond_wait(&round.condition, &round.mutex) == 0);
    CHECK(pthread_mutex_unlock(&round.mutex) == 0);
#ifdef CRABC_NATIVE_WORKER_AUDIT
    struct owner_audit before = audit();
#endif
    struct rlimit saved, low;
    CHECK(getrlimit(RLIMIT_AS, &saved) == 0);
    low = saved;
    low.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_AS, &low) == 0);
    pthread_t refused = (pthread_t)(uintptr_t)0x1234;
    int error = pthread_create(&refused, NULL, later_worker, &round);
    /* Restore before assertions, cancellation or any later allocation. */
    int restore = setrlimit(RLIMIT_AS, &saved);
    if (error == 0) CHECK(pthread_join(refused, NULL) == 0);
    CHECK(restore == 0 && error == EAGAIN);
    CHECK(refused == (pthread_t)(uintptr_t)0x1234 && atomic_load(&callbacks) == 0);
    CHECK(tls_marker == 0x12345 && pthread_getspecific(key) == &creator_key_value);
    intact(main_client, 257, 0x19);
    intact(round.worker_client, 113, 0x71);
    require_live_owner();
#ifdef CRABC_NATIVE_WORKER_AUDIT
    struct owner_audit after = audit();
    CHECK(after.attached_worker_owners == before.attached_worker_owners);
    CHECK(after.reclaimed_worker_descriptors == before.reclaimed_worker_descriptors);
#endif
    CHECK(pthread_cancel(parked) == 0);
    void *result;
    CHECK(pthread_join(parked, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(round.cleanup_calls == 1 && round.destructor_calls == 4 && round.last_client);
    require_live_owner();
#ifdef CRABC_NATIVE_WORKER_AUDIT
    struct owner_audit cancelled = audit();
    CHECK(cancelled.attached_worker_owners + 1 == before.attached_worker_owners);
    CHECK(cancelled.reclaimed_worker_descriptors == before.reclaimed_worker_descriptors + 1);
#endif
    intact(round.worker_client, 113, 0x71);
    intact(round.last_client, 241, 0x44);
    free(round.worker_client);
    free(round.last_client);
    intact(main_client, 257, 0x19);
    pthread_t later;
    CHECK(pthread_create(&later, NULL, later_worker, &round) == 0);
    CHECK(pthread_join(later, &result) == 0 && result == &round);
    CHECK(atomic_load(&callbacks) == 1);
#ifdef CRABC_NATIVE_WORKER_AUDIT
    struct owner_audit joined = audit();
    CHECK(joined.attached_worker_owners == cancelled.attached_worker_owners);
    CHECK(joined.reclaimed_worker_descriptors == cancelled.reclaimed_worker_descriptors + 1);
#endif
    CHECK(tls_marker == 0x12345 && pthread_getspecific(key) == &creator_key_value);
    free(main_client);
    CHECK(pthread_key_delete(key) == 0);
    CHECK(pthread_cond_destroy(&round.condition) == 0);
    CHECK(pthread_mutex_destroy(&round.mutex) == 0);
    puts("native mimalloc worker refusal ok");
    return 0;
}
