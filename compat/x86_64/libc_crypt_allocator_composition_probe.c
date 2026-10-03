/* Private x86 crypt/allocator provider-composition ABI fixture. */

#include <crypt.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef char *(*crypt_signature)(const char *, const char *);
typedef char *(*crypt_r_signature)(const char *, const char *, struct crypt_data *);

static crypt_signature public_crypt = crypt;
static crypt_r_signature public_crypt_r = crypt_r;
static int failures;

#ifdef CRABC_X86_CRYPT_ALLOCATOR_COMPOSITION_CANDIDATE
typedef char *(*crypt_private_hash_signature)(const char *, const char *, char *);

extern char *__crypt_sha256(const char *, const char *, char *);

static crypt_private_hash_signature private_sha256 = __crypt_sha256;
#endif

struct guarded_crypt_data {
    struct crypt_data data;
    unsigned char guard;
};

static void check_heap_backed_crypt(void)
{
    static const char expected[] =
        "$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D";
    static const char key_source[] = "foobar";
    static const char setting_source[] = "$5$rounds=100000$9aEeVXnCiCNHUjO/";
    char *key = malloc(sizeof(key_source));
    char *setting = malloc(sizeof(setting_source));
    struct guarded_crypt_data *storage = malloc(sizeof(*storage));
    char *result;

    if (key == 0 || setting == 0 || storage == 0) {
        failures++;
        goto cleanup;
    }
    memcpy(key, key_source, sizeof(key_source));
    memcpy(setting, setting_source, sizeof(setting_source));
    memset(&storage->data, 0, sizeof(storage->data));
    storage->data.initialized = 0x13579bdf;
    storage->guard = 0xa5;

    result = public_crypt(key, setting);
    if (result == 0 || strcmp(result, expected) != 0)
        failures++;

    result = public_crypt_r(key, setting, &storage->data);
#ifdef CRABC_X86_CRYPT_ALLOCATOR_COMPOSITION_CANDIDATE
    if (result != storage->data.__buf ||
        storage->data.initialized != 0x13579bdf || storage->guard != 0xa5 ||
        strcmp(result, expected) != 0)
        failures++;
#else
    if (result == 0 || strcmp(result, expected) != 0)
        failures++;
#endif

#ifdef CRABC_X86_CRYPT_ALLOCATOR_COMPOSITION_CANDIDATE
    {
        /* 320 is a nonzero multiple of 64 and leaves a guard after __buf. */
        unsigned char *private_output = aligned_alloc(64, 320);

        if (private_output == 0 || ((uintptr_t)private_output & 63) != 0) {
            failures++;
        } else {
            private_output[256] = 0xa5;
            result = private_sha256(key, setting, (char *)private_output);
            if (result != (char *)private_output || private_output[256] != 0xa5 ||
                strcmp(result, expected) != 0)
                failures++;
        }
        free(private_output);
    }
#endif

cleanup:
    free(storage);
    free(setting);
    free(key);
}

struct crypt_worker_context {
    pthread_barrier_t *ready;
    pthread_barrier_t *release;
    int saved_errno;
    int failed;
    char *shared_result;
};

static int wait_workers(pthread_barrier_t *barrier)
{
    int result = pthread_barrier_wait(barrier);
    return result != 0 && result != PTHREAD_BARRIER_SERIAL_THREAD;
}

static void *crypt_worker(void *argument)
{
    struct crypt_worker_context *context = argument;
    static const char setting[] = "$5$rounds=100000$9aEeVXnCiCNHUjO/";
    static const char expected[] =
        "$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D";
    struct guarded_crypt_data *storage = malloc(sizeof(*storage));
    char *result = NULL;

    if (storage == NULL) {
        context->failed = 1;
    } else {
        memset(storage, 0, sizeof(*storage));
        storage->data.initialized = 0x13579bdf;
        storage->guard = 0xa5;
        errno = context->saved_errno;
        result = public_crypt_r("foobar", setting, &storage->data);
        if (result == NULL || strcmp(result, expected) != 0 ||
            errno != context->saved_errno || storage->guard != 0xa5)
            context->failed = 1;
#ifdef CRABC_X86_CRYPT_ALLOCATOR_COMPOSITION_CANDIDATE
        if (result != storage->data.__buf || storage->data.initialized != 0x13579bdf)
            context->failed = 1;
#endif
    }
    context->failed |= wait_workers(context->ready);
    context->failed |= wait_workers(context->release);
    /* The caller-owned record remains live across unrelated global crypt
     * calls and another thread's allocation and result cleanup. */
    if (storage != NULL &&
        (result == NULL || strcmp(result, expected) != 0 ||
         storage->guard != 0xa5 || errno != context->saved_errno))
        context->failed = 1;
    /* Only the designated worker calls crypt here. The main thread has
     * released the barrier and reads this process-owned result after join. */
    if (context->saved_errno == EDOM) {
        context->shared_result = public_crypt("foobar", setting);
        if (context->shared_result == NULL || strcmp(context->shared_result, expected) != 0)
            context->failed = 1;
    }
    free(storage);
    return NULL;
}

static void check_worker_result_lifetime(void)
{
    pthread_barrier_t ready, release;
    pthread_t workers[2];
    struct crypt_worker_context contexts[2];
    if (pthread_barrier_init(&ready, NULL, 3) != 0 ||
        pthread_barrier_init(&release, NULL, 3) != 0) {
        failures++;
        return;
    }
    for (int index = 0; index < 2; index++) {
        contexts[index] = (struct crypt_worker_context){
            &ready, &release, index ? ERANGE : EDOM, 0, NULL };
        if (pthread_create(&workers[index], NULL, crypt_worker, &contexts[index]) != 0)
            _exit(1);
    }
    failures += wait_workers(&ready);
    errno = EINVAL;
    check_heap_backed_crypt();
    if (errno != EINVAL)
        failures++;
    failures += wait_workers(&release);
    for (int index = 0; index < 2; index++) {
        if (pthread_join(workers[index], NULL) != 0)
            failures++;
        failures += contexts[index].failed;
    }
    if (contexts[0].shared_result == NULL ||
        strcmp(contexts[0].shared_result,
            "$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D") != 0)
        failures++;
    else if (public_crypt("foobar", "$5$rounds=100000$9aEeVXnCiCNHUjO/") !=
        contexts[0].shared_result)
        failures++;
    if (pthread_barrier_destroy(&ready) != 0 || pthread_barrier_destroy(&release) != 0)
        failures++;
}

int main(int argc, char **argv)
{
    check_heap_backed_crypt();
    if (argc == 2 && strcmp(argv[1], "workers") == 0) {
        check_worker_result_lifetime();
        check_worker_result_lifetime();
    }
    else if (argc != 1)
        failures++;
    if (failures != 0)
        return failures;
    return write(1, "crypt allocator composition ok\n",
                 sizeof("crypt allocator composition ok\n") - 1) ==
                   (ssize_t)(sizeof("crypt allocator composition ok\n") - 1)
               ? 0
               : 1;
}
