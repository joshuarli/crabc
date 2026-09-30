#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct round {
    unsigned int calls;
    unsigned int cleanup_calls;
    int explicit_exit;
    int failed;
    unsigned char *start_client;
    unsigned char *last_client;
};

static pthread_key_t key;

static int intact(const unsigned char *client, size_t length, unsigned char value)
{
    size_t index;
    for (index = 0; index < length; ++index)
        if (client[index] != value)
            return 0;
    return 1;
}

static void cleanup(void *opaque)
{
    struct round *round = opaque;
    unsigned char *client = malloc(73);
    if (client == NULL || round->calls != 0) {
        round->failed = 1;
        free(client);
        return;
    }
    memset(client, 0x29, 73);
    if (!intact(client, 73, 0x29))
        round->failed = 1;
    free(client);
    ++round->cleanup_calls;
}

static void destructor(void *opaque)
{
    struct round *round = opaque;
    unsigned char *client;
    unsigned char *resized;
    unsigned char value;
    ++round->calls;
    if (round->calls > 4 || pthread_getspecific(key) != NULL
            || (round->explicit_exit && round->cleanup_calls != 1)) {
        round->failed = 1;
        return;
    }
    client = malloc(97);
    if (client == NULL) {
        round->failed = 1;
        return;
    }
    value = (unsigned char)(0x40 + round->calls);
    memset(client, value, 97);
    resized = realloc(client, 241);
    if (resized == NULL) {
        free(client);
        round->failed = 1;
        return;
    }
    if (!intact(resized, 97, value))
        round->failed = 1;
    memset(resized, value, 241);
    if (round->calls < 4) {
        free(resized);
        if (pthread_setspecific(key, round) != 0)
            round->failed = 1;
    } else {
        /* Join transfers this still-live allocation to the caller. */
        round->last_client = resized;
    }
}

static void *worker(void *opaque)
{
    struct round *round = opaque;
    round->start_client = malloc(113);
    if (round->start_client == NULL) {
        round->failed = 1;
        return NULL;
    }
    memset(round->start_client, 0x71, 113);
    if (pthread_setspecific(key, round) != 0) {
        round->failed = 1;
        return NULL;
    }
    pthread_cleanup_push(cleanup, round);
    if (round->explicit_exit)
        pthread_exit(round);
    pthread_cleanup_pop(0);
    return round;
}

int main(void)
{
    unsigned int mode;
    if (pthread_key_create(&key, destructor) != 0)
        return 1;
    for (mode = 0; mode != 2; ++mode) {
        struct round round = { .explicit_exit = (int)mode };
        pthread_t thread;
        void *result = NULL;
        if (pthread_create(&thread, NULL, worker, &round) != 0
                || pthread_join(thread, &result) != 0)
            return 2;
        if (result != &round || round.failed || round.calls != 4
                || round.cleanup_calls != mode || round.start_client == NULL
                || round.last_client == NULL)
            return 3;
        if (!intact(round.start_client, 113, 0x71)
                || !intact(round.last_client, 241, 0x44))
            return 4;
        free(round.start_client);
        free(round.last_client);
    }
    if (pthread_key_delete(key) != 0)
        return 5;
    puts("native mimalloc TSD rearm ok");
    return 0;
}
