#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void *block;

static void *producer(void *unused)
{
    (void)unused;
    block = malloc(16);
    return block == NULL ? (void *)1 : NULL;
}

int main(void)
{
    pthread_t worker;
    void *result;

    if (pthread_create(&worker, NULL, producer, NULL) != 0)
        return 10;
    if (pthread_join(worker, &result) != 0 || result != NULL || block == NULL)
        return 11;

    free(block);
    puts("ok");
    return 0;
}
