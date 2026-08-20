#include <pthread.h>
#include <stdio.h>

static int counter = 0;
static pthread_mutex_t mutex;

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 10000; i++) {
        pthread_mutex_lock(&mutex);
        counter++;
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

int main(void) {
    pthread_t threads[10];

    pthread_mutex_init(&mutex, NULL);
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < 10; i++)
        pthread_create(&threads[i], NULL, worker, NULL);
    pthread_mutex_unlock(&mutex);
    for (int i = 0; i < 10; i++)
        pthread_join(threads[i], NULL);

    if (counter == 100000) {
        printf("pthread ok\n");
        return 0;
    }
    printf("counter=%d\n", counter);
    return 1;
}
