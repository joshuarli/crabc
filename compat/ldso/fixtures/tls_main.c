#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>

static volatile int worker_ready;
static volatile int worker_go;
static int *(*tls_slot)(void);

static void *worker(void *unused)
{
    (void)unused;
    worker_ready = 1;
    while (!worker_go)
        ;
    return (void *)(long)*tls_slot();
}

int main(void)
{
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, 0) != 0)
        return 50;
    while (!worker_ready)
        ;

    void *handle = dlopen("libfixture_tls.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 51;
    tls_slot = (int *(*)(void))dlsym(handle, "fixture_tls_slot");
    if (!tls_slot)
        return 52;
    *tls_slot() = 6;
    worker_go = 1;
    void *worker_result = 0;
    if (pthread_join(thread, &worker_result) != 0)
        return 53;
    printf("tls=%d/%ld\n", *tls_slot(), (long)worker_result);
    return dlclose(handle) == 0 ? 0 : 54;
}
