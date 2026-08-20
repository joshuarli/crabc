#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static volatile int ready;
static char *(*loaded_tls)(void);

static void *worker(void *unused)
{
    char *value;

    (void)unused;
    while (!ready)
        ;
    value = loaded_tls();
    return value && (unsigned long)value % 4096 == 0 &&
        strcmp(value, "dynamic") == 0 ? 0 : (void *)1;
}

int main(void)
{
    void *handle;
    pthread_t thread;
    void *thread_result;

    if (pthread_create(&thread, 0, worker, 0) != 0)
        return 1;
    handle = dlopen("libdynamic_tls.so", RTLD_NOW);
    if (!handle)
        return 2;
    loaded_tls = (char *(*)(void))dlsym(handle, "load_dynamic_tls");
    if (!loaded_tls || !loaded_tls() || (unsigned long)loaded_tls() % 4096 != 0 ||
        strcmp(loaded_tls(), "dynamic") != 0)
        return 3;
    ready = 1;
    if (pthread_join(thread, &thread_result) != 0 || thread_result != 0)
        return 4;
    puts("dynamic TLS ok");
    return 0;
}
