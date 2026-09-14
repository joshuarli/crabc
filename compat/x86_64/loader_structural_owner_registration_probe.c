#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static int transaction_completed;
static int worker_completed;

static void require(int condition)
{
    if (!condition) _Exit(92);
}

static void public_dlfcn_transaction(void)
{
    typedef int (*value_function)(void);
    void *handle;
    value_function value;

    dlerror();
    require(dlsym(RTLD_DEFAULT, "loader_structural_owner_missing") == NULL);
    require(dlerror() != NULL);
    require(dlerror() == NULL);
    handle = dlopen("libloader-structural-owner-plugin.so", RTLD_NOW | RTLD_LOCAL);
    require(handle != NULL);
    value = (value_function)dlsym(handle, "loader_structural_owner_plugin_value");
    require(value != NULL && dlerror() == NULL && value() == 47);
    require(dlclose(handle) == 0);
}

static void *first_application_worker(void *unused)
{
    (void)unused;
    require(transaction_completed == 1);
    public_dlfcn_transaction();
    worker_completed = 1;
    return NULL;
}

int main(void)
{
    pthread_t worker;
    public_dlfcn_transaction();
    transaction_completed = 1;
    require(pthread_create(&worker, NULL, first_application_worker, NULL) == 0);
    require(pthread_join(worker, NULL) == 0 && worker_completed == 1);
    puts("loader-structural-registration-before-worker-ok");
    return 0;
}
