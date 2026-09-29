#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "runtime TLS check failed at line %d: %s\n", __LINE__, #test); \
    exit(101); } } while (0)

struct plugin {
    void *handle;
    int (*ready)(void);
    unsigned (*get)(void);
    void (*set)(unsigned);
};

static struct plugin plugins[2];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned stage;
static unsigned started;
static unsigned completed[2];

static struct plugin open_plugin(const char *name)
{
    struct plugin result;
    result.handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    CHECK(result.handle != 0);
    result.ready = (int (*)(void))dlsym(result.handle, "tls_ready");
    result.get = (unsigned (*)(void))dlsym(result.handle, "tls_get");
    result.set = (void (*)(unsigned))dlsym(result.handle, "tls_set");
    CHECK(result.ready && result.get && result.set && result.ready());
    return result;
}

static void wait_stage(unsigned wanted)
{
    CHECK(pthread_mutex_lock(&lock) == 0);
    while (stage < wanted) CHECK(pthread_cond_wait(&changed, &lock) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

static void announce(unsigned index)
{
    CHECK(pthread_mutex_lock(&lock) == 0);
    ++completed[index];
    CHECK(pthread_cond_broadcast(&changed) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

static void *worker(void *argument)
{
    unsigned number = (unsigned)(uintptr_t)argument;
    CHECK(pthread_mutex_lock(&lock) == 0);
    ++started;
    CHECK(pthread_cond_broadcast(&changed) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
    wait_stage(1);
    CHECK(plugins[0].ready() && plugins[0].get() == 101);
    plugins[0].set(110 + number);
    announce(0);
    wait_stage(2);
    CHECK(plugins[0].get() == 110 + number);
    CHECK(plugins[1].ready() && plugins[1].get() == 202);
    plugins[1].set(220 + number);
    announce(1);
    return 0;
}

static void wait_started(unsigned count)
{
    CHECK(pthread_mutex_lock(&lock) == 0);
    while (started != count) CHECK(pthread_cond_wait(&changed, &lock) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

static void advance(unsigned next)
{
    CHECK(pthread_mutex_lock(&lock) == 0);
    stage = next;
    CHECK(pthread_cond_broadcast(&changed) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

static void wait_workers(unsigned index)
{
    CHECK(pthread_mutex_lock(&lock) == 0);
    while (completed[index] != 2) CHECK(pthread_cond_wait(&changed, &lock) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

int main(void)
{
    pthread_t early, late;
    CHECK(pthread_create(&early, 0, worker, (void *)(uintptr_t)1) == 0);
    wait_started(1);
    plugins[0] = open_plugin("libowned-runtime-tls-one.so");
    CHECK(plugins[0].get() == 101);
    plugins[0].set(131);
    CHECK(pthread_create(&late, 0, worker, (void *)(uintptr_t)2) == 0);
    wait_started(2);
    advance(1);
    wait_workers(0);
    plugins[1] = open_plugin("libowned-runtime-tls-two.so");
    CHECK(plugins[1].get() == 202 && plugins[0].get() == 131);
    plugins[1].set(231);
    advance(2);
    wait_workers(1);
    CHECK(pthread_join(early, 0) == 0 && pthread_join(late, 0) == 0);
    CHECK(plugins[0].get() == 131 && plugins[1].get() == 231);

    for (unsigned index = 0; index != 2; ++index) {
        void *old = plugins[index].handle;
        CHECK(dlclose(old) == 0);
        void *retained = dlopen(index ? "libowned-runtime-tls-two.so"
                                      : "libowned-runtime-tls-one.so", RTLD_NOW | RTLD_NOLOAD);
        CHECK(retained == old);
        CHECK(dlclose(retained) == 0);
        plugins[index] = open_plugin(index ? "libowned-runtime-tls-two.so"
                                            : "libowned-runtime-tls-one.so");
        CHECK(plugins[index].handle == old);
    }
    CHECK(plugins[0].get() == 131 && plugins[1].get() == 231);
    CHECK(dlclose(plugins[1].handle) == 0 && dlclose(plugins[0].handle) == 0);
    puts("runtime TLS: two growth generations, old and new workers, retained reopen");
    return 0;
}
