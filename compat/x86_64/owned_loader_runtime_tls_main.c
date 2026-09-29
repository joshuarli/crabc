#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "runtime TLS check failed at line %d: %s\n", __LINE__, #test); \
    exit(101); } } while (0)

struct plugin {
    void *handle;
    int (*ready)(void);
    unsigned (*get)(void);
    void (*set)(unsigned);
    unsigned *(*address)(void);
};

static struct plugin plugins[2];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned stage;
static unsigned started;
static unsigned completed[2];
static unsigned *worker_addresses[2][2];
static size_t module_ids[2];
static void *main_tls_data[2];

struct tls_snapshot {
    size_t ids[2];
    void *data[2];
    unsigned seen[2];
};

static int collect_tls(struct dl_phdr_info *info, size_t size, void *argument)
{
    struct tls_snapshot *snapshot = argument;
    CHECK(size >= sizeof *info);
    for (unsigned index = 0; index != 2; ++index) {
        const char *name = index ? "libowned-runtime-tls-two.so" : "libowned-runtime-tls-one.so";
        if (info->dlpi_name && strstr(info->dlpi_name, name)) {
            CHECK(++snapshot->seen[index] == 1);
            snapshot->ids[index] = info->dlpi_tls_modid;
            snapshot->data[index] = info->dlpi_tls_data;
        }
    }
    return 0;
}

static struct tls_snapshot snapshot_tls(void)
{
    struct tls_snapshot snapshot = { { 0, 0 }, { 0, 0 }, { 0, 0 } };
    CHECK(dl_iterate_phdr(collect_tls, &snapshot) == 0);
    CHECK(snapshot.seen[0] == 1 && snapshot.seen[1] == 1);
    CHECK(snapshot.ids[0] && snapshot.ids[1] && snapshot.ids[0] != snapshot.ids[1]);
    CHECK(snapshot.data[0] && snapshot.data[1] && snapshot.data[0] != snapshot.data[1]);
    return snapshot;
}

static void check_tls_symbol(unsigned index)
{
    unsigned *symbol = dlsym(plugins[index].handle, "tls_value");
    CHECK(symbol == plugins[index].address());
    CHECK(*symbol == plugins[index].get());
}

static struct plugin open_plugin(const char *name)
{
    struct plugin result;
    result.handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    CHECK(result.handle != 0);
    result.ready = (int (*)(void))dlsym(result.handle, "tls_ready");
    result.get = (unsigned (*)(void))dlsym(result.handle, "tls_get");
    result.set = (void (*)(unsigned))dlsym(result.handle, "tls_set");
    result.address = (unsigned *(*)(void))dlsym(result.handle, "tls_address");
    CHECK(result.ready && result.get && result.set && result.address && result.ready());
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
    worker_addresses[number - 1][0] = plugins[0].address();
    check_tls_symbol(0);
    announce(0);
    wait_stage(2);
    CHECK(plugins[0].get() == 110 + number);
    CHECK(plugins[1].ready() && plugins[1].get() == 202);
    plugins[1].set(220 + number);
    worker_addresses[number - 1][1] = plugins[1].address();
    check_tls_symbol(1);
    struct tls_snapshot before_close = snapshot_tls();
    announce(1);
    wait_stage(3);
    CHECK(plugins[0].ready() && plugins[1].ready());
    CHECK(plugins[0].address() == worker_addresses[number - 1][0]);
    CHECK(plugins[1].address() == worker_addresses[number - 1][1]);
    CHECK(plugins[0].get() == 110 + number && plugins[1].get() == 220 + number);
    for (unsigned index = 0; index != 2; ++index) {
        check_tls_symbol(index);
        CHECK(before_close.ids[index] == module_ids[index]);
    }
    struct tls_snapshot after_close = snapshot_tls();
    for (unsigned index = 0; index != 2; ++index) {
        CHECK(after_close.ids[index] == before_close.ids[index]);
        CHECK(after_close.data[index] == before_close.data[index]);
        CHECK(after_close.data[index] != main_tls_data[index]);
    }
    return 0;
}

static void *fresh_worker(void *argument)
{
    (void)argument;
    CHECK(plugins[0].ready() && plugins[1].ready());
    CHECK(plugins[0].get() == 101 && plugins[1].get() == 202);
    CHECK(plugins[0].address() != plugins[1].address());
    struct tls_snapshot snapshot = snapshot_tls();
    for (unsigned index = 0; index != 2; ++index) {
        CHECK(snapshot.ids[index] == module_ids[index]);
        CHECK(snapshot.data[index] != main_tls_data[index]);
        check_tls_symbol(index);
    }
    plugins[0].set(301);
    plugins[1].set(302);
    CHECK(plugins[0].get() == 301 && plugins[1].get() == 302);
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
    unsigned *main_addresses[2] = { plugins[0].address(), 0 };
    CHECK(pthread_create(&late, 0, worker, (void *)(uintptr_t)2) == 0);
    wait_started(2);
    advance(1);
    wait_workers(0);
    plugins[1] = open_plugin("libowned-runtime-tls-two.so");
    CHECK(plugins[1].get() == 202 && plugins[0].get() == 131);
    plugins[1].set(231);
    main_addresses[1] = plugins[1].address();
    check_tls_symbol(0);
    check_tls_symbol(1);
    struct tls_snapshot before_close = snapshot_tls();
    for (unsigned index = 0; index != 2; ++index) {
        module_ids[index] = before_close.ids[index];
        main_tls_data[index] = before_close.data[index];
    }
    advance(2);
    wait_workers(1);

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
        CHECK(plugins[index].address() == main_addresses[index]);
        check_tls_symbol(index);
    }
    CHECK(plugins[0].get() == 131 && plugins[1].get() == 231);
    struct tls_snapshot after_close = snapshot_tls();
    for (unsigned index = 0; index != 2; ++index) {
        CHECK(after_close.ids[index] == before_close.ids[index]);
        CHECK(after_close.data[index] == before_close.data[index]);
    }
    advance(3);
    CHECK(pthread_join(early, 0) == 0 && pthread_join(late, 0) == 0);
    pthread_t fresh;
    CHECK(pthread_create(&fresh, 0, fresh_worker, 0) == 0);
    CHECK(pthread_join(fresh, 0) == 0);
    CHECK(plugins[0].get() == 131 && plugins[1].get() == 231);
    CHECK(dlclose(plugins[1].handle) == 0 && dlclose(plugins[0].handle) == 0);
    puts("runtime TLS: two growth generations, live-worker retained reopen, fresh worker");
    return 0;
}
