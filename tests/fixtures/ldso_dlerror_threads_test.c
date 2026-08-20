#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

static volatile int ready;

static int has_prefix(const char *value, const char *prefix) {
    int i = 0;
    if (value == 0) return 0;
    while (prefix[i] != 0) {
        if (value[i] != prefix[i]) return 0;
        i++;
    }
    return 1;
}

struct worker_result {
    int kind;
    int ok;
};

static void *worker(void *arg) {
    struct worker_result *result = (struct worker_result *)arg;
    if (result->kind == 1) {
        (void)dlsym(0, 0);
    } else {
        (void)dlclose((void *)0x1234);
    }
    __sync_fetch_and_add(&ready, 1);
    while (ready != 2) {}
    const char *error = dlerror();
    result->ok = result->kind == 1
        ? has_prefix(error, "dlsym: null symbol")
        : has_prefix(error, "dlclose: invalid handle");
    return 0;
}

int main(void) {
    pthread_t first;
    pthread_t second;
    struct worker_result first_result = {1, 0};
    struct worker_result second_result = {2, 0};
    if (pthread_create(&first, 0, worker, &first_result) != 0) return 1;
    if (pthread_create(&second, 0, worker, &second_result) != 0) return 2;
    if (pthread_join(first, 0) != 0) return 3;
    if (pthread_join(second, 0) != 0) return 4;
    if (!first_result.ok || !second_result.ok) return 5;
    write(1, "dlerror threads ok\n", 19);
    return 0;
}
