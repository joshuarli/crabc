#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>

typedef int (*dynamic_tls_dependency_access_fn)(int, int, int, int);

struct dynamic_tls_dependency_state {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int command;
    int worker_status;
    dynamic_tls_dependency_access_fn access;
};

static void *dynamic_tls_dependency_worker(void *opaque)
{
    struct dynamic_tls_dependency_state *const state = opaque;

    if (pthread_mutex_lock(&state->mutex) != 0)
        return (void *)1;
    while (state->command == 0) {
        if (pthread_cond_wait(&state->condition, &state->mutex) != 0) {
            (void)pthread_mutex_unlock(&state->mutex);
            return (void *)2;
        }
    }
    if (state->access(47, 31, 147, 131) != 0)
        state->worker_status = 1;
    if (pthread_mutex_unlock(&state->mutex) != 0)
        return (void *)3;
    return 0;
}

int main(int argc, char **argv)
{
    struct dynamic_tls_dependency_state state;
    void *handle;
    pthread_t worker;
    void *worker_result;
    int access_status;

    if (argc != 2)
        return 1;
    if (pthread_mutex_init(&state.mutex, 0) != 0)
        return 2;
    if (pthread_cond_init(&state.condition, 0) != 0)
        return 3;
    state.command = 0;
    state.worker_status = 0;
    state.access = 0;
    if (pthread_create(&worker, 0, dynamic_tls_dependency_worker, &state) != 0)
        return 4;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == 0)
        return 5;
    state.access = (dynamic_tls_dependency_access_fn)dlsym(handle,
        "dynamic_tls_dependency_access");
    if (state.access == 0)
        return 6;
    access_status = state.access(47, 31, 247, 231);
    if (access_status != 0) {
        fprintf(stderr, "initial dynamic TLS access failed: %d\n", access_status);
        return 6;
    }
    if (pthread_mutex_lock(&state.mutex) != 0)
        return 7;
    state.command = 1;
    if (pthread_cond_signal(&state.condition) != 0)
        return 8;
    if (pthread_mutex_unlock(&state.mutex) != 0)
        return 9;
    if (pthread_join(worker, &worker_result) != 0 || worker_result != 0)
        return 10;
    if (state.worker_status != 0 || state.access(247, 231, 247, 231) != 0)
        return 11;
    if (dlclose(handle) != 0)
        return 12;
    if (pthread_cond_destroy(&state.condition) != 0)
        return 13;
    if (pthread_mutex_destroy(&state.mutex) != 0)
        return 14;
    puts("dynamic TLS dependency graph ok");
    return 0;
}
