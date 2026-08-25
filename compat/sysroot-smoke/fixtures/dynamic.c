/* Dynamic PIE probe for the packaged Linux/AArch64 application sysroot. */

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Thread_local int thread_value = 17;

static void *worker(void *argument)
{
    int *observed = argument;

    *observed = thread_value;
    thread_value = 29;
    errno = 41;
    if (thread_value != 29 || errno != 41)
        return (void *)(uintptr_t)1;
    return (void *)(uintptr_t)0;
}

static int module_value(const char *path)
{
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    void *symbol;
    int (*value)(void);
    const char *error;
    int result;

    if (handle == NULL)
        return 50;
    dlerror();
    symbol = dlsym(handle, "crabc_sysroot_smoke_value");
    error = dlerror();
    if (error != NULL || symbol == NULL) {
        dlclose(handle);
        return 51;
    }
    *(void **)(&value) = symbol;
    result = value() == 42 ? 0 : 52;
    if (dlclose(handle) != 0)
        return 53;
    return result;
}

int main(int argc, char **argv)
{
    pthread_t thread;
    void *result = NULL;
    int observed = -1;
    char *allocation;
    const char *environment;

    if (argc != 2 || argv == NULL || argv[0] == NULL || argv[argc] != NULL)
        return 1;
    environment = getenv("CRABC_SYSROOT_SMOKE");
    if (environment == NULL || strcmp(environment, "1") != 0)
        return 2;

    allocation = malloc(128);
    if (allocation == NULL)
        return 3;
    memset(allocation, 0xA5, 128);
    free(allocation);

    errno = 17;
    if (pthread_create(&thread, NULL, worker, &observed) != 0)
        return 4;
    if (pthread_join(thread, &result) != 0 || result != NULL)
        return 5;
    if (observed != 17 || thread_value != 17 || errno != 17)
        return 6;
    if (module_value(argv[1]) != 0)
        return 7;

    /* The harness holds the process here while it hashes /proc/<pid>/maps. */
    if (getenv("CRABC_SYSROOT_SMOKE_WAIT") != NULL) {
        char release;
        if (read(STDIN_FILENO, &release, 1) != 1)
            return 8;
    }
    puts("crabc sysroot dynamic smoke ok");
    return 0;
}
