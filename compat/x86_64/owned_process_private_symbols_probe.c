#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(void) {
    static const char *const private_names[] = {
        "__crabc_x86_allocator_runtime_v1", "__crabc_x86_allocator_observability_v1",
        "__crabc_x86_allocator_string_duplication_v1", "__crabc_x86_environment_runtime_v1",
        "__crabc_x86_posix_spawn_file_actions_v1", "__crabc_x86_scandir_v1",
        "__crabc_x86_temporary_names_v1",
        "__aio_atfork", "__execvpe", "__futimesat", "__ldso_atfork",
        "__membarrier_init", "__stdio_exit", "__fork_handler", "__funcs_on_exit"
    };
    static const char *const public_names[] = {
        "execvpe", "futimesat", "fork", "pthread_atfork", "atexit", "exit"
    };
    for (unsigned i = 0; i < sizeof private_names / sizeof *private_names; i++) {
        dlerror();
        if (dlsym(RTLD_DEFAULT, private_names[i]) != NULL || dlerror() == NULL) {
            fprintf(stderr, "private process symbol is exposed: %s\n", private_names[i]);
            return 1;
        }
    }
    for (unsigned i = 0; i < sizeof public_names / sizeof *public_names; i++) {
        dlerror();
        if (dlsym(RTLD_DEFAULT, public_names[i]) == NULL || dlerror() != NULL) {
            fprintf(stderr, "public process symbol is unavailable: %s\n", public_names[i]);
            return 2;
        }
    }
    puts("owned process private symbols ok");
    return 0;
}
