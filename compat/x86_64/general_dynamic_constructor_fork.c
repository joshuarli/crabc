#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(CRABC_CONSTRUCTOR_FORK_LIBRARY)
static int initialized;
static int finalized;
static int child_role;

static void emit(const char *text, unsigned long length) {
    if (write(1, text, length) != (long)length) _Exit(91);
}

static void initialize(void) __attribute__((constructor));
static void initialize(void) {
    if (++initialized != 1) _Exit(92);
    pid_t child = fork();
    if (child < 0) _Exit(93);
    if (child == 0) {
        child_role = 1;
        /* Revisit this DSO while its inherited constructor is still active. */
        void *self = dlopen("libconstructor-fork.so", RTLD_NOW | RTLD_LOCAL);
        if (!self) _Exit(94);
        if (dlclose(self) != 0 || initialized != 1) _Exit(95);
        emit("ctor-child\n", 11);
    } else {
        int status = 0;
        if (waitpid(child, &status, 0) != child || status != 0) _Exit(96);
        /* The parent still owns its active visit after the child completes. */
        void *self = dlopen("libconstructor-fork.so", RTLD_NOW | RTLD_LOCAL);
        if (!self) _Exit(99);
        if (dlclose(self) != 0 || initialized != 1) _Exit(100);
        emit("ctor-parent\n", 12);
    }
}

static void finalize(void) __attribute__((destructor));
static void finalize(void) {
    if (initialized != 1 || ++finalized != 1) _Exit(97);
    if (child_role) emit("fini-child\n", 11);
    else emit("fini-parent\n", 12);
}

int constructor_fork_role(void) {
    if (initialized != 1 || finalized != 0) _Exit(98);
    return child_role;
}
#else
extern int constructor_fork_role(void);

int main(void) {
    if (constructor_fork_role()) return write(1, "main-child\n", 11) != 11;
    return write(1, "main-parent\n", 12) != 12;
}
#endif
