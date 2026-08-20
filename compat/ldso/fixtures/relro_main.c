#include <dlfcn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    void *handle = dlopen("librelro.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return 10;
    int (*call)(void) = (int (*)(void))dlsym(handle, "relro_call");
    void (*write_slot)(void) = (void (*)(void))dlsym(handle, "relro_write");
    if (call == NULL || write_slot == NULL || call() != 19)
        return 11;
    int child = fork();
    if (child < 0)
        return 12;
    if (child == 0) {
        write_slot();
        _exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return 13;
    if (!WIFSIGNALED(status)) {
        puts("relro=writable");
        return 14;
    }
    puts("relro=protected");
    return 0;
}
