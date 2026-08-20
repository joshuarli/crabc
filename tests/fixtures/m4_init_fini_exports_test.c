#define _GNU_SOURCE 1

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int (*main_fn)(int, char **, char **);
typedef void (*init_fini_fn)(void);

/* This is the historical musl ABI used by crt1.o. */
extern void __libc_start_main(main_fn, int, char **,
                              init_fini_fn, init_fini_fn,
                              init_fini_fn, const void *)
    __attribute__((noreturn));

static const char *marker_path;

static void append_marker(const char *marker)
{
    int fd = open(marker_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0 || write(fd, marker, strlen(marker)) != (ssize_t)strlen(marker))
        _exit(91);
    close(fd);
}

static void startup_callback(void)
{
    append_marker("init\n");
}

static void finalization_callback(void)
{
    append_marker("fini\n");
}

static int callback_main(int argc, char **argv, char **envp)
{
    (void)argc;
    (void)argv;
    (void)envp;
    append_marker("main\n");
    return 37;
}

int main(int argc, char **argv)
{
    int fd;
    void *libc_handle;
    init_fini_fn weak_init;
    init_fini_fn weak_fini;

    if (argc != 2)
        return 1;
    marker_path = argv[1];
    fd = open(marker_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return 2;
    close(fd);

    /* Resolve the libc definitions directly: the executable's crti.o also
     * has `_init`/`_fini`, so RTLD_DEFAULT would intentionally interpose them. */
    libc_handle = dlopen("libc.so", RTLD_NOW);
    if (libc_handle == NULL)
        return 3;
    weak_init = (init_fini_fn)dlsym(libc_handle, "_init");
    weak_fini = (init_fini_fn)dlsym(libc_handle, "_fini");
    if (weak_init == NULL || weak_fini == NULL)
        return 4;
    append_marker("exports\n");
    weak_init();
    weak_fini();

    /* Enter the same callback contract that musl crt1.o uses.  crabc's
     * implementation must invoke init, callback_main, then fini and exit
     * with callback_main's status. */
    __libc_start_main(callback_main, argc, argv,
                      startup_callback, finalization_callback,
                      NULL, NULL);
}
