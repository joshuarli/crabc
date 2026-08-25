#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

typedef void (*cxa_callback)(void *);

extern int __cxa_atexit(cxa_callback, void *, void *);
extern void __cxa_finalize(void *);

static int marker_fd;

static void record(void *value)
{
    const char *text = value;
    size_t length = 0;
    while (text[length] != '\0')
        ++length;
    if (write(marker_fd, text, length) != (ssize_t)length)
        _exit(91);
}

int main(int argc, char **argv)
{
    void *const first_dso = (void *)0x1111;
    void *const second_dso = (void *)0x2222;

    if (argc != 2)
        return 1;
    marker_fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (marker_fd < 0)
        return 2;
    if (__cxa_atexit(record, "first-old\n", first_dso) != 0 ||
        __cxa_atexit(record, "second\n", second_dso) != 0 ||
        __cxa_atexit(record, "first-new\n", first_dso) != 0)
        return 3;

    /* Musl exports __cxa_finalize as an ABI no-op. The installed crabc
     * sysroot must retain the registrations for the process-exit LIFO walk. */
    __cxa_finalize(first_dso);
    __cxa_finalize(first_dso);
    exit(0);
}
