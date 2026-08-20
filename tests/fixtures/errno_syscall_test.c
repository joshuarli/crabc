#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile int child_ready;
static volatile int release_child;
static volatile int child_errno;

static void *worker(void *unused)
{
    char byte;
    (void)unused;

    if (read(-1, &byte, 1) != -1 || errno != EBADF)
        return (void *)1;
    if (write(-1, &byte, 1) != -1 || errno != EBADF)
        return (void *)2;
    if (open("/definitely/not/a/real/path", O_RDONLY) != -1 || errno != ENOENT)
        return (void *)3;
    if (close(-1) != -1 || errno != EBADF)
        return (void *)4;
    if (lseek(-1, 0, SEEK_SET) != -1 || errno != EBADF)
        return (void *)5;
    if (clock_gettime(-1, &(struct timespec){0}) != -1 || errno != EINVAL)
        return (void *)6;
    if (stat("/definitely/not/a/real/path", &(struct stat){0}) != -1 || errno != ENOENT)
        return (void *)7;

    errno = E2BIG;
    child_ready = 1;
    while (!release_child)
        ;
    child_errno = errno;
    return 0;
}

int main(void)
{
    pthread_t thread;
    void *result;

    errno = EACCES;
    if (pthread_create(&thread, 0, worker, 0) != 0)
        return 10;
    while (!child_ready)
        ;
    errno = EPERM;
    release_child = 1;
    if (pthread_join(thread, &result) != 0 || result != 0)
        return 11;
    if (child_errno != E2BIG || errno != EPERM)
        return 12;

    puts("errno syscall ok");
    return 0;
}
