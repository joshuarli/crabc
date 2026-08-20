#include <pthread.h>
#include <stdio.h>

#if !defined(__aarch64__)
#error "this focused TLS layout regression is AArch64-only"
#endif

static __thread char initialized __attribute__((aligned(4096))) = 33;
static __thread char zeroed __attribute__((aligned(64)));

static unsigned long thread_pointer(void)
{
    unsigned long value;
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r"(value));
    return value;
}

static int check(void)
{
    return thread_pointer() % 4096 == 0 && initialized == 33 && zeroed == 0 &&
        (unsigned long)&initialized % 4096 == 0 &&
        (unsigned long)&zeroed % 64 == 0;
}

static void *thread_check(void *unused)
{
    (void)unused;
    return check() ? 0 : (void *)1;
}

int main(void)
{
    pthread_t thread;
    void *result;

    if (!check())
        return 1;
    if (pthread_create(&thread, 0, thread_check, 0) != 0)
        return 2;
    if (pthread_join(thread, &result) != 0 || result != 0)
        return 3;
    puts("ldso tls alignment ok");
    return 0;
}
