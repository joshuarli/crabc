#include <pthread.h>
#include <stdint.h>

extern uintptr_t __stack_chk_guard;

static uintptr_t thread_guard(void)
{
    uintptr_t value;
#if defined(__aarch64__)
    uintptr_t tp;
    __asm__ volatile("mrs %0,tpidr_el0" : "=r"(tp));
    value = *(const uintptr_t *)(tp - 16);
#else
    __asm__ volatile("mov %%fs:40,%0" : "=r"(value));
#endif
    return value;
}

static void *worker(void *argument)
{
    return (void *)(uintptr_t)(thread_guard() == *(const uintptr_t *)argument);
}

int main(void)
{
    uintptr_t guard = thread_guard();
    pthread_t thread;
    void *result = 0;
    if (!guard || guard != __stack_chk_guard) return 1;
    if (pthread_create(&thread, 0, worker, &guard) || pthread_join(thread, &result)) return 2;
    return result != (void *)1;
}
