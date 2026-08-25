#include <stdint.h>
#include <stdio.h>

extern uintptr_t __stack_chk_guard;

static uintptr_t constructor_guard;

__attribute__((constructor)) static void observe_startup_guard(void)
{
    /* Keep a real protected frame here: this must execute only after libc has
       published the guard, not merely before main happens to inspect it. */
    volatile unsigned char protected_frame[32];
    protected_frame[0] = 1;
    constructor_guard = __stack_chk_guard + protected_frame[0] - 1;
}

int main(void)
{
    if (constructor_guard == 0)
        return 81;
    if (__stack_chk_guard == 0)
        return 82;
    if (constructor_guard != __stack_chk_guard)
        return 83;
    puts("startup stack guard ok");
    return 0;
}
